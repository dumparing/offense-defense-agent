"""
gdb_runner.py — Subprocess wrapper for GDB / LLDB.

Runs the binary under a debugger in batch mode, executes commands, and captures
structured output including crash information, backtraces, and register state.

Supports both GDB (Linux) and LLDB (macOS) — automatically selects whichever
is available, preferring GDB.

Safety notes:
    - The binary path is validated before execution.
    - Debugger runs in batch mode (non-interactive) with a timeout.
    - No exploitation payloads are generated — analysis only.
"""

from __future__ import annotations

import os
import re
import subprocess
import shutil
import tempfile
from typing import Any


def _validate_binary(path: str) -> str:
    """Validate that the target binary exists and is executable."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Binary not found: {path}")
    if not os.access(path, os.X_OK):
        raise PermissionError(f"Binary is not executable: {path}")
    return os.path.abspath(path)


def _get_debugger() -> str | None:
    """Return the available debugger: 'gdb', 'lldb', or None."""
    if shutil.which("gdb"):
        return "gdb"
    if shutil.which("lldb"):
        return "lldb"
    return None


def run_gdb_analysis(
    binary_path: str,
    stdin_input: str | None = None,
    args: list[str] | None = None,
    timeout: int = 30,
) -> dict[str, Any]:
    """
    Run a binary under a debugger, feed it input, and capture crash information.

    Strategy:
        1. Try GDB if available (Linux)
        2. Try LLDB if available (macOS)
        3. Fall back to direct execution with signal analysis

    Args:
        binary_path: Path to the binary to debug.
        stdin_input:  String to feed to the binary's stdin (e.g. overflow payload).
        args:         Command-line arguments to pass to the binary.
        timeout:      Max seconds before killing the debugger.

    Returns:
        {
            "command": str,
            "crashed": bool,
            "signal": str | None,
            "fault_address": str | None,
            "backtrace": list[str],
            "registers": dict[str, str],
            "stack_dump": str,
            "stdout": str,
            "raw_output": str,
            "error": str | None,
        }
    """
    safe_path = _validate_binary(binary_path)
    debugger = _get_debugger()

    if debugger == "gdb":
        return _run_gdb_analysis(safe_path, stdin_input, args, timeout)

    # For LLDB and no-debugger cases, use direct execution with signal analysis.
    # LLDB batch mode is unreliable on macOS due to code signing requirements.
    return _run_direct_analysis(safe_path, stdin_input, args, timeout)


def _run_gdb_analysis(
    safe_path: str,
    stdin_input: str | None,
    args: list[str] | None,
    timeout: int,
) -> dict[str, Any]:
    """Run analysis using GDB."""
    gdb_commands = [
        "set pagination off",
        "set confirm off",
        "set disassembly-flavor intel",
    ]

    if args:
        arg_str = " ".join(args)
        gdb_commands.append(f"set args {arg_str}")

    gdb_commands.extend([
        "run",
        "echo ===SIGNAL_INFO===\\n",
        "info signal",
        "echo ===BACKTRACE===\\n",
        "backtrace full",
        "echo ===REGISTERS===\\n",
        "info registers",
        "echo ===STACK===\\n",
        "x/32xw $sp",
        "echo ===FRAME===\\n",
        "info frame",
        "echo ===END===\\n",
        "quit",
    ])

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".gdb", delete=False
    ) as cmd_file:
        cmd_file.write("\n".join(gdb_commands) + "\n")
        cmd_path = cmd_file.name

    cmd = ["gdb", "-batch", "-x", cmd_path, safe_path]

    try:
        result = subprocess.run(
            cmd, input=stdin_input,
            capture_output=True, text=True, timeout=timeout,
        )
        raw = result.stdout + "\n" + result.stderr
        parsed = _parse_gdb_output(raw)
        return _build_result(safe_path, "gdb", raw, parsed)

    except subprocess.TimeoutExpired:
        return _error_result(safe_path, f"GDB timed out after {timeout}s")
    except Exception as exc:
        return _error_result(safe_path, str(exc))
    finally:
        os.unlink(cmd_path)


def _run_lldb_analysis(
    safe_path: str,
    stdin_input: str | None,
    args: list[str] | None,
    timeout: int,
) -> dict[str, Any]:
    """Run analysis using LLDB (macOS)."""
    lldb_commands = [
        "settings set auto-confirm true",
    ]

    if args:
        arg_str = " ".join(args)
        lldb_commands.append(f"settings set target.run-args {arg_str}")

    # Write stdin to a temp file for LLDB to use
    stdin_file = None
    if stdin_input:
        stdin_file = tempfile.NamedTemporaryFile(
            mode="w", suffix=".stdin", delete=False
        )
        stdin_file.write(stdin_input)
        stdin_file.close()
        lldb_commands.append(
            f"settings set target.input-path {stdin_file.name}"
        )

    lldb_commands.extend([
        "run",
        "script print('===BACKTRACE===')",
        "bt",
        "script print('===REGISTERS===')",
        "register read",
        "script print('===FRAME===')",
        "frame info",
        "script print('===END===')",
        "quit",
    ])

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".lldb", delete=False
    ) as cmd_file:
        cmd_file.write("\n".join(lldb_commands) + "\n")
        cmd_path = cmd_file.name

    cmd = ["lldb", "--batch", "--source", cmd_path, safe_path]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        raw = result.stdout + "\n" + result.stderr
        parsed = _parse_lldb_output(raw)
        return _build_result(safe_path, "lldb", raw, parsed)

    except subprocess.TimeoutExpired:
        return _error_result(safe_path, f"LLDB timed out after {timeout}s")
    except Exception as exc:
        return _error_result(safe_path, str(exc))
    finally:
        os.unlink(cmd_path)
        if stdin_file:
            os.unlink(stdin_file.name)


def _run_direct_analysis(
    safe_path: str,
    stdin_input: str | None,
    args: list[str] | None,
    timeout: int,
) -> dict[str, Any]:
    """
    Run the binary directly and analyze the exit signal.

    This is the most portable approach — works on any OS without
    debugger dependencies. We lose register/stack details but reliably
    detect crashes and their signal type.
    """
    import signal as sig_mod

    cmd = [safe_path] + (args or [])

    try:
        result = subprocess.run(
            cmd,
            input=stdin_input,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        returncode = result.returncode
        stdout = result.stdout
        stderr = result.stderr
        raw = f"STDOUT:\n{stdout}\nSTDERR:\n{stderr}\nReturn code: {returncode}"

        # On Unix, negative return codes indicate signal death
        # e.g., -11 = SIGSEGV, -6 = SIGABRT
        crashed = returncode < 0 or returncode > 128
        signal_name = None
        if returncode < 0:
            sig_num = -returncode
            signal_name = _signal_name(sig_num)
        elif returncode > 128:
            # Shell convention: 128 + signal_number
            sig_num = returncode - 128
            signal_name = _signal_name(sig_num)

        # Try to extract useful info from stderr
        backtrace = []
        fault_address = None

        # macOS crash reporter sometimes puts info in stderr
        for line in stderr.splitlines():
            if "fault" in line.lower() or "crash" in line.lower():
                backtrace.append(line.strip())
            addr_match = re.search(r"(0x[0-9a-fA-F]+)", line)
            if addr_match and not fault_address and crashed:
                fault_address = addr_match.group(1)

        # Also check for AddressSanitizer output
        asan_match = re.search(r"(ASAN|AddressSanitizer).*?(0x[0-9a-fA-F]+)", stderr)
        if asan_match:
            fault_address = asan_match.group(2)

        return {
            "command": " ".join(cmd),
            "debugger": "direct",
            "crashed": crashed,
            "signal": signal_name,
            "fault_address": fault_address,
            "backtrace": backtrace,
            "registers": {},
            "stack_dump": "",
            "stdout": stdout,
            "raw_output": raw,
            "error": None,
        }

    except subprocess.TimeoutExpired:
        return _error_result(safe_path, f"Binary timed out after {timeout}s")
    except Exception as exc:
        return _error_result(safe_path, str(exc))


def _signal_name(sig_num: int) -> str:
    """Convert a signal number to its name."""
    import signal as sig_mod
    try:
        return sig_mod.Signals(sig_num).name
    except (ValueError, AttributeError):
        return f"SIG{sig_num}"


def _build_result(
    safe_path: str, debugger: str, raw: str, parsed: dict
) -> dict[str, Any]:
    """Build a standardized result dict from parsed debugger output."""
    return {
        "command": f"{debugger} -batch {safe_path}",
        "debugger": debugger,
        "crashed": parsed["crashed"],
        "signal": parsed["signal"],
        "fault_address": parsed["fault_address"],
        "backtrace": parsed["backtrace"],
        "registers": parsed["registers"],
        "stack_dump": parsed.get("stack_dump", ""),
        "stdout": parsed.get("program_stdout", ""),
        "raw_output": raw,
        "error": None,
    }


def run_gdb_commands(
    binary_path: str,
    commands: list[str],
    timeout: int = 30,
) -> dict[str, Any]:
    """
    Run arbitrary debugger commands on a binary (for advanced analysis).

    Args:
        binary_path: Path to the binary.
        commands:     List of debugger commands to execute.
        timeout:      Max seconds.

    Returns:
        {"command": str, "raw_output": str, "error": str | None}
    """
    safe_path = _validate_binary(binary_path)
    debugger = _get_debugger()

    if debugger is None:
        return {"command": "", "raw_output": "", "error": "No debugger found"}

    if debugger == "lldb":
        full_commands = [
            "settings set auto-confirm true",
        ] + commands + ["quit"]
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".lldb", delete=False
        ) as cmd_file:
            cmd_file.write("\n".join(full_commands) + "\n")
            cmd_path = cmd_file.name
        cmd = ["lldb", "--batch", "--source", cmd_path, safe_path]
    else:
        full_commands = [
            "set pagination off",
            "set confirm off",
            "set disassembly-flavor intel",
        ] + commands + ["quit"]
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".gdb", delete=False
        ) as cmd_file:
            cmd_file.write("\n".join(full_commands) + "\n")
            cmd_path = cmd_file.name
        cmd = ["gdb", "-batch", "-x", cmd_path, safe_path]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return {
            "command": f"{debugger} -batch {safe_path}",
            "raw_output": result.stdout + "\n" + result.stderr,
            "error": result.stderr.strip() if result.returncode != 0 else None,
        }
    except subprocess.TimeoutExpired:
        return {"command": f"{debugger} {safe_path}", "raw_output": "",
                "error": f"Timed out after {timeout}s"}
    except Exception as exc:
        return {"command": f"{debugger} {safe_path}", "raw_output": "",
                "error": str(exc)}
    finally:
        os.unlink(cmd_path)


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _parse_gdb_output(raw: str) -> dict[str, Any]:
    """Parse GDB batch output into structured crash information."""
    result: dict[str, Any] = {
        "crashed": False,
        "signal": None,
        "fault_address": None,
        "backtrace": [],
        "registers": {},
        "stack_dump": "",
        "program_stdout": "",
    }

    # Detect crash signals
    signal_patterns = [
        (r"Program received signal (SIG\w+)", "signal"),
        (r"Program received signal (\w+),", "signal"),
    ]

    for pattern, key in signal_patterns:
        match = re.search(pattern, raw)
        if match:
            result["crashed"] = True
            result["signal"] = match.group(1)
            break

    # Also detect "stopped" messages
    if not result["crashed"]:
        stopped = re.search(r"Program stopped with signal (SIG\w+)", raw)
        if stopped:
            result["crashed"] = True
            result["signal"] = stopped.group(1)

    # Fault address
    fault_match = re.search(r"(?:0x[0-9a-fA-F]+)\s+in\s+", raw)
    if result["crashed"] and fault_match:
        addr = re.search(r"(0x[0-9a-fA-F]+)", fault_match.group())
        if addr:
            result["fault_address"] = addr.group(1)

    # Parse backtrace section
    bt_section = _extract_section(raw, "===BACKTRACE===", "===REGISTERS===")
    if bt_section:
        result["backtrace"] = _parse_backtrace(bt_section)
    else:
        # Try to find backtrace in raw output
        result["backtrace"] = _parse_backtrace(raw)

    # Parse registers
    reg_section = _extract_section(raw, "===REGISTERS===", "===STACK===")
    if reg_section:
        result["registers"] = _parse_registers(reg_section)

    # Stack dump
    stack_section = _extract_section(raw, "===STACK===", "===FRAME===")
    if stack_section:
        result["stack_dump"] = stack_section.strip()

    # Program stdout (everything before GDB's output)
    pre_gdb = raw.split("Program received signal")[0] if result["crashed"] else raw
    stdout_lines = []
    for line in pre_gdb.splitlines():
        if not line.startswith(("(gdb)", "Reading symbols", "Breakpoint",
                                "[Thread", "[Inferior", "Starting program",
                                "Using host", "warning:", "GNU gdb",
                                "Copyright", "License", "This GDB",
                                "---Type", "For bug", "Find the",
                                "set ", "echo ", "Type ")):
            stripped = line.strip()
            if stripped:
                stdout_lines.append(stripped)
    result["program_stdout"] = "\n".join(stdout_lines)

    return result


def _parse_lldb_output(raw: str) -> dict[str, Any]:
    """Parse LLDB batch output into structured crash information."""
    result: dict[str, Any] = {
        "crashed": False,
        "signal": None,
        "fault_address": None,
        "backtrace": [],
        "registers": {},
        "stack_dump": "",
        "program_stdout": "",
    }

    # Detect crash signals in LLDB
    # LLDB: "Process 12345 stopped"  +  "stop reason = signal SIGSEGV"
    # or: "Process 12345 stopped" + "stop reason = EXC_BAD_ACCESS"
    signal_match = re.search(
        r"stop reason = (?:signal )?(SIG\w+|EXC_\w+(?:\s*\([^)]*\))?)", raw
    )
    if signal_match:
        result["crashed"] = True
        signal_name = signal_match.group(1).strip()
        # Map macOS exceptions to POSIX signals
        if signal_name.startswith("EXC_BAD_ACCESS"):
            result["signal"] = "SIGSEGV"
        elif signal_name.startswith("EXC_BAD_INSTRUCTION"):
            result["signal"] = "SIGILL"
        elif signal_name.startswith("EXC_ARITHMETIC"):
            result["signal"] = "SIGFPE"
        elif signal_name.startswith("EXC_"):
            result["signal"] = signal_name
        else:
            result["signal"] = signal_name

    # Also check for "exited with status"
    if not result["crashed"]:
        abort_match = re.search(r"stop reason = signal SIGABRT", raw)
        if abort_match:
            result["crashed"] = True
            result["signal"] = "SIGABRT"

    # Fault address from LLDB
    addr_match = re.search(r"(?:address|at)\s*=?\s*(0x[0-9a-fA-F]+)", raw)
    if result["crashed"] and addr_match:
        result["fault_address"] = addr_match.group(1)

    # Parse backtrace
    bt_section = _extract_section(raw, "===BACKTRACE===", "===REGISTERS===")
    bt_text = bt_section if bt_section else raw
    for line in bt_text.splitlines():
        line = line.strip()
        # LLDB backtrace: frame #0: 0x00007fff... binary`func + offset
        if re.match(r"frame #\d+", line) or re.match(r"\*?\s*frame #\d+", line):
            result["backtrace"].append(line)

    # Parse registers
    reg_section = _extract_section(raw, "===REGISTERS===", "===FRAME===")
    if not reg_section:
        reg_section = _extract_section(raw, "===REGISTERS===", "===END===")
    if reg_section:
        result["registers"] = _parse_lldb_registers(reg_section)

    # Program stdout
    pre_crash = raw.split("Process")[0] if "Process" in raw else raw
    stdout_lines = []
    for line in pre_crash.splitlines():
        if not line.strip().startswith(("(lldb)", "Current executable",
                                        "target create", "settings set",
                                        "command source", "Executing commands")):
            stripped = line.strip()
            if stripped:
                stdout_lines.append(stripped)
    result["program_stdout"] = "\n".join(stdout_lines)

    return result


def _parse_lldb_registers(text: str) -> dict[str, str]:
    """Parse LLDB 'register read' output into a dict."""
    regs = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("General") or line.startswith("==="):
            continue
        # Match: x0 = 0x0000000000000000
        match = re.match(r"(\w+)\s*=\s*(0x[0-9a-fA-F]+)", line)
        if match:
            regs[match.group(1)] = match.group(2)
    return regs


def _extract_section(text: str, start_marker: str, end_marker: str) -> str | None:
    """Extract text between two markers."""
    start = text.find(start_marker)
    if start == -1:
        return None
    start += len(start_marker)
    end = text.find(end_marker, start)
    if end == -1:
        end = len(text)
    return text[start:end]


def _parse_backtrace(text: str) -> list[str]:
    """Extract backtrace frames from GDB output."""
    frames = []
    for line in text.splitlines():
        line = line.strip()
        # Match lines like: #0  0x00007fff... in func_name (...) at file.c:10
        if re.match(r"#\d+\s+", line):
            frames.append(line)
    return frames


def _parse_registers(text: str) -> dict[str, str]:
    """Parse 'info registers' output into a dict."""
    regs = {}
    for line in text.splitlines():
        line = line.strip()
        # Match: rax  0x7fffffffe120  140737488347424
        match = re.match(r"(\w+)\s+(0x[0-9a-fA-F]+)\s+", line)
        if match:
            regs[match.group(1)] = match.group(2)
    return regs


def _error_result(binary_path: str, error: str) -> dict[str, Any]:
    """Return a standard error result dict."""
    return {
        "command": f"gdb -batch {binary_path}",
        "crashed": False,
        "signal": None,
        "fault_address": None,
        "backtrace": [],
        "registers": {},
        "stack_dump": "",
        "stdout": "",
        "raw_output": "",
        "error": error,
    }
