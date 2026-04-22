"""
disassembler.py — Subprocess wrapper for objdump / binary analysis.

Disassembles binaries using objdump and analyzes the assembly for
memory corruption patterns:
    - Buffer overflow: calls to gets, strcpy, sprintf without bounds
    - Format string: printf/fprintf with user-controlled format arg
    - Use-after-free: free() followed by dereference patterns

Safety notes:
    - Read-only analysis — no binary modification or exploitation.
    - Only uses objdump (standard binutils tool).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from typing import Any


# Dangerous functions that commonly lead to vulnerabilities
DANGEROUS_FUNCTIONS = {
    # Buffer overflow sources
    "gets": {
        "category": "buffer_overflow",
        "severity": "critical",
        "description": "Reads input with no bounds checking — always exploitable",
    },
    "strcpy": {
        "category": "buffer_overflow",
        "severity": "high",
        "description": "Copies string without length limit — overflow if src > dst",
    },
    "strcat": {
        "category": "buffer_overflow",
        "severity": "high",
        "description": "Appends string without length limit",
    },
    "sprintf": {
        "category": "buffer_overflow",
        "severity": "high",
        "description": "Formatted print to buffer without size limit",
    },
    "scanf": {
        "category": "buffer_overflow",
        "severity": "medium",
        "description": "Input without field width — potential overflow with %s",
    },
    "vsprintf": {
        "category": "buffer_overflow",
        "severity": "high",
        "description": "Variadic sprintf without size limit",
    },
    # Format string
    "printf": {
        "category": "format_string",
        "severity": "medium",
        "description": "Vulnerable if format string is user-controlled",
    },
    "fprintf": {
        "category": "format_string",
        "severity": "medium",
        "description": "Vulnerable if format string is user-controlled",
    },
    "syslog": {
        "category": "format_string",
        "severity": "medium",
        "description": "Vulnerable if format string is user-controlled",
    },
    # Input sources (tracked for format string cross-referencing)
    "fgets": {
        "category": "input_source",
        "severity": "info",
        "description": "Reads user input — track data flow to printf-family functions",
    },
    "read": {
        "category": "input_source",
        "severity": "info",
        "description": "Reads from file descriptor — potential user input source",
    },
    "recv": {
        "category": "input_source",
        "severity": "info",
        "description": "Receives network data — potential user input source",
    },
    # Memory management (UAF indicators)
    "free": {
        "category": "use_after_free",
        "severity": "info",
        "description": "Memory deallocation — check for use-after-free patterns",
    },
    "malloc": {
        "category": "memory_management",
        "severity": "info",
        "description": "Dynamic allocation — track for double-free / UAF",
    },
    "realloc": {
        "category": "memory_management",
        "severity": "info",
        "description": "Reallocation — may invalidate existing pointers",
    },
}

# Fortified variants (macOS uses _chk versions)
FORTIFIED_MAPPINGS = {
    "__strcpy_chk": "strcpy",
    "__strcat_chk": "strcat",
    "__sprintf_chk": "sprintf",
    "__vsprintf_chk": "vsprintf",
    "__memcpy_chk": "memcpy",
    "__memmove_chk": "memmove",
    "___strcpy_chk": "strcpy",
    "___strcat_chk": "strcat",
    "___sprintf_chk": "sprintf",
}


def _validate_binary(path: str) -> str:
    """Validate that the binary exists."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Binary not found: {path}")
    return os.path.abspath(path)


def disassemble_binary(
    binary_path: str,
    timeout: int = 30,
) -> dict[str, Any]:
    """
    Disassemble a binary using objdump and return structured results.

    Returns:
        {
            "command": str,
            "functions": [{"name": str, "address": str, "size": int}, ...],
            "dangerous_calls": [{"function": str, "call_site": str, ...}, ...],
            "sections": [{"name": str, "size": str, "address": str}, ...],
            "raw_disassembly": str,
            "error": str | None,
        }
    """
    safe_path = _validate_binary(binary_path)

    if shutil.which("objdump") is None:
        return _error_result(safe_path, "objdump is not installed or not on PATH")

    # Get section headers
    sections = _get_sections(safe_path, timeout)

    # Full disassembly with Intel syntax
    cmd = ["objdump", "-d", "-M", "intel", safe_path]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        raw = result.stdout

        functions = _parse_functions(raw)
        dangerous_calls = _find_dangerous_calls(raw)

        # Supplement with symbol table analysis (nm) for macOS
        # where objdump may not resolve stub symbols properly
        imported_dangerous = _find_dangerous_imports(safe_path, timeout)
        for imp in imported_dangerous:
            # Only add if not already found via disassembly
            if not any(d["function"] == imp["function"] for d in dangerous_calls):
                dangerous_calls.append(imp)

        vuln_patterns = _analyze_vulnerability_patterns(raw, dangerous_calls)

        return {
            "command": " ".join(cmd),
            "functions": functions,
            "dangerous_calls": dangerous_calls,
            "vulnerability_patterns": vuln_patterns,
            "sections": sections,
            "raw_disassembly": raw,
            "error": None,
        }

    except subprocess.TimeoutExpired:
        return _error_result(safe_path, f"objdump timed out after {timeout}s")
    except Exception as exc:
        return _error_result(safe_path, str(exc))


def disassemble_function(
    binary_path: str,
    function_name: str,
    timeout: int = 30,
) -> dict[str, Any]:
    """
    Disassemble a specific function from the binary.

    Uses objdump with grep-like filtering to extract just one function.
    """
    safe_path = _validate_binary(binary_path)

    if shutil.which("objdump") is None:
        return _error_result(safe_path, "objdump not found")

    cmd = ["objdump", "-d", "-M", "intel", safe_path]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        raw = result.stdout

        # Extract the specific function
        func_asm = _extract_function(raw, function_name)

        if func_asm is None:
            return {
                "command": " ".join(cmd),
                "function_name": function_name,
                "assembly": None,
                "dangerous_calls": [],
                "error": f"Function '{function_name}' not found in binary",
            }

        dangerous = _find_dangerous_calls(func_asm)

        return {
            "command": " ".join(cmd),
            "function_name": function_name,
            "assembly": func_asm,
            "dangerous_calls": dangerous,
            "error": None,
        }

    except subprocess.TimeoutExpired:
        return _error_result(safe_path, f"Timed out after {timeout}s")
    except Exception as exc:
        return _error_result(safe_path, str(exc))


def get_strings(
    binary_path: str,
    min_length: int = 4,
    timeout: int = 15,
) -> dict[str, Any]:
    """
    Extract printable strings from a binary (like the `strings` command).
    Useful for finding hardcoded passwords, format strings, etc.
    """
    safe_path = _validate_binary(binary_path)

    if shutil.which("strings") is None:
        return {"strings": [], "error": "strings command not found"}

    cmd = ["strings", f"-n{min_length}", safe_path]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        found = result.stdout.strip().splitlines()

        # Flag interesting strings
        interesting = []
        for s in found:
            flags = []
            if "%" in s and any(c in s for c in "dxsnp"):
                flags.append("format_specifier")
            if any(w in s.lower() for w in ["password", "secret", "key", "flag"]):
                flags.append("sensitive_keyword")
            if re.match(r"^/[\w/]+$", s):
                flags.append("file_path")
            if flags:
                interesting.append({"string": s, "flags": flags})

        return {
            "total_strings": len(found),
            "all_strings": found,
            "interesting_strings": interesting,
            "error": None,
        }

    except subprocess.TimeoutExpired:
        return {"strings": [], "error": f"Timed out after {timeout}s"}
    except Exception as exc:
        return {"strings": [], "error": str(exc)}


def get_binary_info(binary_path: str, timeout: int = 15) -> dict[str, Any]:
    """Get binary metadata: architecture, protections, linking."""
    safe_path = _validate_binary(binary_path)

    info: dict[str, Any] = {
        "path": safe_path,
        "arch": None,
        "bits": None,
        "endian": None,
        "stripped": None,
        "pie": None,
        "nx": None,
        "relro": None,
    }

    file_out = ""

    # Use file command
    if shutil.which("file"):
        try:
            result = subprocess.run(
                ["file", safe_path],
                capture_output=True, text=True, timeout=timeout
            )
            file_out = result.stdout

            if "ELF" in file_out or "Mach-O" in file_out:
                if "64-bit" in file_out:
                    info["bits"] = 64
                elif "32-bit" in file_out:
                    info["bits"] = 32

                if "x86-64" in file_out or "x86_64" in file_out:
                    info["arch"] = "x86_64"
                elif "Intel 80386" in file_out or "i386" in file_out:
                    info["arch"] = "i386"
                elif "arm64" in file_out or "aarch64" in file_out:
                    info["arch"] = "arm64"
                elif "ARM" in file_out:
                    info["arch"] = "ARM"

                if "LSB" in file_out:
                    info["endian"] = "little"
                elif "MSB" in file_out:
                    info["endian"] = "big"
                elif "arm64" in file_out:
                    info["endian"] = "little"  # ARM64 is little-endian

                if "Mach-O" in file_out:
                    info["stripped"] = "not stripped" not in file_out
                    # Mach-O executables are typically not PIE unless marked
                    info["pie"] = "pie" in file_out.lower()
                else:
                    info["stripped"] = "not stripped" not in file_out
                    info["pie"] = "pie" in file_out.lower() or "shared object" in file_out

        except (subprocess.TimeoutExpired, Exception):
            pass

    # --- Platform-specific security feature detection ---

    if "Mach-O" in file_out:
        # macOS: use nm for stripped detection, otool for protections
        _detect_macho_features(safe_path, info, timeout)
    else:
        # Linux: use readelf for security features
        _detect_elf_features(safe_path, info, timeout)

    return info


def _detect_macho_features(
    safe_path: str, info: dict[str, Any], timeout: int
) -> None:
    """Detect security features on macOS Mach-O binaries."""
    # Stripped detection: check if local symbols exist via nm
    if shutil.which("nm"):
        try:
            result = subprocess.run(
                ["nm", safe_path],
                capture_output=True, text=True, timeout=timeout,
            )
            # If nm finds local/debug symbols (T, t, S, etc.), it's not stripped
            local_symbols = [
                l for l in result.stdout.splitlines()
                if l.strip() and not l.strip().startswith("U ")
                and " U " not in l
            ]
            info["stripped"] = len(local_symbols) == 0
        except Exception:
            pass

    # Debug symbols: check for DWARF info
    if shutil.which("dwarfdump"):
        try:
            result = subprocess.run(
                ["dwarfdump", "--debug-info", safe_path],
                capture_output=True, text=True, timeout=timeout,
            )
            info["has_debug_info"] = "DW_TAG_compile_unit" in result.stdout
        except Exception:
            pass

    # PIE detection via otool
    if shutil.which("otool"):
        try:
            result = subprocess.run(
                ["otool", "-hv", safe_path],
                capture_output=True, text=True, timeout=timeout,
            )
            info["pie"] = "PIE" in result.stdout
            # On macOS ARM64, NX is always enforced by hardware
            if info.get("arch") == "arm64":
                info["nx"] = True
                info["relro"] = "n/a (Mach-O)"
        except Exception:
            pass


def _detect_elf_features(
    safe_path: str, info: dict[str, Any], timeout: int
) -> None:
    """Detect security features on Linux ELF binaries."""
    if not shutil.which("readelf"):
        return

    try:
        result = subprocess.run(
            ["readelf", "-l", safe_path],
            capture_output=True, text=True, timeout=timeout,
        )
        info["nx"] = "GNU_STACK" in result.stdout and "RWE" not in result.stdout

        result2 = subprocess.run(
            ["readelf", "-d", safe_path],
            capture_output=True, text=True, timeout=timeout,
        )
        if "BIND_NOW" in result2.stdout:
            info["relro"] = "full"
        elif "GNU_RELRO" in result.stdout:
            info["relro"] = "partial"
        else:
            info["relro"] = "none"

    except (subprocess.TimeoutExpired, Exception):
        pass


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _find_dangerous_imports(binary_path: str, timeout: int) -> list[dict]:
    """
    Use nm to find imported dangerous functions from the symbol table.

    This catches cases where objdump doesn't resolve stub symbols
    (common on macOS with Mach-O binaries).
    """
    if not shutil.which("nm"):
        return []

    try:
        result = subprocess.run(
            ["nm", "-u", binary_path],  # -u: undefined (imported) symbols
            capture_output=True, text=True, timeout=timeout,
        )
        imports = []
        for line in result.stdout.splitlines():
            raw_sym = line.strip()

            # Check fortified variants first (e.g., ___strcpy_chk → strcpy)
            for fortified, original in FORTIFIED_MAPPINGS.items():
                if fortified in raw_sym and original in DANGEROUS_FUNCTIONS:
                    info = DANGEROUS_FUNCTIONS[original]
                    imports.append({
                        "address": "imported",
                        "function": original,
                        "category": info["category"],
                        "severity": info["severity"],
                        "description": info["description"] + " (fortified variant)",
                        "source": "symbol_table",
                    })
                    break
            else:
                # Match: U _gets  or  U _strcpy
                match = re.match(r"(?:U\s+)?_?(\w+)", raw_sym)
                if match:
                    func_name = match.group(1)
                    if func_name in DANGEROUS_FUNCTIONS:
                        info = DANGEROUS_FUNCTIONS[func_name]
                        imports.append({
                            "address": "imported",
                            "function": func_name,
                            "category": info["category"],
                            "severity": info["severity"],
                            "description": info["description"],
                            "source": "symbol_table",
                        })
        return imports
    except Exception:
        return []


def _get_sections(binary_path: str, timeout: int) -> list[dict]:
    """Get section headers from the binary."""
    cmd = ["objdump", "-h", binary_path]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        sections = []
        for line in result.stdout.splitlines():
            # Match lines like: 13 .text  00001234  00401000 ...
            match = re.match(
                r"\s*\d+\s+(\.\w+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)", line
            )
            if match:
                sections.append({
                    "name": match.group(1),
                    "size": match.group(2),
                    "address": f"0x{match.group(3)}",
                })
        return sections
    except Exception:
        return []


def _parse_functions(raw: str) -> list[dict]:
    """Extract function names and addresses from disassembly."""
    functions = []
    # Match: 0000000000401136 <main>: or 0000000100000460 <_main>:
    pattern = re.compile(r"^([0-9a-fA-F]+)\s+<_?(\w+)>:", re.MULTILINE)
    for match in pattern.finditer(raw):
        functions.append({
            "address": f"0x{match.group(1)}",
            "name": match.group(2),
        })
    return functions


def _find_dangerous_calls(raw: str) -> list[dict]:
    """Find calls to dangerous functions in the disassembly."""
    calls = []
    for line in raw.splitlines():
        line_stripped = line.strip()

        # Linux x86: call  <gets@plt> or call  401030 <gets@plt>
        call_match = re.search(
            r"([0-9a-fA-F]+):\s+.*call\s+[0-9a-fA-F]*\s*<_?(\w+)@?",
            line_stripped,
        )

        # macOS ARM64: bl  0x100000528 <_gets+0x...> or <_gets>
        if not call_match:
            call_match = re.search(
                r"([0-9a-fA-F]+):\s+[0-9a-fA-F]+\s+bl\s+0x[0-9a-fA-F]+\s+<_?(\w+?)(?:\+0x[0-9a-fA-F]+)?(?:@\w+)?>",
                line_stripped,
            )

        if call_match:
            func_name = call_match.group(2)
            # Strip leading underscore (macOS convention)
            clean_name = func_name.lstrip("_") if func_name.startswith("_") else func_name
            if clean_name in DANGEROUS_FUNCTIONS:
                info = DANGEROUS_FUNCTIONS[clean_name]
                calls.append({
                    "address": f"0x{call_match.group(1)}",
                    "function": clean_name,
                    "category": info["category"],
                    "severity": info["severity"],
                    "description": info["description"],
                })
            elif func_name in DANGEROUS_FUNCTIONS:
                info = DANGEROUS_FUNCTIONS[func_name]
                calls.append({
                    "address": f"0x{call_match.group(1)}",
                    "function": func_name,
                    "category": info["category"],
                    "severity": info["severity"],
                    "description": info["description"],
                })
    return calls


def _analyze_vulnerability_patterns(
    raw: str, dangerous_calls: list[dict]
) -> list[dict]:
    """
    Higher-level analysis: combine dangerous calls with context
    to identify likely vulnerability patterns.
    """
    patterns = []

    # Group dangerous calls by category
    categories: dict[str, list] = {}
    for call in dangerous_calls:
        cat = call["category"]
        categories.setdefault(cat, []).append(call)

    # Collect all imported/called function names for cross-referencing
    all_func_names = set(c["function"] for c in dangerous_calls)

    # Buffer overflow pattern: gets/strcpy/sprintf present
    bof_funcs = categories.get("buffer_overflow", [])
    if bof_funcs:
        func_names = list(set(c["function"] for c in bof_funcs))
        patterns.append({
            "vulnerability": "buffer_overflow",
            "confidence": "high" if "gets" in func_names else "medium",
            "evidence": func_names,
            "description": (
                f"Binary calls {', '.join(func_names)} which can overflow "
                f"stack/heap buffers. Found at {len(bof_funcs)} call site(s)."
            ),
        })

    # Format string pattern: only flag as vulnerability if there's evidence
    # the format argument could be user-controlled.
    # Heuristic: printf is only a real format string vuln if the binary also
    # reads user input (gets, fgets, scanf, read) AND uses printf.
    # If buffer overflow functions are present, user data can reach printf.
    fmt_funcs = categories.get("format_string", [])
    if fmt_funcs:
        # Check for user-input sources in the binary
        input_source_funcs = categories.get("input_source", [])
        input_sources = (
            all_func_names & {"gets", "fgets", "scanf", "read", "recv", "getline"}
            | set(c["function"] for c in input_source_funcs)
        )
        has_user_input = len(input_sources) > 0 or len(bof_funcs) > 0

        if has_user_input:
            # User input exists — format string is plausible
            confidence = "high" if not bof_funcs else "medium"
            patterns.append({
                "vulnerability": "format_string",
                "confidence": confidence,
                "evidence": list(set(c["function"] for c in fmt_funcs)),
                "description": (
                    f"Binary reads user input ({', '.join(input_sources) or 'via overflow'}) "
                    f"and calls printf-family functions at {len(fmt_funcs)} site(s). "
                    "Format string attack is possible if user data reaches "
                    "the format argument."
                ),
            })
        # If no user input sources, don't flag printf as a vulnerability —
        # it's likely just using constant format strings.

    # Use-after-free pattern: malloc + free both present
    has_malloc = "memory_management" in categories
    has_free = "use_after_free" in categories
    if has_malloc and has_free:
        patterns.append({
            "vulnerability": "use_after_free",
            "confidence": "low",
            "evidence": ["malloc", "free"],
            "description": (
                "Binary uses dynamic memory (malloc/free). "
                "Use-after-free is possible if freed memory is dereferenced."
            ),
        })

    return patterns


def _extract_function(raw: str, func_name: str) -> str | None:
    """Extract a single function's disassembly from full objdump output."""
    # Find the function header (handles optional _ prefix on macOS)
    pattern = re.compile(
        rf"^[0-9a-fA-F]+\s+<_?{re.escape(func_name)}>:", re.MULTILINE
    )
    match = pattern.search(raw)
    if not match:
        return None

    start = match.start()
    # Find the next function header or end of text
    next_func = re.search(
        r"\n[0-9a-fA-F]+\s+<\w+>:", raw[match.end():]
    )
    if next_func:
        end = match.end() + next_func.start()
    else:
        end = len(raw)

    return raw[start:end].strip()


def _error_result(binary_path: str, error: str) -> dict[str, Any]:
    """Return a standard error result dict."""
    return {
        "command": f"objdump -d {binary_path}",
        "functions": [],
        "dangerous_calls": [],
        "vulnerability_patterns": [],
        "sections": [],
        "raw_disassembly": "",
        "error": error,
    }
