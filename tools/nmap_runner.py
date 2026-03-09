"""
nmap_runner.py — Subprocess wrapper for Nmap.

Runs `nmap -sV <target>` and parses the text output into a structured list
of discovered services. This keeps the rest of the system decoupled from
Nmap's raw CLI output.

Safety notes:
    - The target IP is validated before being passed to the shell.
    - The command is executed with a timeout to prevent hangs.
    - Only service-version detection (-sV) is used; no exploitation.
"""

import re
import shutil
import subprocess
from ipaddress import ip_address


def _validate_target(target: str) -> str:
    """
    Validate that the target is a legitimate IP address.
    Prevents command injection by rejecting anything that isn't a valid IP.
    """
    try:
        ip_address(target)
        return target
    except ValueError:
        raise ValueError(
            f"Invalid target '{target}': must be a valid IPv4 or IPv6 address"
        )


def run_nmap_service_scan(target: str, timeout: int = 120) -> dict:
    """
    Execute `nmap -sV <target>` and return structured results.

    Returns:
        {
            "command": str,          # exact command that was run
            "raw_output": str,       # full nmap stdout
            "services": [            # parsed open-port entries
                {
                    "port": int,
                    "protocol": str,
                    "state": str,
                    "service": str,
                    "version": str,
                },
                ...
            ],
            "error": str | None,
        }
    """
    safe_target = _validate_target(target)

    # Check that nmap is installed
    if shutil.which("nmap") is None:
        return {
            "command": f"nmap -sV {safe_target}",
            "raw_output": "",
            "services": [],
            "error": "nmap is not installed or not on PATH",
        }

    cmd = ["nmap", "-sV", safe_target]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        raw = result.stdout
        services = _parse_nmap_output(raw)

        return {
            "command": " ".join(cmd),
            "raw_output": raw,
            "services": services,
            "error": result.stderr.strip() or None,
        }

    except subprocess.TimeoutExpired:
        return {
            "command": " ".join(cmd),
            "raw_output": "",
            "services": [],
            "error": f"nmap timed out after {timeout}s",
        }
    except Exception as exc:
        return {
            "command": " ".join(cmd),
            "raw_output": "",
            "services": [],
            "error": str(exc),
        }


def _parse_nmap_output(raw: str) -> list[dict]:
    """
    Parse nmap's text table into a list of service dicts.

    Matches lines like:
        22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1
        80/tcp   open  http    Apache httpd 2.4.52
    """
    services = []
    # Pattern: port/proto  state  service  version-info (optional)
    pattern = re.compile(
        r"^(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)\s*(.*)?$"
    )
    for line in raw.splitlines():
        match = pattern.match(line.strip())
        if match:
            services.append(
                {
                    "port": int(match.group(1)),
                    "protocol": match.group(2),
                    "state": match.group(3),
                    "service": match.group(4),
                    "version": (match.group(5) or "").strip(),
                }
            )
    return services
