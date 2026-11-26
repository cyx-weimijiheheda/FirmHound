"""Readiness checks for the selected native or Docker FirmRec backend.

This module is used by ``make firmrec-doctor``. It never raises and never runs
the firmware pipeline; it only inspects the operator's machine and reports what
is missing. Optional host tools are reported as warnings so a partially
provisioned machine still produces a useful answer.
"""

from __future__ import annotations

import shutil
from typing import Any

from tools.external.firmrec.runner import FirmrecAnalyzer

_REQUIRED_COMMANDS = ("psql", "binwalk")
_OPTIONAL_COMMANDS = ("sasquatch", "unsquashfs", "fakeroot", "fakechroot", "pg_isready")
_HINTS = {
    "repo_dir": "clone https://github.com/seclab-fudan/FirmRec into ./vendor/FirmRec",
    "python_bin": "create a Python 3.9 env and install requirements-firmrec.txt",
    "ghidra_headless": "install Ghidra 10.2.2 and point at support/analyzeHeadless",
    "firmrec_static_jar": "build firmentry/firmrec-static.jar (see docs/guide/firmrec-native.md)",
    "vuln_firmware_images": (
        "provide an upstream vuln_info tree (vuln_info_dir/official) or "
        "vuln_firmware_dir/<CVE>/ with vulnerable firmware"
    ),
    "psql": "install PostgreSQL client/server and create the root superuser role",
    "binwalk": "install binwalk 2.3.x (not v3)",
    "sasquatch": "build sasquatch for SquashFS images with vendor patches",
    "fakeroot": "install fakeroot (upstream extract.sh)",
    "fakechroot": "install fakechroot (upstream unpack.sh)",
}


def _command_status(name: str) -> bool:
    return shutil.which(name) is not None


def check_local_stack(config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return a structured readiness report for the native backend."""
    cfg = dict(config or {})
    analyzer = FirmrecAnalyzer(cfg)

    required: list[str] = list(analyzer._local_missing())  # noqa: SLF001 - same package
    required.extend(analyzer._vuln_info_missing())  # noqa: SLF001 - same package

    commands = {name: _command_status(name) for name in (*_REQUIRED_COMMANDS, *_OPTIONAL_COMMANDS)}
    for name in _REQUIRED_COMMANDS:
        if not commands[name]:
            required.append(f"command:{name}")

    warnings = [f"command:{name}" for name in _OPTIONAL_COMMANDS if not commands[name]]
    required = list(dict.fromkeys(required))
    warnings = list(dict.fromkeys(warnings))

    status = "ok" if not required else "missing"
    if not required and warnings:
        status = "degraded"
    return {
        "status": status,
        "backend": analyzer._resolve_backend(),  # noqa: SLF001 - same package
        "repo_dir": str(analyzer.repo_dir or ""),
        "python_bin": str(analyzer.python_bin or ""),
        "ghidra_headless": str(analyzer.ghidra_headless or ""),
        "firmrec_static_jar": str(analyzer.firmrec_static_jar or ""),
        "missing": required,
        "warnings": warnings,
        "commands": commands,
        "hints": {item: _HINTS[item] for item in required if item in _HINTS},
        "config": {
            "backend": analyzer.backend,
            "vuln_info_source": analyzer.vuln_info_source,
            "vuln_info_dir": str(analyzer.vuln_info_dir or ""),
            "official_vuln_info_path": str(analyzer.official_vuln_info_path or ""),
            "vuln_firmware_dir": str(analyzer.vuln_firmware_dir or ""),
            "signature_db": analyzer.signature_db,
        },
    }


def check_stack(config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Check the backend that will actually run, without requiring duplicate host tools."""
    analyzer = FirmrecAnalyzer(config)
    if analyzer._resolve_backend() != "docker":  # noqa: SLF001 - same package
        return check_local_stack(config)
    probe = analyzer.probe()
    return {
        "status": "ok" if probe.available else "missing",
        "backend": "docker",
        "image": analyzer.image,
        "version": probe.version,
        "missing": probe.missing,
        "warnings": [],
        "commands": {},
        "hints": {},
        "note": probe.notes,
    }


def format_report(report: dict[str, Any]) -> str:
    """Render a short human-readable readiness report."""
    lines = [f"FirmRec backend: {report.get('backend', 'unknown')} ({report.get('status')})"]
    keys = (
        ("image", "version")
        if report.get("backend") == "docker"
        else ("repo_dir", "python_bin", "ghidra_headless", "firmrec_static_jar")
    )
    for key in keys:
        lines.append(f"  {key}: {report.get(key) or '<not configured>'}")
    if report.get("missing"):
        lines.append("  missing:")
        for item in report["missing"]:
            hint = (report.get("hints") or {}).get(item, "")
            lines.append(f"    - {item}{': ' + hint if hint else ''}")
    if report.get("warnings"):
        lines.append("  warnings:")
        for item in report["warnings"]:
            lines.append(f"    - {item}")
    if not report.get("missing"):
        lines.append("  ready for `external.firmrec.enabled=true`")
    return "\n".join(lines)


__all__ = ["check_local_stack", "check_stack", "format_report"]
