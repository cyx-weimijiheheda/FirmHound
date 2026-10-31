"""Optional Ghidra headless export for binary summaries and call chains.

Ghidra is used only when explicitly configured or discoverable. The export
script is the generic CFG/CG exporter already shipped for mini-BOND; it never
executes the target. Missing Ghidra or a failed import degrades to the existing
symbol/string fallback and never aborts a run.
"""

from __future__ import annotations

import json
import os
import shutil
import uuid
from pathlib import Path
from typing import Any

from fsa.utils.proc import run_command
from tools.analysis.source_sink_rules import (
    classify_sink,
    classify_source,
    classify_validation,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT_DIR = _REPO_ROOT / "tools" / "external" / "bond" / "ghidra_scripts"
_SCRIPT_NAME = "ExportCfgCg.java"
_MAX_FUNCTIONS = 1000
_MAX_STRING = 300


def resolve_ghidra_headless(config: dict[str, Any] | None = None) -> str | None:
    """Return a usable analyzeHeadless path from config, env, PATH, or common dirs."""
    configured = ""
    if isinstance(config, dict):
        section = config.get("decompile")
        if isinstance(section, dict):
            configured = str(section.get("ghidra_headless") or "")
    candidates = [
        configured,
        os.environ.get("GHIDRA_HEADLESS", ""),
        "/opt/ghidra/support/analyzeHeadless",
        "/usr/share/ghidra/support/analyzeHeadless",
    ]
    for value in candidates:
        if value and Path(value).is_file():
            return str(Path(value))
    return shutil.which("analyzeHeadless")


def _clean_string(value: Any) -> str:
    text = " ".join(str(value).split())
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        text = text[1:-1]
    return text[:_MAX_STRING]


def export_binary(
    binary: str | Path,
    out_json: str | Path,
    ghidra_headless: str,
    *,
    timeout: float = 600.0,
) -> dict[str, Any]:
    """Run Ghidra headless on one binary and return the parsed export.

    Results carry ``available`` so callers can distinguish a real Ghidra export
    from an honest fallback without raising.
    """
    binary = Path(binary).resolve()
    out_json = Path(out_json).resolve()
    if not binary.is_file():
        return {
            "status": "failed",
            "available": False,
            "limitation": f"binary does not exist: {binary}",
        }
    if not Path(ghidra_headless).is_file():
        return {
            "status": "degraded",
            "available": False,
            "limitation": f"Ghidra headless not found: {ghidra_headless}",
        }
    script = _SCRIPT_DIR / _SCRIPT_NAME
    if not script.is_file():
        return {
            "status": "degraded",
            "available": False,
            "limitation": f"Ghidra export script missing: {script}",
        }

    out_json.parent.mkdir(parents=True, exist_ok=True)
    project_dir = out_json.parent / "ghidra-projects"
    project_dir.mkdir(parents=True, exist_ok=True)
    project_name = f"fsa_{uuid.uuid4().hex[:12]}"
    command = [
        ghidra_headless,
        str(project_dir),
        project_name,
        "-import",
        str(binary),
        "-overwrite",
        "-scriptPath",
        str(_SCRIPT_DIR),
        "-postScript",
        script.name,
        str(out_json),
        "-deleteProject",
    ]
    result = run_command(command, timeout=timeout, env={"LC_ALL": "C"})
    if result.status != "success":
        return {
            "status": "degraded" if result.status == "timeout" else "failed",
            "available": False,
            "limitation": (
                f"Ghidra export {result.status}: "
                f"{(result.stderr or result.stdout)[-500:]}"
            ),
        }
    if not out_json.is_file():
        return {
            "status": "failed",
            "available": False,
            "limitation": "Ghidra completed without writing the export JSON",
        }
    try:
        exported = json.loads(out_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "status": "failed",
            "available": False,
            "limitation": f"invalid Ghidra export JSON: {exc}",
        }
    if not isinstance(exported.get("functions"), dict) or not isinstance(
        exported.get("callgraph"), dict
    ):
        return {
            "status": "failed",
            "available": False,
            "limitation": "Ghidra export is missing functions/callgraph mappings",
        }
    return {
        "status": "ok",
        "available": True,
        "binary": str(binary),
        "artifact": str(out_json),
        "export": exported,
    }


def summarize_functions(export: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert a Ghidra export into ``binary_summary.functions`` records."""
    functions = export.get("functions") or {}
    callgraph = export.get("callgraph") or {}
    reverse: dict[str, list[str]] = {}
    for caller, callees in callgraph.items():
        for callee in callees or []:
            reverse.setdefault(str(callee), []).append(str(caller))

    records: list[dict[str, Any]] = []
    for addr, info in sorted(functions.items(), key=lambda item: str(item[0])):
        if not isinstance(info, dict):
            continue
        name = str(info.get("name") or f"sub_{addr}")
        strings = [
            cleaned
            for item in (info.get("strings") or [])
            if (cleaned := _clean_string(item))
        ][:20]
        callee_addrs = [str(item) for item in (callgraph.get(addr) or [])]
        callee_names = [
            str((functions.get(item) or {}).get("name") or item)
            for item in callee_addrs
        ]
        caller_names = [
            str((functions.get(item) or {}).get("name") or item)
            for item in reverse.get(addr, [])
        ]
        records.append(
            {
                "name": name,
                "addr": str(addr),
                "callers": caller_names,
                "callees": callee_names,
                "caller_addrs": reverse.get(addr, []),
                "callee_addrs": callee_addrs,
                "strings": strings,
                "is_source": bool(classify_source(name))
                or any(classify_source(item) for item in strings),
                "is_sink": bool(classify_sink(name)),
                "is_validation": bool(classify_validation(name))
                or any(classify_validation(item) for item in strings),
                "is_auth": "auth" in name.lower() or "login" in name.lower(),
            }
        )
        if len(records) >= _MAX_FUNCTIONS:
            break
    return records


def _name_matches(name: str, sink: str) -> bool:
    normalized = name.lower().strip("_")
    target = sink.lower().strip("_")
    return normalized == target or normalized.endswith(f"_{target}")


def chain_callers(summary: dict[str, Any], sink_func: str) -> dict[str, Any]:
    """Find Ghidra callgraph edges whose callee matches ``sink_func``."""
    functions = [
        item
        for item in (summary.get("functions") or [])
        if isinstance(item, dict) and item.get("addr")
    ]
    by_addr = {str(item["addr"]): item for item in functions}
    callers: list[dict[str, Any]] = []
    for caller_addr, caller in by_addr.items():
        for callee_addr in caller.get("callee_addrs") or []:
            callee = by_addr.get(str(callee_addr))
            if callee is None or not _name_matches(str(callee.get("name")), sink_func):
                continue
            source = next(
                (
                    item
                    for item in caller.get("strings") or []
                    if classify_source(str(item))
                ),
                None,
            )
            if source is None:
                for sibling_addr in caller.get("callee_addrs") or []:
                    sibling = by_addr.get(str(sibling_addr)) or {}
                    sibling_name = str(sibling.get("name") or "")
                    if classify_source(sibling_name):
                        source = sibling_name
                        break
            filters = [
                str((by_addr.get(str(item)) or {}).get("name") or item)
                for item in caller.get("callee_addrs") or []
                if classify_validation(
                    str((by_addr.get(str(item)) or {}).get("name") or item)
                )
            ]
            try:
                caller_int = int(str(caller_addr), 16)
                sink_int = int(str(callee_addr), 16)
            except ValueError:
                continue
            callers.append(
                {
                    "func_addr": caller_int,
                    "func_name": str(caller.get("name") or caller_addr),
                    "sink": sink_func,
                    "sink_addr": sink_int,
                    "same_func_source": bool(source),
                    "source": source,
                    "same_func_filters": filters,
                }
            )
    return {"status": "ok" if callers else "no-callers", "sink_callers": callers}


def apply_export(summary: dict[str, Any], export: dict[str, Any]) -> dict[str, Any]:
    """Attach Ghidra functions to a binary summary and mark it fully analyzed."""
    summary["functions"] = summarize_functions(export)
    summary["decompile_status"] = "full"
    summary["decompile_backend"] = "ghidra"
    return summary
