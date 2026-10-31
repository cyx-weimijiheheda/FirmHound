"""Executable ELF triage and honest decompilation-fallback stages."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from fsa.safety.policy_engine import PolicyEngine
from fsa.schemas.loader import validate
from fsa.utils.config_files import resolve_config_file
from fsa.utils.hashing import sha256_file
from fsa.utils.jsonio import load_yaml, save_json
from tools.analysis.source_sink_rules import match_binary
from tools.binary.elf_read import iter_imports, iter_strings, load_elf
from tools.binary.elf_triage import triage_elf
from tools.binary.ghidra_export import apply_export, export_binary, resolve_ghidra_headless
from tools.binary.secfeatures import security_features
from tools.filesystem.inventory import inventory_rootfs
from tools.filesystem.startup_parse import parse_all_startup
from tools.pipeline_context import load_artifact, resolve_rootfs, run_path, save_artifact


def _binary_id(relative_path: str) -> str:
    return f"bin-{hashlib.sha256(relative_path.encode()).hexdigest()[:12]}"


def execute_triage(
    run_dir: str,
    max_binaries: int = 500,
    max_strings_per_binary: int = 200,
) -> dict[str, Any]:
    """Inventory and statically summarize real ELF files from the selected rootfs."""
    rootfs = resolve_rootfs(run_dir)
    inventory = inventory_rootfs(rootfs)
    startup = parse_all_startup(rootfs)
    surfaces = load_artifact(run_dir, "attack_surface.json", {"surfaces": []})
    surface_rows = surfaces.get("surfaces", []) if isinstance(surfaces, dict) else []
    summaries: list[dict[str, Any]] = []

    for relative in inventory["elf_paths"][:max_binaries]:
        path = rootfs / relative
        basename = path.name
        startup_refs = len(startup.get("grouped", {}).get(basename, []))
        surface_refs = sum(
            1 for surface in surface_rows if Path(str(surface.get("binary") or "")).name == basename
        )
        elf = load_elf(path)
        if elf is None:
            continue
        imports = sorted(iter_imports(elf))
        strings = list(iter_strings(elf))[:max_strings_per_binary]
        triage = triage_elf(
            path,
            startup_refs=startup_refs,
            attack_surface_refs=surface_refs,
        )
        summary: dict[str, Any] = {
            "binary_id": _binary_id(relative),
            "path": relative,
            "sha256": sha256_file(path),
            "architecture": triage["architecture"],
            "security_features": security_features(path),
            "imports": imports,
            "strings_summary": {
                "sample": strings,
                "sample_count": len(strings),
                "truncated": len(strings) >= max_strings_per_binary,
            },
            "functions": [],
            "network_functions": triage["network_imports"],
            "sources": [],
            "sinks": [],
            "auth_functions": [],
            "validation_functions": [],
            "triage_score": triage["triage_score"],
            "decompile_status": "fallback",
            "triage_reasons": triage["reasons"],
            "danger": triage["danger"],
            "startup_refs": startup_refs,
            "attack_surface_refs": surface_refs,
        }
        matches = match_binary(summary)
        summary["sources"] = sorted({item["type"] for item in matches["sources"]})
        summary["sinks"] = sorted({item["function"] for item in matches["sinks"]})
        summary["validation_functions"] = sorted({item["api"] for item in matches["validations"]})
        validate(summary, schema_name="binary_summary")
        summaries.append(summary)
        save_json(
            run_path(run_dir) / "binaries" / summary["binary_id"] / "binary_summary.json",
            summary,
        )

    payload = {
        "rootfs": str(rootfs),
        "inventory": inventory,
        "startup": startup,
        "summaries": summaries,
        "truncated": len(inventory["elf_paths"]) > max_binaries,
    }
    artifact = save_artifact(run_dir, "binary_summaries.json", payload)
    status = "degraded" if payload["truncated"] else "ok"
    return {
        "status": status,
        "binary_count": len(summaries),
        "inventory_elf_count": inventory["elf_count"],
        "binary_summaries": str(artifact),
    }


def _ref_count(value: Any) -> int:
    if isinstance(value, list | tuple | set):
        return len(value)
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _decompile_priority(summary: dict[str, Any]) -> float:
    """Rank binaries for expensive Ghidra work beyond the coarse triage score.

    Attack-surface/startup references and a web-server path name are stronger
    signals than the many binaries that tie at the same triage score.
    """
    score = float(summary.get("triage_score", 0) or 0)
    reasons = {str(item) for item in (summary.get("triage_reasons") or [])}
    sinks = {str(item) for item in (summary.get("sinks") or [])}
    if "command_execution+format_string" in reasons:
        score += 0.2
    if _ref_count(summary.get("attack_surface_refs")):
        score += 0.3
    if _ref_count(summary.get("startup_refs")):
        score += 0.2
    if sinks & {"system", "popen", "_system", "doSystemCmd", "alpha_system2"}:
        score += 0.2
    path = str(summary.get("path") or "").lower()
    if any(token in path for token in ("httpd", "web", "cgi", "upnp", "soap")):
        score += 0.5
    return score


def _decompile_config(config_path: str | None) -> tuple[dict[str, Any], PolicyEngine]:
    repo = Path(__file__).resolve().parents[2]
    path = resolve_config_file(config_path or repo / "config" / "dev.yaml")
    config = load_yaml(path) or {}
    base = path.parent.parent if path.parent.name == "config" else path.parent
    safety = (config.get("safety") or {}).get("config")
    if safety and not Path(safety).is_absolute():
        safety = str((base / Path(safety)).resolve())
    return config, PolicyEngine.from_yaml(safety)


def _fallback_decompile(
    run_dir: str,
    payload: dict[str, Any],
    reason: str,
    *,
    backend: str = "fallback",
) -> dict[str, Any]:
    record = {
        "status": "degraded",
        "reason": reason,
        "fallback": "pyelftools",
        "backend": backend,
        "binary_count": len(payload.get("summaries", [])),
    }
    save_artifact(run_dir, "decompile.json", record)
    return {
        **record,
        "decompile_status": record["status"],
        "decompile_reason": record["reason"],
    }


def execute_decompile(
    run_dir: str,
    config_path: str | None = None,
) -> dict[str, Any]:
    """Enrich top-N binaries with Ghidra functions/callgraph, or degrade honestly."""
    payload = load_artifact(run_dir, "binary_summaries.json")
    if not isinstance(payload, dict):
        return {"status": "failed", "reason": "binary triage artifact is missing"}
    config, policy = _decompile_config(config_path)
    section = config.get("decompile") if isinstance(config, dict) else {}
    section = section if isinstance(section, dict) else {}
    backend = str(section.get("backend", "auto")).lower()
    max_binaries = max(1, int(section.get("max_binaries", 5)))
    timeout_s = float(section.get("timeout_s", 600))

    if backend in {"fallback", "off", "none"}:
        return _fallback_decompile(
            run_dir,
            payload,
            "decompile.backend disables Ghidra; symbol/string fallback retained",
            backend=backend,
        )
    ghidra = resolve_ghidra_headless(config)
    if ghidra is None:
        return _fallback_decompile(
            run_dir,
            payload,
            "Ghidra headless not found (set decompile.ghidra_headless or GHIDRA_HEADLESS); "
            "symbol/string fallback retained",
        )

    try:
        rootfs = resolve_rootfs(run_dir)
        policy.check_path(rootfs)
    except Exception as exc:  # noqa: BLE001 - fallback, never abort the run
        return _fallback_decompile(
            run_dir,
            payload,
            f"cannot resolve a policy-allowed rootfs: {exc}",
        )

    summaries = [
        item
        for item in payload.get("summaries", [])
        if isinstance(item, dict)
        and item.get("path")
        and not str(item["path"]).endswith(".ko")
        and ".so" not in str(item["path"])
    ]
    summaries.sort(key=_decompile_priority, reverse=True)
    selected = summaries[:max_binaries]
    run = run_path(run_dir)
    out_dir = run / "artifacts" / "decompile"
    out_dir.mkdir(parents=True, exist_ok=True)
    results: dict[str, dict[str, Any]] = {}
    analyzed = 0

    for summary in selected:
        binary_id = str(summary.get("binary_id") or "unknown")
        binary_path = rootfs / str(summary.get("path"))
        try:
            policy.check_path(binary_path)
        except Exception as exc:  # noqa: BLE001 - skip this binary, keep the run
            results[binary_id] = {"status": "skipped", "limitation": str(exc)}
            continue
        if not binary_path.is_file():
            results[binary_id] = {
                "status": "skipped",
                "limitation": f"binary not found: {summary.get('path')}",
            }
            continue
        out_json = out_dir / f"{binary_id}.json"
        exported = export_binary(
            binary_path,
            out_json,
            ghidra,
            timeout=timeout_s,
        )
        if not exported.get("available"):
            results[binary_id] = {
                "status": exported.get("status", "failed"),
                "limitation": exported.get("limitation"),
            }
            continue
        apply_export(summary, exported["export"])
        save_json(
            run / "binaries" / binary_id / "binary_summary.json",
            summary,
        )
        results[binary_id] = {
            "status": "ok",
            "artifact": str(out_json),
            "function_count": len(summary.get("functions", [])),
        }
        analyzed += 1

    status = "ok" if analyzed else "degraded"
    reason = (
        f"Ghidra exported {analyzed}/{len(selected)} selected binaries"
        if analyzed
        else "Ghidra was available but no selected binary could be exported"
    )
    record = {
        "status": status,
        "reason": reason,
        "backend": "ghidra",
        "ghidra_headless": ghidra,
        "selected_binaries": len(selected),
        "analyzed_binaries": analyzed,
        "binaries": results,
        "binary_count": len(payload.get("summaries", [])),
    }
    save_artifact(run_dir, "binary_summaries.json", payload)
    save_artifact(run_dir, "decompile.json", record)
    return {
        **record,
        "decompile_status": status,
        "decompile_reason": reason,
    }
