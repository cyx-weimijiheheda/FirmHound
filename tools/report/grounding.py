"""Evidence-grounding summary for the final report.

Everything here is derived from artifacts that already exist in the run
directory. It never runs analysis, calls a model, or reads external reports.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from tools.binary.call_chain import SUPPORTED_ARCHES


def _candidate_binary(
    candidate: dict[str, Any],
    summaries: dict[str, dict[str, Any]],
    rootfs: Path | None,
) -> tuple[bool, dict[str, Any] | None]:
    summary = summaries.get(str(candidate.get("binary_id") or ""))
    if not isinstance(summary, dict):
        return False, None
    relative = str(summary.get("path") or "")
    if rootfs is None or not relative:
        return False, summary
    try:
        return (rootfs / relative).is_file(), summary
    except OSError:
        return False, summary


def _chain_length(candidate: dict[str, Any]) -> int:
    chain = candidate.get("call_chain")
    return len(chain) if isinstance(chain, list) else 0


def _evidence_counts(
    candidates: list[dict[str, Any]],
    evidence_dir: Path,
) -> tuple[int, int]:
    referenced = 0
    resolved = 0
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        ids = candidate.get("evidence")
        if not isinstance(ids, list):
            continue
        for evidence_id in ids:
            value = str(evidence_id)
            referenced += 1
            if value.startswith("ev-") and (evidence_dir / f"{value}.json").is_file():
                resolved += 1
    return referenced, resolved


def _decompile_state(
    decompile: dict[str, Any],
    run_state: dict[str, Any],
) -> tuple[str, str | None, str | None]:
    if isinstance(decompile, dict) and decompile:
        status = str(decompile.get("status") or "unknown")
        reason = decompile.get("reason")
        fallback = decompile.get("fallback")
        return status, str(reason) if reason else None, str(fallback) if fallback else None
    artifacts = run_state.get("artifacts") if isinstance(run_state, dict) else {}
    artifacts = artifacts if isinstance(artifacts, dict) else {}
    fallback = artifacts.get("fallback")
    if fallback:
        reason = artifacts.get("reason")
        return "fallback", str(reason) if reason else None, str(fallback)
    return "unknown", None, None


def build_grounding(
    run_dir: str | Path,
    *,
    rootfs: dict[str, Any],
    binaries: dict[str, Any],
    ranking: dict[str, Any],
    verdict: dict[str, Any],
    run_state: dict[str, Any],
    decompile: dict[str, Any],
    external: dict[str, Any],
    agent_trace: dict[str, Any],
) -> dict[str, Any]:
    """Summarize provenance, traceability, coverage, and capability gaps."""
    run = Path(run_dir)
    rootfs_value = ""
    if isinstance(rootfs, dict):
        rootfs_value = str(rootfs.get("rootfs_path") or rootfs.get("input_path") or "")
    rootfs_path = Path(rootfs_value) if rootfs_value else None

    summaries: dict[str, dict[str, Any]] = {}
    detected_arches: set[str] = set()
    binary_rows = binaries.get("summaries") if isinstance(binaries, dict) else []
    for summary in binary_rows or []:
        if not isinstance(summary, dict):
            continue
        binary_id = str(summary.get("binary_id") or "")
        if binary_id:
            summaries[binary_id] = summary
        arch = str(summary.get("architecture") or "").lower()
        if arch:
            detected_arches.add(arch)

    candidates = ranking.get("candidates") if isinstance(ranking, dict) else []
    candidates = [item for item in (candidates or []) if isinstance(item, dict)]
    traceable = 0
    missing: list[str] = []
    with_chain = 0
    for candidate in candidates:
        ok, _summary = _candidate_binary(candidate, summaries, rootfs_path)
        if ok:
            traceable += 1
        else:
            missing.append(str(candidate.get("candidate_id") or "?"))
        if _chain_length(candidate) >= 2:
            with_chain += 1

    verdicts = verdict.get("verdicts") if isinstance(verdict, dict) else []
    verdicts = [item for item in (verdicts or []) if isinstance(item, dict)]
    reviewed_ids = {str(item.get("candidate_id")) for item in verdicts}
    candidate_ids = {str(item.get("candidate_id")) for item in candidates}
    orphan_verdicts = sorted(reviewed_ids - candidate_ids)

    referenced, resolved = _evidence_counts(candidates, run / "evidence")
    decompile_status, decompile_reason, decompile_fallback = _decompile_state(
        decompile, run_state
    )

    per_tool = external.get("per_tool") if isinstance(external, dict) else {}
    external_tools = []
    for name, info in sorted((per_tool or {}).items()):
        if isinstance(info, dict):
            external_tools.append(
                {
                    "name": name,
                    "status": str(info.get("status") or "unknown"),
                    "limitation": info.get("limitation"),
                }
            )

    model = agent_trace.get("model") if isinstance(agent_trace, dict) else {}
    model = model if isinstance(model, dict) else {}
    model_calls = int(model.get("calls") or 0)
    model_used = bool(model.get("used")) or model_calls > 0

    unsupported = sorted(arch for arch in detected_arches if arch not in SUPPORTED_ARCHES)
    rootfs_data = rootfs if isinstance(rootfs, dict) else {}
    return {
        "input_type": rootfs_data.get("input_type", "unknown"),
        "unpack_method": rootfs_data.get("unpack_method"),
        "rootfs_score": rootfs_data.get("rootfs_score"),
        "extraction_confidence": rootfs_data.get("extraction_confidence"),
        "unpack_degraded": bool(rootfs_data.get("unpack_degraded", False)),
        "rootfs_candidates": rootfs_data.get("rootfs_candidates"),
        "rootfs_duplicates_suppressed": rootfs_data.get(
            "rootfs_duplicates_suppressed"
        ),
        "binary_truncated": bool(binaries.get("truncated", False))
        if isinstance(binaries, dict)
        else False,
        "candidate_total": len(candidates),
        "candidate_traceable": traceable,
        "candidate_missing_binary": len(missing),
        "candidate_missing_ids": missing[:10],
        "candidates_with_chain": with_chain,
        "candidates_without_chain": len(candidates) - with_chain,
        "detected_architectures": sorted(detected_arches),
        "chain_supported_arches": sorted(SUPPORTED_ARCHES),
        "chain_unsupported_architectures": unsupported,
        "reviewed_total": len(verdicts),
        "unreviewed_total": len(candidate_ids - reviewed_ids),
        "orphan_verdicts": orphan_verdicts,
        "evidence_referenced": referenced,
        "evidence_resolved": resolved,
        "decompile_status": decompile_status,
        "decompile_reason": decompile_reason,
        "decompile_fallback": decompile_fallback,
        "decompile_backend": (
            decompile.get("backend") if isinstance(decompile, dict) else None
        ),
        "decompile_analyzed": (
            int(decompile.get("analyzed_binaries") or 0)
            if isinstance(decompile, dict)
            else 0
        ),
        "decompile_selected": (
            int(decompile.get("selected_binaries") or 0)
            if isinstance(decompile, dict)
            else 0
        ),
        "external_tools": external_tools,
        "model_used": model_used,
        "model_provider": model.get("provider"),
        "model_name": model.get("model"),
        "model_calls": model_calls,
        "model_tokens": int(model.get("tokens") or 0),
        "model_fallback_count": int(model.get("fallback_count") or 0),
        "agent_enabled": bool(agent_trace.get("enabled", False))
        if isinstance(agent_trace, dict)
        else False,
        "agent_status": agent_trace.get("status")
        if isinstance(agent_trace, dict)
        else None,
    }
