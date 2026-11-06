"""Deterministic implementations for the bounded agent action catalog.

Every function here only collects facts. None of them may change
``conclusion_category``, ``status``, or ``risk_level``; the loop enforces that
invariant and the final verdict remains the verifier's job.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fsa.reporting.evidence_store import EvidenceStore
from tools.audit.audit_constants import CHAIN_SINKS
from tools.audit.static import _enrich_with_chain
from tools.binary.call_chain import recover_chains
from tools.binary.elf_read import iter_symbols, load_elf
from tools.emulation.qemu_user import run_l1_load_check
from tools.filesystem.startup_parse import parse_all_startup
from tools.pipeline_context import load_artifact
from tools.web.auth_matrix import classify_auth

ActionOutcome = dict[str, Any]


def _add_counterevidence(candidate: dict[str, Any], marker: str) -> None:
    counter = candidate.setdefault("counterevidence", [])
    if marker not in counter:
        counter.append(marker)


def _record_fact(candidate: dict[str, Any], fact: str) -> None:
    facts = candidate.setdefault("agent_facts", [])
    if fact not in facts:
        facts.append(fact)


def _new_evidence(
    store: EvidenceStore,
    run_id: str,
    candidate: dict[str, Any],
    *,
    type: str,  # noqa: A002 - matches EvidenceStore API
    observation: str,
    tool: str,
    source_file: str | None = None,
    fact_status: str = "confirmed",
    contradicts: bool = False,
) -> str:
    item = store.add(
        run_id=run_id,
        stage="AGENT_LOOP",
        type=type,
        observation=observation,
        tool=tool,
        tool_version="1.0",
        source_file=source_file,
        artifact_path=None,
        fact_status=fact_status,
        supports=[] if contradicts else [candidate.get("candidate_id", "")],
        contradicts=[candidate.get("candidate_id", "")] if contradicts else [],
    )
    evidence_id = str(item["evidence_id"])
    candidate.setdefault("evidence", []).append(evidence_id)
    return evidence_id


def _outcome(
    status: str,
    *,
    facts: tuple[str, ...] = (),
    evidence_ids: list[str] | None = None,
    limitations: list[str] | None = None,
) -> ActionOutcome:
    return {
        "status": status,
        "produced_facts": list(facts),
        "evidence_ids": evidence_ids or [],
        "limitations": limitations or [],
    }


def _defined_symbols(context: dict[str, Any]) -> set[str]:
    """Read symbol names when the binary is available; empty on any failure."""
    rootfs = str(context.get("rootfs") or "")
    summary = context.get("binary_summary") or {}
    binary = str(summary.get("path") or "")
    if not rootfs or not binary:
        return set()
    elf = load_elf(Path(rootfs) / binary)
    if elf is None:
        return set()
    try:
        return set(iter_symbols(elf))
    except Exception:  # noqa: BLE001 - malformed ELF degrades to imports/strings
        return set()


def build_context(
    run_dir: str,
    candidate: dict[str, Any],
    summaries: dict[str, Any],
    surfaces: dict[str, Any],
    options: dict[str, Any],
    task: dict[str, Any],
) -> dict[str, Any]:
    """Assemble the immutable-ish context an action may read."""
    rootfs_payload = load_artifact(run_dir, "rootfs.json", {})
    rootfs = ""
    if isinstance(rootfs_payload, dict):
        rootfs = str(rootfs_payload.get("rootfs_path") or "")
    if not rootfs and isinstance(summaries, dict):
        rootfs = str(summaries.get("rootfs") or "")

    binary_id = str(candidate.get("binary_id") or "")
    summary = next(
        (
            item
            for item in (summaries.get("summaries", []) if isinstance(summaries, dict) else [])
            if isinstance(item, dict) and item.get("binary_id") == binary_id
        ),
        {},
    )

    surface_id = str(candidate.get("surface_id") or "")
    surface = next(
        (
            item
            for item in (surfaces.get("surfaces", []) if isinstance(surfaces, dict) else [])
            if isinstance(item, dict) and item.get("surface_id") == surface_id
        ),
        {},
    )

    startup = summaries.get("startup") if isinstance(summaries, dict) else {}
    if not isinstance(startup, dict) or not startup:
        startup = parse_all_startup(rootfs) if rootfs else {}

    authorization = task.get("authorization", {}) if isinstance(task, dict) else {}
    arch = str(summary.get("architecture") or "")
    if not arch and isinstance(summaries, dict):
        for item in summaries.get("summaries", []):
            if isinstance(item, dict) and item.get("architecture"):
                arch = str(item["architecture"])
                break

    return {
        "run_dir": run_dir,
        "rootfs": rootfs or None,
        "binary_summary": summary,
        "surface": surface,
        "surfaces": surfaces.get("surfaces", []) if isinstance(surfaces, dict) else [],
        "startup": startup,
        "arch": arch,
        "tier": str(options.get("tier", "standard")),
        "max_binary_size_mb": int(options.get("max_binary_size_mb", 64)),
        "dynamic_timeout_s": int(
            (options.get("dynamic", {}) or {}).get("qemu_load_check", {}).get("timeout_s", 30)
        ),
        "allow_emulation": bool(authorization.get("allow_emulation", False)),
        "unified_candidates": load_artifact(run_dir, "unified_candidates.json", {}),
    }


def action_recover_call_chain(
    candidate: dict[str, Any],
    *,
    context: dict[str, Any],
    store: EvidenceStore,
    run_id: str,
) -> ActionOutcome:
    """Attach a disassembly-backed call chain, reusing the static helper."""
    summary = context.get("binary_summary") or {}
    rootfs = str(context.get("rootfs") or "")
    before_chain = json.dumps(candidate.get("call_chain", []), sort_keys=True)
    before_evidence = list(candidate.get("evidence", []))
    _enrich_with_chain(candidate, summary, rootfs, store, run_id, stage="AGENT_LOOP")
    after_chain = json.dumps(candidate.get("call_chain", []), sort_keys=True)
    new_ids = [item for item in candidate.get("evidence", []) if item not in before_evidence]
    if after_chain != before_chain:
        _record_fact(candidate, "call_chain_reachable")
        return _outcome("ok", facts=("call_chain_reachable",), evidence_ids=new_ids)
    sink = str((candidate.get("sink") or {}).get("function", ""))
    return _outcome(
        "degraded",
        limitations=[f"no ARM32/MIPS caller recovered for sink {sink!r}"],
    )


def action_cross_check_imports_strings(
    candidate: dict[str, Any],
    *,
    context: dict[str, Any],
    store: EvidenceStore,
    run_id: str,
) -> ActionOutcome:
    """Confirm that the recorded source and sink actually appear in the binary."""
    summary = context.get("binary_summary") or {}
    imports = {str(item) for item in summary.get("imports", []) or []}
    strings = "\n".join(
        str(item) for item in (summary.get("strings_summary", {}) or {}).get("sample", []) or []
    )
    source = candidate.get("source") or {}
    sink = candidate.get("sink") or {}
    source_name = str(source.get("api") or source.get("string") or "")
    if not source_name:
        candidate_name = str(source.get("name") or "")
        if candidate_name and candidate_name != str(source.get("type") or ""):
            source_name = candidate_name
    sink_name = str(sink.get("function") or "")
    symbols = _defined_symbols(context)
    source_checked = bool(source_name)
    source_present = source_checked and (
        source_name in imports or source_name in strings or source_name in symbols
    )
    sink_present = bool(sink_name) and (
        sink_name in imports or sink_name in strings or sink_name in symbols
    )
    ok = sink_present and (not source_checked or source_present)

    evidence_ids: list[str] = []
    limitations: list[str] = []
    if not source_checked:
        limitations.append("source has no concrete api/string symbol to cross-check")
    evidence_ids.append(
        _new_evidence(
            store,
            run_id,
            candidate,
            type="file_observation",
            observation=(
                f"agent cross-check: source={source_name!r} present={source_present}; "
                f"sink={sink_name!r} present={sink_present}"
            ),
            tool="tools.audit.agent_cross_check",
            source_file=str(summary.get("path") or "") or None,
            contradicts=not ok,
        )
    )
    if source_checked and not source_present:
        _add_counterevidence(candidate, "source-not-imported")
        limitations.append(f"source {source_name!r} not found in imports/strings")
    if not sink_present:
        _add_counterevidence(candidate, "sink-not-imported")
        limitations.append(f"sink {sink_name!r} not found in imports/strings")
    _record_fact(candidate, "source_sink_cross_checked")
    status = "ok" if ok else "degraded"
    return _outcome(
        status,
        facts=("source_sink_cross_checked",),
        evidence_ids=evidence_ids,
        limitations=limitations,
    )


def action_check_handler_startup(
    candidate: dict[str, Any],
    *,
    context: dict[str, Any],
    store: EvidenceStore,
    run_id: str,
) -> ActionOutcome:
    """Check whether the candidate handler is launched by an init script."""
    entry = candidate.get("entry") or {}
    surface = context.get("surface") or {}
    handler = str(entry.get("handler") or surface.get("handler") or "")
    startup = context.get("startup") or {}
    grouped = startup.get("grouped", {}) if isinstance(startup, dict) else {}
    targets = {Path(handler).name} if handler else set()
    surface_binary = str(surface.get("binary") or "")
    if surface_binary:
        targets.add(Path(surface_binary).name)
    started = bool(surface.get("startup_evidence")) or any(target in grouped for target in targets)
    if started:
        source = ", ".join(str(item) for item in (surface.get("startup_evidence") or [])) or str(
            handler
        )
        evidence_id = _new_evidence(
            store,
            run_id,
            candidate,
            type="file_observation",
            observation=f"startup evidence confirms handler {handler!r} starts: {source}",
            tool="tools.filesystem.startup_parse",
            source_file=source,
        )
        _record_fact(candidate, "handler_startup_checked")
        _record_fact(candidate, "handler_started")
        return _outcome(
            "ok",
            facts=("handler_startup_checked", "handler_started"),
            evidence_ids=[evidence_id],
        )

    _add_counterevidence(candidate, "handler-not-started")
    _record_fact(candidate, "handler_startup_checked")
    return _outcome(
        "degraded",
        facts=("handler_startup_checked",),
        limitations=[f"handler {handler!r} not found in startup scripts"],
    )


def action_cross_check_evidence_store(
    candidate: dict[str, Any],
    *,
    context: dict[str, Any],
    store: EvidenceStore,
    run_id: str,
) -> ActionOutcome:
    """Resolve evidence references and flag contradictions without inventing facts."""
    all_evidence = store.list_all()
    valid_ids = {str(item.get("evidence_id")) for item in all_evidence}
    refs = [str(item) for item in candidate.get("evidence", []) if str(item).startswith("ev-")]
    dangling = sorted({item for item in refs if item not in valid_ids})
    if dangling:
        candidate["evidence"] = [
            item for item in candidate.get("evidence", []) if str(item) not in dangling
        ]
        unresolved = candidate.setdefault("evidence_unresolved", [])
        for item in dangling:
            if item not in unresolved:
                unresolved.append(item)

    contradictory = [
        str(item.get("evidence_id"))
        for item in all_evidence
        if set(item.get("contradicts", []) or []) & set(refs)
    ]
    if contradictory:
        _add_counterevidence(candidate, "contradictory-evidence")
    _record_fact(candidate, "contradiction_checked")
    limitations = [f"dangling evidence references: {', '.join(dangling)}"] if dangling else []
    return _outcome(
        "degraded" if dangling else "ok",
        facts=("contradiction_checked",),
        limitations=limitations,
    )


def action_verify_auth_hint(
    candidate: dict[str, Any],
    *,
    context: dict[str, Any],
    store: EvidenceStore,
    run_id: str,
) -> ActionOutcome:
    """Resolve ``authorization.required`` only when the auth matrix is confident."""
    entry = candidate.get("entry") or {}
    surface = context.get("surface") or {}
    summary = context.get("binary_summary") or {}
    rootfs = str(context.get("rootfs") or "")
    handler = str(entry.get("handler") or surface.get("handler") or "")
    route = entry.get("route") or surface.get("route")
    binary = Path(rootfs) / str(summary.get("path") or "") if summary.get("path") else None
    hint = classify_auth(route, binary, handler, None)
    if hint.confidence < 0.75 or hint.hint not in {"auth", "preauth"}:
        return _outcome(
            "degraded",
            limitations=[
                f"auth hint {hint.hint!r} at confidence {hint.confidence}; left unresolved"
            ],
        )
    authorization = candidate.setdefault("authorization", {})
    authorization["required"] = hint.hint == "auth"
    authorization["hint"] = hint.hint
    evidence_id = _new_evidence(
        store,
        run_id,
        candidate,
        type="file_observation",
        observation=f"auth matrix: {hint.hint} (confidence={hint.confidence})",
        tool="tools.web.auth_matrix",
        source_file=str(summary.get("path") or "") or None,
    )
    _record_fact(candidate, "auth_known")
    return _outcome("ok", facts=("auth_known",), evidence_ids=[evidence_id])


def action_enrich_from_recovered_handlers(
    candidate: dict[str, Any],
    *,
    context: dict[str, Any],
    store: EvidenceStore,
    run_id: str,
) -> ActionOutcome:
    """Map an unmapped candidate to a recovered registration handler."""
    rootfs = str(context.get("rootfs") or "")
    summary = context.get("binary_summary") or {}
    binary = str(summary.get("path") or "")
    if not rootfs or not binary:
        return _outcome("degraded", limitations=["rootfs or binary path is unavailable"])
    try:
        report = recover_chains(Path(rootfs) / binary, sink_functions=sorted(CHAIN_SINKS))
    except Exception as exc:  # noqa: BLE001 - degrade, never abort
        return _outcome("degraded", limitations=[f"call-chain recovery failed: {exc}"])
    registration = report.get("registration") or {}
    if not registration:
        return _outcome("degraded", limitations=["no registration handler recovered"])
    handler, address = next(iter(registration.items()))
    entry = candidate.setdefault("entry", {})
    entry["handler"] = handler
    entry["handler_addr"] = hex(int(address))
    surfaces = context.get("surfaces") or []
    match = next(
        (item for item in surfaces if isinstance(item, dict) and item.get("handler") == handler),
        None,
    )
    if match and match.get("surface_id"):
        candidate["surface_id"] = match["surface_id"]
    evidence_id = _new_evidence(
        store,
        run_id,
        candidate,
        type="decompile",
        observation=f"registration handler {handler!r} at 0x{int(address):x}",
        tool="tools.binary.call_chain",
        source_file=binary,
    )
    _record_fact(candidate, "entry_mapped")
    return _outcome("ok", facts=("entry_mapped",), evidence_ids=[evidence_id])


def action_qemu_load_check(
    candidate: dict[str, Any],
    *,
    context: dict[str, Any],
    store: EvidenceStore,
    run_id: str,
) -> ActionOutcome:
    """Run the harmless L1 QEMU user-mode load check."""
    if not context.get("allow_emulation"):
        return _outcome("skipped", limitations=["emulation is not authorized"])
    rootfs = str(context.get("rootfs") or "")
    arch = str(context.get("arch") or "")
    if not rootfs or not arch:
        return _outcome("degraded", limitations=["rootfs or architecture is unknown"])
    result = run_l1_load_check(rootfs, arch, timeout=float(context.get("dynamic_timeout_s", 30)))
    if result.get("status") == "skipped":
        return _outcome(
            "degraded",
            limitations=[str(result.get("limitation", "QEMU is unavailable"))],
        )
    load_ok = bool(result.get("load_ok"))
    evidence_id = _new_evidence(
        store,
        run_id,
        candidate,
        type="emulation",
        observation=f"QEMU L1 load check: load_ok={load_ok}, qemu={result.get('qemu')}",
        tool="tools.emulation.qemu_user",
        fact_status="confirmed" if load_ok else "unknown",
    )
    _record_fact(candidate, "dynamic_load_checked")
    return _outcome(
        "ok" if load_ok else "degraded",
        facts=("dynamic_load_checked",),
        evidence_ids=[evidence_id],
        limitations=[] if load_ok else ["L1 load check did not report QEMU_OK"],
    )


def action_klee_feasibility(
    candidate: dict[str, Any],
    *,
    context: dict[str, Any],
    store: EvidenceStore,
    run_id: str,
) -> ActionOutcome:
    """Consume an existing KLEE ``symex`` result; never run or prune in-loop."""
    unified = context.get("unified_candidates") or {}
    target = next(
        (
            item
            for item in unified.get("candidates", [])
            if isinstance(item, dict) and item.get("candidate_id") == candidate.get("candidate_id")
        ),
        None,
    )
    symex = (target or {}).get("symex") if isinstance(target, dict) else None
    if not isinstance(symex, dict) or not symex:
        return _outcome(
            "skipped",
            limitations=["no existing KLEE symex result; run EXTERNAL_ANALYSIS/SYMEX_PRUNE first"],
        )
    reason = str(symex.get("reason", "unknown"))
    _record_fact(candidate, "symex_feasibility_checked")
    if reason == "infeasible":
        _add_counterevidence(candidate, "klee-infeasible")
        evidence_id = _new_evidence(
            store,
            run_id,
            candidate,
            type="command_output",
            observation=f"KLEE reports infeasible path: {symex.get('detail', '')}".strip(),
            tool="tools.external.klee",
            fact_status="confirmed",
        )
        return _outcome("ok", facts=("symex_feasibility_checked",), evidence_ids=[evidence_id])
    return _outcome(
        "degraded",
        facts=("symex_feasibility_checked",),
        limitations=[f"KLEE result is {reason!r}; no conclusion drawn"],
    )


ACTION_HANDLERS = {
    "recover_call_chain": action_recover_call_chain,
    "cross_check_imports_strings": action_cross_check_imports_strings,
    "check_handler_startup": action_check_handler_startup,
    "cross_check_evidence_store": action_cross_check_evidence_store,
    "verify_auth_hint": action_verify_auth_hint,
    "enrich_from_recovered_handlers": action_enrich_from_recovered_handlers,
    "qemu_load_check": action_qemu_load_check,
    "klee_feasibility": action_klee_feasibility,
}
