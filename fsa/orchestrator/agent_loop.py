"""Bounded, evidence-driven candidate loop for the optional AGENT_LOOP stage."""

from __future__ import annotations

import hashlib
import json
import time
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fsa.orchestrator.agent_catalog import eligible_actions, rank_actions
from fsa.orchestrator.agent_model import choose_with_model
from fsa.orchestrator.agent_options import effective_runtime
from fsa.orchestrator.agent_visualization import write_agent_visualization
from fsa.prompts.manager import PromptManager
from fsa.reporting.decision_store import DecisionStore
from fsa.reporting.evidence_store import EvidenceStore
from fsa.runtime import Budget, load_runtime
from fsa.runtime.mock import OfflineRuleRuntime
from fsa.safety.policy_engine import PolicyEngine
from fsa.schemas.loader import validate
from fsa.utils.jsonio import load_json, save_json
from fsa.utils.progress import report_detail, report_note
from tools.analysis.risk_score import rank_candidates
from tools.audit.agent_actions import ACTION_HANDLERS, build_context
from tools.pipeline_context import load_artifact, load_task, run_path

_FORBIDDEN_FIELDS = ("conclusion_category", "status", "risk_level")
_ACTION_STATUSES = {"ok", "degraded", "failed", "partial", "skipped", "unsafe"}


def _normalize_action_outcome(outcome: Any, action: Any) -> dict[str, Any]:
    """Enforce the action contract and facts declared by its catalog entry."""
    if not isinstance(outcome, dict):
        return {
            "status": "failed",
            "produced_facts": [],
            "evidence_ids": [],
            "limitations": ["action returned a non-dict result"],
        }

    raw_limitations = outcome.get("limitations", []) or []
    if isinstance(raw_limitations, str):
        raw_limitations = [raw_limitations]
    if not isinstance(raw_limitations, list | tuple | set):
        raw_limitations = ["action returned malformed limitations"]
    limitations = [str(item) for item in raw_limitations]
    status = str(outcome.get("status", "failed"))
    if status not in _ACTION_STATUSES:
        limitations.append(f"action returned unsupported status: {status}")
        status = "failed"
    if status == "partial":
        status = "degraded"
    elif status == "unsafe":
        status = "failed"

    raw_produced = outcome.get("produced_facts", []) or []
    if isinstance(raw_produced, str):
        raw_produced = [raw_produced]
    if not isinstance(raw_produced, list | tuple | set):
        raw_produced = []
        limitations.append("action returned malformed produced_facts")
        status = "failed"
    produced = {str(item) for item in raw_produced}
    allowed = {str(item) for item in getattr(action, "produces", ())}
    unexpected = produced - allowed
    if unexpected:
        limitations.append(f"action claimed undeclared facts: {sorted(unexpected)}")
        produced -= unexpected
        status = "failed"

    raw_evidence = outcome.get("evidence_ids", []) or []
    if isinstance(raw_evidence, str):
        raw_evidence = [raw_evidence]
    if not isinstance(raw_evidence, list | tuple | set):
        raw_evidence = []
        limitations.append("action returned malformed evidence_ids")
        status = "failed"
    evidence_ids = [str(item) for item in raw_evidence]
    return {
        "status": status,
        "produced_facts": sorted(produced),
        "evidence_ids": evidence_ids,
        "limitations": limitations,
    }


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _signature(candidate: dict[str, Any]) -> str:
    payload = {
        "evidence": sorted(str(item) for item in candidate.get("evidence", [])),
        "call_chain": candidate.get("call_chain", []),
        "validation": candidate.get("validation", []),
        "auth": (candidate.get("authorization") or {}).get("required"),
        "missing": candidate.get("decisive_missing_fact"),
        "facts": sorted(str(item) for item in candidate.get("agent_facts", [])),
    }
    raw = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _derive_missing(candidate: dict[str, Any], surface: dict[str, Any]) -> set[str]:
    missing: set[str] = set()
    facts = {str(item) for item in candidate.get("agent_facts", [])}
    call_chain = candidate.get("call_chain") or []
    counter = candidate.get("counterevidence") or []
    if len(call_chain) < 2 or "call-chain-not-proven" in counter:
        missing.add("call_chain_reachable")
    if "source_sink_cross_checked" not in facts:
        missing.add("source_sink_cross_checked")
    entry = candidate.get("entry") or {}
    has_handler = bool(entry.get("handler") or entry.get("route") or (surface or {}).get("handler"))
    if has_handler and "handler_startup_checked" not in facts:
        missing.add("handler_startup_checked")
    if (candidate.get("authorization") or {}).get("required") is None:
        missing.add("auth_known")
    if (candidate.get("evidence") or candidate.get("counterevidence")) and (
        "contradiction_checked" not in facts
    ):
        missing.add("contradiction_checked")
    if candidate.get("surface_id") in (None, "", "unmapped-surface") or not entry.get("handler"):
        missing.add("entry_mapped")
    return missing


@dataclass
class CandidateState:
    """Mutable per-candidate loop state; never serialized directly."""

    candidate: dict[str, Any]
    initial_missing: list[str]
    missing: set[str]
    tried: set[str] = field(default_factory=set)
    failed_actions: int = 0
    no_progress: int = 0
    last_signature: str = ""
    stalled: bool = False
    skipped: bool = False
    evidence_added: list[str] = field(default_factory=list)
    status: str = "ok"


def _budget_block(options: dict[str, Any]) -> dict[str, Any]:
    model = options.get("model", {})
    return {
        "max_candidates": int(options.get("max_candidates", 10)),
        "max_steps": int(options.get("max_steps", 20)),
        "max_steps_per_candidate": int(options.get("max_steps_per_candidate", 4)),
        "max_tool_calls": int(options.get("max_tool_calls", 40)),
        "max_seconds": float(options.get("max_seconds", 120)),
        "used_candidates": 0,
        "used_steps": 0,
        "used_tool_calls": 0,
        "used_seconds": 0.0,
        "max_model_calls": int(model.get("max_calls", 8)),
        "used_model_calls": 0,
        "max_model_tokens": int(model.get("max_tokens", 4000)),
        "used_model_tokens": 0,
    }


def _trace_skeleton(
    run_id: str,
    options: dict[str, Any],
    *,
    provider: str,
    model_name: str,
) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "enabled": bool(options.get("enabled", False)),
        "tier": str(options.get("tier", "standard")),
        "status": "skipped",
        "started_at": _now(),
        "finished_at": _now(),
        "requested": {
            "enabled": bool(options.get("enabled", False)),
            "tier": str(options.get("requested_tier", options.get("tier", "standard"))),
            "source": "task_card",
        },
        "disabled_reason": options.get("disabled_reason"),
        "budget": _budget_block(options),
        "model": {
            "used": False,
            "provider": provider,
            "model": model_name,
            "calls": 0,
            "tokens": 0,
            "fallback_count": 0,
            "last_fallback_reason": None,
        },
        "candidates": [],
        "steps": [],
        "summary": {
            "stop_reason": "not started",
            "steps": 0,
            "actions": {},
            "evidence_added": 0,
            "resolved_candidates": 0,
            "stalled_candidates": 0,
            "skipped_candidates": 0,
        },
        "limitations": list(options.get("limitations", [])),
    }


def _write_trace(run: Path, trace: dict[str, Any]) -> Path:
    trace["finished_at"] = _now()
    validate(trace, schema_name="agent_trace")
    path = run / "artifacts" / "agent_trace.json"
    save_json(path, trace)
    try:
        write_agent_visualization(run, trace)
    except Exception as exc:  # noqa: BLE001 - visualization must not fail analysis
        trace["limitations"].append(
            f"agent execution visualization could not be written: {type(exc).__name__}: {exc}"
        )
        save_json(path, trace)
    return path


def _finalize_trace(
    trace: dict[str, Any],
    states: list[CandidateState],
    *,
    stop_reason: str,
    status: str | None = None,
) -> None:
    trace["candidates"] = [
        {
            "candidate_id": str(state.candidate.get("candidate_id", "")),
            "initial_missing_facts": state.initial_missing,
            "final_missing_facts": sorted(state.missing),
            "actions_attempted": sorted(state.tried),
            "evidence_added": state.evidence_added,
            "dangling_evidence": sorted(
                {str(item) for item in state.candidate.get("evidence_unresolved", [])}
            ),
            "status": state.status,
            "no_progress_streak": state.no_progress,
        }
        for state in states
    ]
    trace["summary"]["stop_reason"] = stop_reason
    trace["summary"]["steps"] = len(trace["steps"])
    trace["summary"]["resolved_candidates"] = sum(
        1 for state in states if not state.missing and not state.skipped and not state.stalled
    )
    trace["summary"]["stalled_candidates"] = sum(1 for state in states if state.stalled)
    trace["summary"]["skipped_candidates"] = sum(1 for state in states if state.skipped)
    trace["summary"]["evidence_added"] = sum(len(entry["evidence_ids"]) for entry in trace["steps"])
    actions: dict[str, int] = {}
    for entry in trace["steps"]:
        action = str(entry["selected_action"])
        actions[action] = actions.get(action, 0) + 1
    trace["summary"]["actions"] = actions
    if status is None:
        if not trace["steps"]:
            status = "skipped"
        elif (
            any(entry["status"] in {"degraded", "failed", "skipped"} for entry in trace["steps"])
            or trace["summary"]["stalled_candidates"]
            or trace["summary"]["skipped_candidates"]
            or any(state.status == "degraded" for state in states)
        ):
            status = "degraded"
        else:
            status = "ok"
    trace["status"] = status


def _restore_forbidden(candidate: dict[str, Any], snapshot: dict[str, Any]) -> list[str]:
    violations: list[str] = []
    for key in _FORBIDDEN_FIELDS:
        if candidate.get(key) != snapshot[key]:
            candidate[key] = snapshot[key]
            violations.append(key)
    return violations


def _update_ranking(run: Path, candidates: list[dict[str, Any]], enriched: dict[str, Any]) -> None:
    merged = [enriched.get(str(item.get("candidate_id")), item) for item in candidates]
    ranked = rank_candidates(merged)
    for candidate in ranked:
        validate(candidate, schema_name="candidate")
    payload = {"run_id": run.name, "candidates": ranked}
    save_json(run / "artifacts" / "ranking.json", payload)
    save_json(run / "ranking.json", payload)

    unified_path = run / "artifacts" / "unified_candidates.json"
    if unified_path.is_file():
        unified = load_json(unified_path)
        if isinstance(unified, dict):
            for index, item in enumerate(unified.get("candidates", [])):
                cid = str(item.get("candidate_id", "")) if isinstance(item, dict) else ""
                if cid in enriched:
                    unified["candidates"][index] = enriched[cid]
            for item in unified.get("candidates", []):
                validate(item, schema_name="candidate")
            save_json(unified_path, unified)


def run_agent_loop(
    run_dir: str | Path,
    *,
    options: dict[str, Any],
    config: dict[str, Any],
    runtime: Any | None = None,
    prompts: PromptManager | None = None,
) -> dict[str, Any]:
    """Run the bounded loop and return a stage-style status dict."""
    run = run_path(run_dir)
    task = load_task(run)
    runtime_name = effective_runtime(options, config)
    runtime_obj = runtime or load_runtime(runtime_name)
    model_name = str(getattr(runtime_obj, "model", "") or "")
    trace = _trace_skeleton(run.name, options, provider=runtime_name, model_name=model_name)

    if not options.get("enabled", False):
        trace["disabled_reason"] = options.get("disabled_reason") or "not requested"
        _finalize_trace(trace, [], stop_reason="agent disabled", status="skipped")
        path = _write_trace(run, trace)
        return {"status": "skipped", "reason": "agent disabled", "agent_trace": str(path)}

    if task.get("blind", False):
        trace["enabled"] = False
        trace["disabled_reason"] = "blind"
        trace["limitations"].append("blind run: agent disabled")
        _finalize_trace(trace, [], stop_reason="blind", status="skipped")
        path = _write_trace(run, trace)
        return {
            "status": "skipped",
            "reason": "blind run: agent disabled",
            "agent_trace": str(path),
        }

    ranking = load_artifact(run, "ranking.json", {})
    candidates = ranking.get("candidates", []) if isinstance(ranking, dict) else []
    if not candidates:
        trace["limitations"].append("ranking.json has no candidates")
        _finalize_trace(trace, [], stop_reason="no candidates", status="skipped")
        path = _write_trace(run, trace)
        return {"status": "skipped", "reason": "no candidates", "agent_trace": str(path)}

    summaries = load_artifact(run, "binary_summaries.json", {})
    surfaces = load_artifact(run, "attack_surface.json", {"surfaces": []})
    store = EvidenceStore(run)
    decisions = DecisionStore(run)
    safety_path = config.get("safety", {}).get("config") if isinstance(config, dict) else None
    policy = PolicyEngine.from_yaml(safety_path) if safety_path else PolicyEngine.from_yaml()
    manager = prompts or PromptManager()

    max_candidates = int(options.get("max_candidates", 10))
    model_cfg = options.get("model", {}) or {}
    model_mode = model_cfg.get("enabled", "auto")
    model_enabled = not isinstance(runtime_obj, OfflineRuleRuntime) and (
        model_mode is True or model_mode == "auto"
    )
    budget = Budget(
        max_total_tokens=int(model_cfg.get("max_tokens", 4000)),
        max_tokens_per_stage=int(model_cfg.get("max_tokens", 4000)),
        max_model_calls_per_stage=int(model_cfg.get("max_calls", 8)),
    )
    budget.begin_stage()

    display = options.get("progress")
    if not isinstance(display, dict):
        display = {}
    every_steps = max(1, int(display.get("every_steps", 10)))
    show_tokens = bool(display.get("show_tokens", True))
    show_model = bool(display.get("show_model", False))

    states: list[CandidateState] = []
    for candidate in candidates[:max_candidates]:
        if not isinstance(candidate, dict):
            continue
        state = CandidateState(
            candidate=candidate,
            initial_missing=[],
            missing=set(),
        )
        scene = build_context(run_dir, candidate, summaries, surfaces, options, task)
        state.missing = _derive_missing(candidate, scene.get("surface") or {})
        state.initial_missing = sorted(state.missing)
        state.last_signature = _signature(candidate)
        states.append(state)

    # Resume/idempotency: replay completed steps from a previous attempt so
    # evidence is not duplicated and the same action is not retried.
    replayed: list[dict[str, Any]] = []
    candidate_steps: dict[str, int] = {}
    trace_path = run / "artifacts" / "agent_trace.json"
    if trace_path.is_file():
        try:
            previous = load_json(trace_path)
        except Exception:  # noqa: BLE001 - corrupt trace restarts the stage
            previous = {}
        if isinstance(previous, dict) and previous.get("enabled") and previous.get("steps"):
            replayed = [entry for entry in previous.get("steps", []) if isinstance(entry, dict)]
            trace["steps"] = list(replayed)
            trace["started_at"] = previous.get("started_at", trace["started_at"])
            trace["limitations"] = list(previous.get("limitations", []))
            previous_model = previous.get("model", {})
            if isinstance(previous_model, dict):
                trace["model"].update(previous_model)
            previous_budget = previous.get("budget", {})
            if isinstance(previous_budget, dict):
                used_calls = int(previous_budget.get("used_model_calls", 0))
                used_tokens = int(previous_budget.get("used_model_tokens", 0))
                trace["budget"]["used_model_calls"] = used_calls
                trace["budget"]["used_model_tokens"] = used_tokens
                budget.total_calls = used_calls
                budget.stage_calls_used = used_calls
                budget.total_tokens_used = used_tokens
                budget.stage_tokens_used = used_tokens
            for entry in replayed:
                cid = str(entry.get("candidate_id", ""))
                candidate_steps[cid] = candidate_steps.get(cid, 0) + 1
                state = next(
                    (item for item in states if str(item.candidate.get("candidate_id", "")) == cid),
                    None,
                )
                if state is None:
                    continue
                action = str(entry.get("selected_action", ""))
                if action:
                    state.tried.add(action)
                if entry.get("status") in {"ok", "degraded"}:
                    facts = state.candidate.setdefault("agent_facts", [])
                    for fact in entry.get("produced_facts", []):
                        fact = str(fact)
                        state.missing.discard(fact)
                        if fact not in facts:
                            facts.append(fact)
                    evidence_ids = [str(ev) for ev in entry.get("evidence_ids", [])]
                    candidate_evidence = state.candidate.setdefault("evidence", [])
                    for evidence_id in evidence_ids:
                        if evidence_id not in candidate_evidence:
                            candidate_evidence.append(evidence_id)
                        if evidence_id not in state.evidence_added:
                            state.evidence_added.append(evidence_id)

    max_steps = int(options.get("max_steps", 20))
    max_steps_per_candidate = int(options.get("max_steps_per_candidate", 4))
    max_tool_calls = int(options.get("max_tool_calls", 40))
    max_seconds = float(options.get("max_seconds", 120))
    no_progress_limit = int(options.get("no_progress_limit", 2))
    max_action_failures = int(options.get("max_action_failures", 3))
    deadline = time.monotonic() + max_seconds
    step = len(replayed)
    tool_calls = len(replayed)
    evidence_total = sum(
        len(entry.get("evidence_ids", []))
        for entry in replayed
        if isinstance(entry, dict)
    )
    trace["budget"].update(
        {
            "used_candidates": len(states),
            "used_steps": step,
            "used_tool_calls": tool_calls,
        }
    )
    stop_reason = "no work"
    model_info = trace["model"]

    try:
        while step < max_steps:
            if time.monotonic() >= deadline:
                stop_reason = "time budget"
                break
            if tool_calls >= max_tool_calls:
                stop_reason = "tool-call budget"
                break
            available = [
                item
                for item in states
                if item.missing
                and not item.stalled
                and not item.skipped
                and candidate_steps.get(str(item.candidate.get("candidate_id", "")), 0)
                < max_steps_per_candidate
            ]
            # Round-robin keeps one candidate from consuming the whole budget;
            # within each round, spend effort on the highest-risk candidate.
            state = min(
                available,
                key=lambda item: (
                    candidate_steps.get(str(item.candidate.get("candidate_id", "")), 0),
                    -float(item.candidate.get("risk_score", 0) or 0),
                ),
                default=None,
            )
            if state is None:
                stop_reason = "no work"
                break

            candidate = state.candidate
            cid = str(candidate.get("candidate_id", ""))
            scene = build_context(run_dir, candidate, summaries, surfaces, options, task)
            try:
                rootfs = scene.get("rootfs")
                binary = (scene.get("binary_summary") or {}).get("path")
                if rootfs:
                    policy.check_path(rootfs)
                if rootfs and binary:
                    policy.check_path(Path(str(rootfs)) / str(binary))
            except Exception as exc:  # noqa: BLE001 - policy rejection degrades the candidate
                state.skipped = True
                state.status = "skipped"
                trace["limitations"].append(f"{cid}: policy rejected action path: {exc}")
                continue
            actions = eligible_actions(candidate, scene, state.missing, state.tried)
            actions = rank_actions(actions, state.missing)[:4]
            if not actions:
                state.skipped = True
                state.status = "degraded"
                trace["limitations"].append(
                    f"{cid}: no eligible action for missing facts {sorted(state.missing)}"
                )
                continue

            chosen = actions[0]
            selector = "rule"
            model_choice = None
            confidence = 1.0
            reason = chosen.description
            if len(actions) > 1 and model_enabled:
                choice, fallback = choose_with_model(
                    runtime_obj,
                    budget,
                    candidate=candidate,
                    missing=state.missing,
                    actions=actions,
                    policy=policy,
                    allow_public=bool(model_cfg.get("allow_public", False)),
                    prompts=manager,
                )
                model_info["calls"] = budget.stage_calls_used
                model_info["tokens"] = budget.stage_tokens_used
                if choice:
                    chosen = next(spec for spec in actions if spec.action_id == choice["action_id"])
                    selector = "model"
                    model_info["used"] = True
                    confidence = float(choice["confidence"])
                    reason = str(choice["reason"])[:200]
                    model_choice = {
                        "action_id": chosen.action_id,
                        "confidence": confidence,
                        "reason": reason,
                    }
                    if show_model:
                        report_note(
                            f"model chose {chosen.action_id} "
                            f"(confidence {confidence:.2f}): {reason}"
                        )
                else:
                    model_info["fallback_count"] += 1
                    model_info["last_fallback_reason"] = fallback
                    if show_model:
                        report_note(f"model fallback: {fallback}")

            before = {key: deepcopy(candidate.get(key)) for key in _FORBIDDEN_FIELDS}
            signature_before = _signature(candidate)
            started = time.monotonic()
            try:
                outcome = ACTION_HANDLERS[chosen.action_id](
                    candidate,
                    context=scene,
                    store=store,
                    run_id=run.name,
                )
            except Exception as exc:  # noqa: BLE001 - one action must not abort the run
                outcome = {
                    "status": "failed",
                    "produced_facts": [],
                    "evidence_ids": [],
                    "limitations": [f"{type(exc).__name__}: {exc}"],
                }
            outcome = _normalize_action_outcome(outcome, chosen)
            duration_ms = int((time.monotonic() - started) * 1000)
            violations = _restore_forbidden(candidate, before)
            if violations:
                outcome = {
                    "status": "failed",
                    "produced_facts": [],
                    "evidence_ids": [],
                    "limitations": [f"action attempted to change protected fields: {violations}"],
                }

            produced = {str(item) for item in outcome.get("produced_facts", [])}
            evidence_ids = [str(item) for item in outcome.get("evidence_ids", [])]
            limitations = [str(item) for item in outcome.get("limitations", [])]
            state.missing -= produced
            state.tried.add(chosen.action_id)
            state.evidence_added.extend(evidence_ids)
            if outcome.get("status") == "failed":
                state.failed_actions += 1
            else:
                state.failed_actions = 0

            signature_after = _signature(candidate)
            progressed = signature_after != signature_before and bool(produced or evidence_ids)
            if progressed:
                state.no_progress = 0
                state.last_signature = signature_after
            else:
                state.no_progress += 1
            if state.no_progress >= no_progress_limit:
                state.stalled = True
                state.status = "stalled"
            if state.failed_actions >= max_action_failures:
                state.stalled = True
                state.status = "failed"

            decisions.add(
                stage="AGENT_LOOP",
                observation=f"agent action for {cid}",
                options=[spec.action_id for spec in actions],
                selected=chosen.action_id,
                reason=reason,
                confidence=max(0.0, min(1.0, confidence)),
                next_stage="AGENT_LOOP",
                actor=selector,
                inputs=[cid, *sorted(state.missing)],
            )
            trace["steps"].append(
                {
                    "step": step + 1,
                    "candidate_id": cid,
                    "missing_facts": sorted(state.missing | produced),
                    "eligible_actions": [spec.action_id for spec in actions],
                    "selected_action": chosen.action_id,
                    "selector": selector,
                    "model_choice": model_choice,
                    "status": str(outcome.get("status", "failed")),
                    "produced_facts": sorted(produced),
                    "evidence_ids": evidence_ids,
                    "signature_before": signature_before,
                    "signature_after": signature_after,
                    "duration_ms": duration_ms,
                    "limitation": "; ".join(limitations) if limitations else None,
                }
            )
            trace["limitations"].extend(limitations)
            if outcome.get("status") == "skipped":
                state.skipped = True
                state.status = "skipped"

            step += 1
            tool_calls += 1
            evidence_total += len(evidence_ids)
            candidate_steps[cid] = candidate_steps.get(cid, 0) + 1
            new_steps = step - len(replayed)
            if new_steps == 1 or new_steps % every_steps == 0:
                resolved = sum(
                    1
                    for item in states
                    if not item.missing and not item.skipped and not item.stalled
                )
                skipped = sum(1 for item in states if item.skipped)
                parts = [
                    f"agent step {step}/{max_steps}",
                    cid,
                    chosen.action_id,
                    f"selector={selector}",
                ]
                if show_tokens:
                    parts.extend(
                        [
                            f"tok {budget.stage_tokens_used}/{budget.max_total_tokens}",
                            f"calls {budget.stage_calls_used}/{budget.max_model_calls_per_stage}",
                        ]
                    )
                parts.extend(
                    [
                        f"ev {evidence_total}",
                        f"missing {len(state.missing)}",
                        f"resolved {resolved}/{len(states)}",
                        f"skipped {skipped}",
                    ]
                )
                report_detail(" · ".join(parts))
            elapsed = time.monotonic() - (deadline - max_seconds)
            trace["budget"].update(
                {
                    "used_candidates": len(states),
                    "used_steps": step,
                    "used_tool_calls": tool_calls,
                    "used_seconds": round(elapsed, 3),
                    "used_model_calls": budget.stage_calls_used,
                    "used_model_tokens": budget.stage_tokens_used,
                }
            )
            model_info["calls"] = budget.stage_calls_used
            model_info["tokens"] = budget.stage_tokens_used
            _finalize_trace(trace, states, stop_reason="running", status="partial")
            _write_trace(run, trace)
    except Exception as exc:  # noqa: BLE001 - stage degrades instead of aborting the run
        trace["limitations"].append(f"agent loop failed: {type(exc).__name__}: {exc}")
        _finalize_trace(trace, states, stop_reason="internal error", status="failed")
        path = _write_trace(run, trace)
        return {"status": "failed", "reason": str(exc), "agent_trace": str(path)}

    if step >= max_steps and stop_reason == "no work":
        stop_reason = "step budget"
    elif stop_reason == "no work" and states and all(
        state.skipped or state.stalled or not state.missing for state in states
    ):
        stop_reason = "action catalog exhausted"

    for state in states:
        if state.missing and not state.skipped and not state.stalled:
            state.status = "degraded"

    enriched = {str(state.candidate.get("candidate_id", "")): state.candidate for state in states}
    try:
        _update_ranking(run, candidates, enriched)
    except Exception as exc:  # noqa: BLE001 - a write failure is a stage failure
        trace["limitations"].append(f"ranking update failed: {type(exc).__name__}: {exc}")
        _finalize_trace(trace, states, stop_reason=stop_reason, status="failed")
        path = _write_trace(run, trace)
        return {"status": "failed", "reason": str(exc), "agent_trace": str(path)}

    _finalize_trace(trace, states, stop_reason=stop_reason)
    summary = trace["summary"]
    parts = [
        "done",
        f"steps {summary['steps']}",
        stop_reason,
        f"ev {summary['evidence_added']}",
        f"resolved {summary['resolved_candidates']}/{len(states)}",
        f"skipped {summary['skipped_candidates']}",
    ]
    if show_tokens:
        parts.append(f"model {model_info['calls']} calls / {model_info['tokens']} tok")
    parts.append(f"fallback {model_info['fallback_count']}")
    report_detail(" · ".join(parts))
    path = _write_trace(run, trace)
    return {
        "status": trace["status"],
        "agent_trace": str(path),
        "steps": len(trace["steps"]),
        "summary": trace["summary"],
    }
