"""Declarative action catalog for the bounded AGENT_LOOP stage.

The catalog is deliberately small and closed. The model may only choose an
``action_id`` from the rule-filtered list; it never supplies tool names, paths,
shell commands, or parameters.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tools.audit.audit_constants import CHAIN_SINKS

Precondition = Callable[[dict[str, Any], dict[str, Any]], bool]


@dataclass(frozen=True)
class ActionSpec:
    """One legal next step for a candidate."""

    action_id: str
    tier: str  # standard | dynamic | external
    produces: tuple[str, ...]
    weight: int
    cost: float
    description: str
    precondition: Precondition


def _rootfs(context: dict[str, Any]) -> Path | None:
    value = context.get("rootfs")
    if value in (None, ""):
        return None
    path = Path(str(value))
    return path if path.is_dir() else None


def _summary(candidate: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    value = context.get("binary_summary")
    return value if isinstance(value, dict) else {}


def _can_recover_chain(candidate: dict[str, Any], context: dict[str, Any]) -> bool:
    rootfs = _rootfs(context)
    summary = _summary(candidate, context)
    sink = str((candidate.get("sink") or {}).get("function", ""))
    binary = str(summary.get("path", ""))
    arch = str(context.get("arch", "")).lower()
    if arch not in {"arm", "arm32"}:
        return False
    if rootfs is None or not binary or sink not in CHAIN_SINKS:
        return False
    elf = rootfs / binary
    try:
        if not elf.is_file():
            return False
        limit = int(context.get("max_binary_size_mb", 64)) * 1024 * 1024
        return elf.stat().st_size <= limit
    except OSError:
        return False


def _can_cross_check(candidate: dict[str, Any], context: dict[str, Any]) -> bool:
    summary = _summary(candidate, context)
    source = candidate.get("source") or {}
    sink = candidate.get("sink") or {}
    has_source = bool(source.get("api") or source.get("name") or source.get("string"))
    has_sink = bool(sink.get("function"))
    return (
        bool(summary.get("imports") or summary.get("strings_summary")) and has_source and has_sink
    )


def _can_check_startup(candidate: dict[str, Any], context: dict[str, Any]) -> bool:
    if _rootfs(context) is None:
        return False
    entry = candidate.get("entry") or {}
    if entry.get("handler") or entry.get("route"):
        return True
    surface = context.get("surface") or {}
    return bool(surface.get("handler"))


def _can_check_evidence(candidate: dict[str, Any], context: dict[str, Any]) -> bool:
    return bool(candidate.get("evidence") or candidate.get("counterevidence"))


def _can_verify_auth(candidate: dict[str, Any], context: dict[str, Any]) -> bool:
    entry = candidate.get("entry") or {}
    surface = context.get("surface") or {}
    return bool(
        entry.get("route") or entry.get("handler") or surface.get("route") or surface.get("handler")
    )


ACTION_CATALOG: tuple[ActionSpec, ...] = (
    ActionSpec(
        action_id="recover_call_chain",
        tier="standard",
        produces=("call_chain_reachable",),
        weight=5,
        cost=1.0,
        description="Recover an ARM32 caller of the sink with capstone.",
        precondition=_can_recover_chain,
    ),
    ActionSpec(
        action_id="cross_check_imports_strings",
        tier="standard",
        produces=("source_sink_cross_checked",),
        weight=3,
        cost=0.5,
        description="Confirm source/sink presence in imports and strings.",
        precondition=_can_cross_check,
    ),
    ActionSpec(
        action_id="check_handler_startup",
        tier="standard",
        produces=("handler_startup_checked", "handler_started"),
        weight=4,
        cost=0.7,
        description="Check whether the candidate handler starts from init scripts.",
        precondition=_can_check_startup,
    ),
    ActionSpec(
        action_id="cross_check_evidence_store",
        tier="standard",
        produces=("contradiction_checked",),
        weight=2,
        cost=0.2,
        description="Resolve evidence references and look for contradictions.",
        precondition=_can_check_evidence,
    ),
    ActionSpec(
        action_id="verify_auth_hint",
        tier="standard",
        produces=("auth_known",),
        weight=3,
        cost=0.5,
        description="Resolve authorization.required with the auth matrix.",
        precondition=_can_verify_auth,
    ),
    ActionSpec(
        action_id="enrich_from_recovered_handlers",
        tier="standard",
        produces=("entry_mapped",),
        weight=2,
        cost=1.0,
        description="Map an unmapped handler to a real surface when exact.",
        precondition=lambda candidate, context: _rootfs(context) is not None,
    ),
    ActionSpec(
        action_id="qemu_load_check",
        tier="dynamic",
        produces=("dynamic_load_checked",),
        weight=1,
        cost=5.0,
        description="Harmless QEMU user-mode L1 load check.",
        precondition=lambda candidate, context: _rootfs(context) is not None,
    ),
    ActionSpec(
        action_id="klee_feasibility",
        tier="external",
        produces=("symex_feasibility_checked",),
        weight=1,
        cost=20.0,
        description="Conservative KLEE feasibility check (counterevidence only).",
        precondition=lambda candidate, context: bool(
            context.get("unified_candidates") and _summary(candidate, context)
        ),
    ),
)

_ORDER = {spec.action_id: index for index, spec in enumerate(ACTION_CATALOG)}


def action_spec(action_id: str) -> ActionSpec:
    """Return the catalog entry or raise ``KeyError``."""
    for spec in ACTION_CATALOG:
        if spec.action_id == action_id:
            return spec
    raise KeyError(f"unknown agent action: {action_id}")


def actions_for_tier(tier: str) -> list[ActionSpec]:
    """Return actions allowed by ``standard < dynamic < external``."""
    if tier == "external":
        allowed = {"standard", "dynamic", "external"}
    elif tier == "dynamic":
        allowed = {"standard", "dynamic"}
    else:
        allowed = {"standard"}
    return [spec for spec in ACTION_CATALOG if spec.tier in allowed]


def eligible_actions(
    candidate: dict[str, Any],
    context: dict[str, Any],
    missing: set[str],
    attempted: set[str],
) -> list[ActionSpec]:
    """Filter the closed catalog by tier, preconditions, and missing facts."""
    actions: list[ActionSpec] = []
    for spec in actions_for_tier(str(context.get("tier", "standard"))):
        if spec.action_id in attempted:
            continue
        if spec.produces and not set(spec.produces) & missing:
            continue
        try:
            if not spec.precondition(candidate, context):
                continue
        except Exception:  # noqa: BLE001 - a bad precondition degrades, never aborts
            continue
        actions.append(spec)
    return actions


def rank_actions(actions: list[ActionSpec], missing: set[str]) -> list[ActionSpec]:
    """Deterministic priority order used before (and without) the model."""

    def score(spec: ActionSpec) -> tuple[float, int]:
        overlap = len(set(spec.produces) & missing)
        return (-(spec.weight * overlap / max(spec.cost, 0.1)), _ORDER[spec.action_id])

    return sorted(actions, key=score)
