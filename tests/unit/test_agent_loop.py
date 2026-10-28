"""Bounded agent loop: budgets, invariants, fallback, and trace contract."""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

import pytest

from fsa.orchestrator import agent_loop
from fsa.orchestrator.agent_options import resolve_agent_options
from fsa.schemas.loader import validate
from fsa.utils.jsonio import load_json, save_json
from fsa.utils.progress import StageProgress, use_progress


def _candidate(**overrides: Any) -> dict[str, Any]:
    candidate: dict[str, Any] = {
        "candidate_id": "cand-1",
        "surface_id": "unmapped-surface",
        "binary_id": "bin-1",
        "entry": {},
        "source": {"string": "QUERY_STRING", "name": "http_query", "type": "http_query"},
        "transform": [],
        "validation": [],
        "authorization": {"required": False, "hint": "preauth"},
        "sink": {"function": "system", "type": "command_execution"},
        "call_chain": [],
        "user_control": "partial",
        "vuln_class_hypothesis": "command_injection",
        "risk_score": 10,
        "risk_level": "MEDIUM",
        "evidence": [],
        "counterevidence": ["call-chain-not-proven"],
        "conclusion_category": "unknown",
        "decisive_missing_fact": "source-to-sink data-flow",
        "status": "analyzing",
    }
    candidate.update(overrides)
    return candidate


def _run(tmp_path: Path, *, blind: bool = False, ranking: bool = True) -> Path:
    run = tmp_path / "runs" / "run-1"
    run.mkdir(parents=True)
    save_json(
        run / "state" / "task_card.json",
        {
            "task_id": "run-1",
            "raw_input_refs": [],
            "objective": "firmware_vuln_hunt",
            "firmware_path": "pending_human_input",
            "depth": "standard",
            "blind": blind,
            "constraints": [],
            "success_criteria": [],
            "authorization": {
                "holder": "owner",
                "scope": "analysis-only",
                "allow_emulation": False,
                "network_isolation": True,
            },
        },
    )
    save_json(run / "artifacts" / "rootfs.json", {})
    save_json(
        run / "artifacts" / "binary_summaries.json",
        {
            "rootfs": "",
            "summaries": [
                {
                    "binary_id": "bin-1",
                    "path": "bin/httpd",
                    "architecture": "x86_64",
                    "imports": ["getenv", "system"],
                    "strings_summary": {"sample": ["QUERY_STRING"]},
                }
            ],
            "startup": {"grouped": {}},
        },
    )
    save_json(run / "artifacts" / "attack_surface.json", {"surfaces": []})
    if ranking:
        payload = {"run_id": "run-1", "candidates": [_candidate()]}
        save_json(run / "artifacts" / "ranking.json", payload)
        save_json(run / "ranking.json", payload)
    return run


def _options(**overrides: Any) -> dict[str, Any]:
    payload = {"enabled": True}
    payload.update(overrides)
    return resolve_agent_options({}, payload)


def test_disabled_loop_skips(tmp_path: Path) -> None:
    run = _run(tmp_path)
    result = agent_loop.run_agent_loop(
        run, options=resolve_agent_options({}), config={"runtime": {"default": "mock"}}
    )
    assert result["status"] == "skipped"
    trace = load_json(run / "artifacts" / "agent_trace.json")
    validate(trace, schema_name="agent_trace")
    assert trace["disabled_reason"] == "not requested"


def test_blind_run_hard_disables(tmp_path: Path) -> None:
    run = _run(tmp_path, blind=True)
    result = agent_loop.run_agent_loop(
        run,
        options=_options(),
        config={"runtime": {"default": "mock"}},
    )
    assert result["status"] == "skipped"
    trace = load_json(run / "artifacts" / "agent_trace.json")
    assert trace["disabled_reason"] == "blind"
    assert trace["enabled"] is False


def test_missing_ranking_skips(tmp_path: Path) -> None:
    run = _run(tmp_path, ranking=False)
    result = agent_loop.run_agent_loop(
        run, options=_options(), config={"runtime": {"default": "mock"}}
    )
    assert result["status"] == "skipped"
    trace = load_json(run / "artifacts" / "agent_trace.json")
    assert trace["summary"]["stop_reason"] == "no candidates"


def test_static_actions_run_and_trace_validates(tmp_path: Path) -> None:
    run = _run(tmp_path)
    result = agent_loop.run_agent_loop(
        run, options=_options(), config={"runtime": {"default": "mock"}}
    )
    assert result["status"] in {"ok", "degraded"}
    trace = load_json(run / "artifacts" / "agent_trace.json")
    validate(trace, schema_name="agent_trace")
    assert trace["steps"]
    assert "cross_check_imports_strings" in trace["summary"]["actions"]
    assert trace["candidates"][0]["actions_attempted"]
    assert (run / "artifacts" / "ranking.json").is_file()
    assert (run / "artifacts" / "agent_execution.html").is_file()


def test_visualization_is_throttled_but_final_html_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = _run(tmp_path)
    calls: list[Path] = []

    def fake_visualization(run_dir: Path, trace: dict[str, Any]) -> Path:
        target = Path(run_dir) / "artifacts" / "agent_execution.html"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("visualization", encoding="utf-8")
        calls.append(target)
        return target

    monkeypatch.setattr(agent_loop, "write_agent_visualization", fake_visualization)
    result = agent_loop.run_agent_loop(
        run, options=_options(), config={"runtime": {"default": "mock"}}
    )

    trace = load_json(run / "artifacts" / "agent_trace.json")
    assert result["steps"] == len(trace["steps"])
    assert calls
    # First step + terminal write; the per-step loop never renders every step.
    assert len(calls) <= 2 + trace["summary"]["steps"] // 10
    assert len(calls) < trace["summary"]["steps"] + 2
    assert (run / "artifacts" / "agent_execution.html").is_file()


def test_progress_detail_includes_tokens_candidates_and_evidence(tmp_path: Path) -> None:
    run = _run(tmp_path)
    stream = io.StringIO()
    progress = StageProgress(enabled=True, stream=stream)
    progress.stage_start("AGENT_LOOP", 5, 10)
    with use_progress(progress):
        agent_loop.run_agent_loop(
            run, options=_options(), config={"runtime": {"default": "mock"}}
        )
    progress.stage_end("AGENT_LOOP", "ok", 1.0)

    text = stream.getvalue()
    assert "agent step " in text
    assert "selector=" in text
    assert "tok " in text
    assert "calls " in text
    assert "ev " in text
    assert "resolved " in text
    assert "skipped " in text


def test_progress_can_hide_token_counters(tmp_path: Path) -> None:
    run = _run(tmp_path)
    stream = io.StringIO()
    progress = StageProgress(enabled=True, stream=stream)
    progress.stage_start("AGENT_LOOP", 5, 10)
    with use_progress(progress):
        agent_loop.run_agent_loop(
            run,
            options=_options(progress={"show_tokens": False}),
            config={"runtime": {"default": "mock"}},
        )
    progress.stage_end("AGENT_LOOP", "ok", 1.0)

    assert "tok " not in stream.getvalue()


def test_resume_does_not_duplicate_steps_or_evidence(tmp_path: Path) -> None:
    run = _run(tmp_path)
    options = _options()
    config = {"runtime": {"default": "mock"}}
    agent_loop.run_agent_loop(run, options=options, config=config)
    first = load_json(run / "artifacts" / "agent_trace.json")
    first_evidence = len(list((run / "evidence").glob("*.json")))

    agent_loop.run_agent_loop(run, options=options, config=config)
    second = load_json(run / "artifacts" / "agent_trace.json")
    assert len(second["steps"]) == len(first["steps"])
    assert len(list((run / "evidence").glob("*.json"))) == first_evidence


def test_resume_replays_interrupted_trace_with_skipped_status(tmp_path: Path) -> None:
    run = _run(tmp_path)
    options = _options()
    config = {"runtime": {"default": "mock"}}
    agent_loop.run_agent_loop(run, options=options, config=config)
    trace_path = run / "artifacts" / "agent_trace.json"
    interrupted = load_json(trace_path)
    interrupted["status"] = "skipped"  # incremental writes keep the skeleton status
    save_json(trace_path, interrupted)
    first_evidence = len(list((run / "evidence").glob("*.json")))

    agent_loop.run_agent_loop(run, options=options, config=config)
    resumed = load_json(trace_path)
    assert len(resumed["steps"]) == len(interrupted["steps"])
    assert len(list((run / "evidence").glob("*.json"))) == first_evidence


def test_forbidden_field_mutation_is_restored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = _run(tmp_path)

    class _FakeAction:
        action_id = "bad_action"
        description = "mutate conclusion"
        cost = 0.1
        produces = ("contradiction_checked",)

    def fake_eligible(candidate, context, missing, attempted):
        return [] if "bad_action" in attempted else [_FakeAction()]

    def fake_handler(candidate, *, context, store, run_id):
        candidate["conclusion_category"] = "confirmed-issue"
        return {
            "status": "ok",
            "produced_facts": ["contradiction_checked"],
            "evidence_ids": [],
            "limitations": [],
        }

    monkeypatch.setattr(agent_loop, "eligible_actions", fake_eligible)
    monkeypatch.setattr(agent_loop, "rank_actions", lambda actions, missing: actions)
    monkeypatch.setitem(agent_loop.ACTION_HANDLERS, "bad_action", fake_handler)

    result = agent_loop.run_agent_loop(
        run,
        options=_options(max_steps=1),
        config={"runtime": {"default": "mock"}},
    )
    trace = load_json(run / "artifacts" / "agent_trace.json")
    assert trace["steps"][0]["status"] == "failed"
    assert trace["steps"][0]["limitation"]
    ranking = load_json(run / "artifacts" / "ranking.json")
    assert ranking["candidates"][0]["conclusion_category"] == "unknown"
    assert result["status"] == "degraded"


def test_no_progress_stalls_candidate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run = _run(tmp_path)

    class _FakeAction:
        def __init__(self, action_id: str) -> None:
            self.action_id = action_id
            self.description = "no progress"
            self.cost = 0.1
            self.produces = ("contradiction_checked",)

    def fake_eligible(candidate, context, missing, attempted):
        return [
            action
            for action in (_FakeAction("a1"), _FakeAction("a2"))
            if action.action_id not in attempted
        ]

    def fake_handler(candidate, *, context, store, run_id):
        return {
            "status": "ok",
            "produced_facts": [],
            "evidence_ids": [],
            "limitations": [],
        }

    monkeypatch.setattr(agent_loop, "eligible_actions", fake_eligible)
    monkeypatch.setattr(agent_loop, "rank_actions", lambda actions, missing: actions)
    monkeypatch.setitem(agent_loop.ACTION_HANDLERS, "a1", fake_handler)
    monkeypatch.setitem(agent_loop.ACTION_HANDLERS, "a2", fake_handler)

    agent_loop.run_agent_loop(
        run,
        options=_options(no_progress_limit=2, max_steps=5),
        config={"runtime": {"default": "mock"}},
    )
    trace = load_json(run / "artifacts" / "agent_trace.json")
    assert trace["summary"]["stalled_candidates"] == 1
    assert trace["candidates"][0]["status"] == "stalled"


def test_model_fallback_is_recorded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run = _run(tmp_path)

    class _FakeRuntime:
        base_url = "https://api.example.com/v1"
        model = "fake"

        def ask_model(self, messages, budget):  # pragma: no cover - must not be called
            raise AssertionError("public endpoint should be rejected before the call")

    class _FakeAction:
        def __init__(self, action_id: str) -> None:
            self.action_id = action_id
            self.description = "collect"
            self.cost = 0.1
            self.produces = ("contradiction_checked",)

    def fake_eligible(candidate, context, missing, attempted):
        return [
            action
            for action in (_FakeAction("a1"), _FakeAction("a2"))
            if action.action_id not in attempted
        ]

    def fake_handler(candidate, *, context, store, run_id):
        return {
            "status": "ok",
            "produced_facts": ["contradiction_checked"],
            "evidence_ids": [],
            "limitations": [],
        }

    monkeypatch.setattr(agent_loop, "eligible_actions", fake_eligible)
    monkeypatch.setattr(agent_loop, "rank_actions", lambda actions, missing: actions)
    monkeypatch.setitem(agent_loop.ACTION_HANDLERS, "a1", fake_handler)
    monkeypatch.setitem(agent_loop.ACTION_HANDLERS, "a2", fake_handler)

    agent_loop.run_agent_loop(
        run,
        options=_options(model={"enabled": True, "allow_public": False}),
        config={"runtime": {"default": "fake"}},
        runtime=_FakeRuntime(),
    )
    trace = load_json(run / "artifacts" / "agent_trace.json")
    assert trace["model"]["fallback_count"] == 1
    assert "public" in (trace["model"]["last_fallback_reason"] or "")
