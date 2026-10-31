"""Interruption snapshot reports must summarize only existing artifacts."""

from __future__ import annotations

from pathlib import Path

from fsa.utils.jsonio import load_json, save_json
from tools.report.partial import execute_partial_report


def _write(path: Path, payload: object) -> None:
    save_json(path, payload)


def _run(tmp_path: Path) -> Path:
    run = tmp_path / "runs" / "run-1"
    run.mkdir(parents=True)
    _write(
        run / "state" / "run_state.json",
        {
            "run_id": "run-1",
            "status": "running",
            "current_stage": "AGENT_LOOP",
            "completed_stages": ["BASELINE", "UNPACK", "RANK"],
            "failed_stages": [],
            "started_at": "2026-10-26T10:00:00Z",
            "updated_at": "2026-10-26T10:05:00Z",
            "plan": {"stages": ["INIT", "RANK", "AGENT_LOOP", "VERIFY_TOP_K", "REPORT", "DONE"]},
        },
    )
    _write(
        run / "state" / "task_card.json",
        {"task_id": "run-1", "firmware_path": "/tmp/fw.bin"},
    )
    _write(
        run / "artifacts" / "rootfs.json",
        {"status": "ok", "unpack_method": "squashfs", "extraction_confidence": 1.0},
    )
    _write(
        run / "artifacts" / "binary_summaries.json",
        {"summaries": [{"binary_id": "bin-1"}]},
    )
    _write(
        run / "artifacts" / "attack_surface.json",
        {"surfaces": [{"surface_id": "surf-1"}]},
    )
    _write(
        run / "artifacts" / "ranking.json",
        {
            "run_id": "run-1",
            "candidates": [
                {
                    "candidate_id": "cand-1",
                    "binary_id": "bin-1",
                    "vuln_class_hypothesis": "command_injection",
                    "risk_score": 14,
                    "risk_level": "MEDIUM",
                    "source": {"type": "http_query", "string": "$(reboot)"},
                    "sink": {"function": "system"},
                    "call_chain": [],
                    "conclusion_category": "unknown",
                }
            ],
        },
    )
    _write(
        run / "artifacts" / "agent_trace.json",
        {
            "run_id": "run-1",
            "enabled": True,
            "tier": "standard",
            "status": "skipped",
            "steps": [
                {
                    "step": 1,
                    "candidate_id": "cand-1",
                    "selected_action": "cross_check_imports_strings",
                    "status": "ok",
                }
            ],
            "model": {
                "provider": "openai_compatible",
                "model": "deepseek-flash",
                "calls": 1,
                "tokens": 100,
                "fallback_count": 0,
            },
            "summary": {"actions": {"cross_check_imports_strings": 1}},
            "limitations": [],
        },
    )
    return run


def test_partial_report_summarizes_existing_artifacts(tmp_path: Path) -> None:
    run = _run(tmp_path)
    result = execute_partial_report(run, limit=5)
    assert result["status"] == "ok"
    assert result["candidate_count"] == 1
    assert result["verdict_count"] == 0
    assert result["agent_steps"] == 1
    report = Path(result["report"]).read_text(encoding="utf-8")
    assert "中断快照报告" in report
    assert "AGENT_LOOP" in report
    assert "VERIFY_TOP_K 未完成" in report
    assert "cand-1" in report
    assert "fsa resume run-1" in report
    assert "快照只汇总已有产物" in report
    assert "$(reboot)" not in report
    assert not (run / "report.md").exists()
    assert not (run / "final_verdict.json").exists()


def test_partial_report_writes_custom_output(tmp_path: Path) -> None:
    run = _run(tmp_path)
    target = tmp_path / "snapshot.md"
    result = execute_partial_report(run, output_path=target)
    assert result["status"] == "ok"
    assert Path(result["report"]) == target.resolve()
    assert target.is_file()


def test_partial_report_notes_final_run(tmp_path: Path) -> None:
    run = _run(tmp_path)
    state = load_json(run / "state" / "run_state.json")
    state["status"] = "done"
    save_json(run / "state" / "run_state.json", state)
    (run / "report.md").write_text("# final\n", encoding="utf-8")
    result = execute_partial_report(run)
    assert result["final"] is True
    report = Path(result["report"]).read_text(encoding="utf-8")
    assert "status：done" in report
