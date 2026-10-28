"""Grounding summary: provenance, traceability, coverage, and capability gaps."""

from __future__ import annotations

from pathlib import Path

from fsa.utils.jsonio import save_json
from tools.report.grounding import build_grounding


def _run(tmp_path: Path) -> Path:
    run = tmp_path / "runs" / "run-ground"
    rootfs = tmp_path / "rootfs"
    (rootfs / "sbin").mkdir(parents=True)
    (rootfs / "sbin" / "httpd").write_bytes(b"ELF")
    save_json(run / "evidence" / "ev-1.json", {"observation": "present"})
    save_json(
        run / "state" / "run_state.json",
        {"run_id": "run-ground", "artifacts": {"fallback": "pyelftools", "reason": "no backend"}},
    )
    return run


def test_grounding_counts_traceability_chain_and_gaps(tmp_path: Path) -> None:
    run = _run(tmp_path)
    rootfs_dir = tmp_path / "rootfs"
    rootfs = {
        "input_type": "firmware",
        "rootfs_path": str(rootfs_dir),
        "unpack_method": "squashfs",
        "rootfs_score": 8,
        "extraction_confidence": 1.0,
        "status": "ok",
        "rootfs_candidates": 1,
        "rootfs_duplicates_suppressed": 1,
        "unpack_degraded": True,
    }
    binaries = {
        "summaries": [
            {"binary_id": "bin-1", "path": "sbin/httpd", "architecture": "mipsel"},
            {"binary_id": "bin-2", "path": "sbin/missing", "architecture": "mipsel"},
        ]
    }
    ranking = {
        "candidates": [
            {
                "candidate_id": "cand-1",
                "binary_id": "bin-1",
                "call_chain": [{"from": "a"}, {"from": "b"}],
                "evidence": ["ev-1", "ev-missing"],
            },
            {"candidate_id": "cand-2", "binary_id": "bin-2", "call_chain": []},
            {"candidate_id": "cand-3", "binary_id": "bin-none", "call_chain": []},
        ]
    }
    verdict = {
        "verdicts": [
            {"candidate_id": "cand-1", "action": "DOWNGRADE"},
            {"candidate_id": "cand-orphan", "action": "REJECT"},
        ]
    }
    external = {
        "per_tool": {
            "satc": {"status": "skipped", "limitation": "image missing"},
            "firmrec": {"status": "skipped", "limitation": "blind"},
        }
    }
    agent_trace = {
        "enabled": True,
        "status": "degraded",
        "model": {"used": True, "provider": "openai_compatible", "model": "x", "calls": 3},
    }

    grounding = build_grounding(
        run,
        rootfs=rootfs,
        binaries=binaries,
        ranking=ranking,
        verdict=verdict,
        run_state={"artifacts": {"fallback": "pyelftools", "reason": "no backend"}},
        decompile={},
        external=external,
        agent_trace=agent_trace,
    )

    assert grounding["candidate_total"] == 3
    assert grounding["candidate_traceable"] == 1
    assert grounding["candidate_missing_binary"] == 2
    assert grounding["candidates_with_chain"] == 1
    assert grounding["candidates_without_chain"] == 2
    assert grounding["detected_architectures"] == ["mipsel"]
    assert grounding["chain_unsupported_architectures"] == ["mipsel"]
    assert grounding["reviewed_total"] == 2
    assert grounding["orphan_verdicts"] == ["cand-orphan"]
    assert grounding["evidence_referenced"] == 2
    assert grounding["evidence_resolved"] == 1
    assert grounding["decompile_status"] == "fallback"
    assert grounding["decompile_reason"] == "no backend"
    assert grounding["model_used"] is True
    assert grounding["external_tools"][0]["name"] == "firmrec"
    assert grounding["rootfs_duplicates_suppressed"] == 1
