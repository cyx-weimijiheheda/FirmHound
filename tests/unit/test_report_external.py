"""Report rendering for external findings and FirmRec recurrence isolation."""

from __future__ import annotations

import json
from pathlib import Path

from tools.report.generate import _finding_count, _tool_statuses, execute_report


def _write(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def test_finding_count_accepts_int_and_list() -> None:
    assert _finding_count({"findings": 3}) == 3
    assert _finding_count({"findings": [{"a": 1}, {"b": 2}]}) == 2
    assert _finding_count({}) == 0
    assert _finding_count(None) == 0


def test_tool_statuses_prefers_per_tool() -> None:
    payload = {"per_tool": {"satc": {"status": "ok"}, "firmrec": {"status": "skipped"}}}
    assert _tool_statuses(payload) == "firmrec=skipped, satc=ok"


def test_tool_statuses_missing_payload_names_the_tools() -> None:
    """No external artifact at all must still say which tools did not run."""
    rendered = _tool_statuses({})
    for name in ("satc", "firmrec", "klee", "bond"):
        assert name in rendered
    assert "未运行" in rendered
    assert _tool_statuses(None) == rendered


def test_tool_statuses_skipped_includes_limitation() -> None:
    payload = {
        "status": "skipped",
        "per_tool": {},
        "limitation": "all selected external analyzers disabled in config",
    }
    rendered = _tool_statuses(payload)
    assert "klee" in rendered
    assert "disabled in config" in rendered


def test_tool_statuses_includes_per_tool_limitation() -> None:
    payload = {"per_tool": {"klee": {"status": "skipped", "limitation": "klee not installed"}}}
    assert _tool_statuses(payload) == "klee=skipped（klee not installed）"


def test_report_without_external_artifacts_names_tools_and_limits(tmp_path: Path) -> None:
    """Regression: section 18 used to collapse to a bare 未启用 line."""
    run = tmp_path / "runs" / "run-noext"
    _write(
        run / "state" / "task_card.json",
        {
            "task_id": "run-noext",
            "authorization": {"holder": "owner", "scope": "analysis-only"},
        },
    )
    _write(run / "artifacts" / "rootfs.json", {"status": "ok"})
    _write(run / "artifacts" / "binary_summaries.json", {"inventory": {}, "summaries": []})
    _write(run / "artifacts" / "attack_surface.json", {"surfaces": []})
    _write(run / "artifacts" / "ranking.json", {"candidates": []})
    _write(run / "artifacts" / "verdict.json", {"run_id": "run-noext", "verdicts": []})
    _write(run / "artifacts" / "local_validation.json", {})

    result = execute_report(str(run))

    assert result["status"] == "ok"
    report = (run / "report.md").read_text(encoding="utf-8")
    section = report.split("## 18. 外部分析器结果", 1)[1].split("## 19.", 1)[0]
    for name in ("satc", "firmrec", "klee", "bond"):
        assert name in section
    assert "受限结论" in section


def test_report_merges_klee_artifact_when_all_json_is_missing(tmp_path: Path) -> None:
    """KLEE writes klee.json in SYMEX_PRUNE; the report must not report 0."""
    run = tmp_path / "runs" / "run-klee"
    _write(
        run / "state" / "task_card.json",
        {
            "task_id": "run-klee",
            "authorization": {"holder": "owner", "scope": "analysis-only"},
        },
    )
    _write(run / "artifacts" / "rootfs.json", {"status": "ok"})
    _write(run / "artifacts" / "binary_summaries.json", {"inventory": {}, "summaries": []})
    _write(run / "artifacts" / "attack_surface.json", {"surfaces": []})
    _write(run / "artifacts" / "ranking.json", {"candidates": []})
    _write(run / "artifacts" / "verdict.json", {"run_id": "run-klee", "verdicts": []})
    _write(run / "artifacts" / "local_validation.json", {})
    _write(
        run / "artifacts" / "external_findings" / "klee.json",
        {
            "status": "ok",
            "tool": "klee",
            "findings": [{"finding_id": "k1"}, {"finding_id": "k2"}],
        },
    )

    result = execute_report(str(run))

    assert result["status"] == "ok"
    report = (run / "report.md").read_text(encoding="utf-8")
    section = report.split("## 18. 外部分析器结果", 1)[1].split("## 19.", 1)[0]
    assert "规范化外部发现：2" in section
    assert "klee=ok" in section


def test_report_grounds_evidence_and_discloses_gaps(tmp_path: Path) -> None:
    run = tmp_path / "runs" / "run-grounded"
    rootfs = tmp_path / "rootfs"
    (rootfs / "sbin").mkdir(parents=True)
    (rootfs / "sbin" / "httpd").write_bytes(b"ELF")
    _write(
        run / "state" / "task_card.json",
        {
            "task_id": "run-grounded",
            "authorization": {"holder": "owner", "scope": "analysis-only"},
        },
    )
    _write(
        run / "artifacts" / "rootfs.json",
        {
            "status": "ok",
            "input_type": "firmware",
            "rootfs_path": str(rootfs),
            "unpack_method": "squashfs",
            "rootfs_score": 8,
            "extraction_confidence": 1.0,
        },
    )
    _write(
        run / "artifacts" / "binary_summaries.json",
        {
            "inventory": {},
            "summaries": [
                {"binary_id": "bin-1", "path": "sbin/httpd", "architecture": "mipsel"}
            ],
        },
    )
    _write(run / "artifacts" / "attack_surface.json", {"surfaces": []})
    _write(
        run / "artifacts" / "ranking.json",
        {
            "candidates": [
                {
                    "candidate_id": "cand-1",
                    "binary_id": "bin-1",
                    "surface_id": "ntp_sync.cgi",
                    "source": {"name": "ntp_server", "type": "http_query"},
                    "sink": {"function": "system", "type": "command_execution"},
                    "call_chain": [],
                    "authorization": {"required": True},
                    "risk_score": 10,
                    "risk_level": "MEDIUM",
                    "evidence": ["ev-1"],
                    "counterevidence": ["call-chain-not-proven"],
                    "conclusion_category": "unknown",
                }
            ]
        },
    )
    _write(
        run / "artifacts" / "verdict.json",
        {
            "run_id": "run-grounded",
            "verdicts": [
                {
                    "candidate_id": "cand-1",
                    "action": "DOWNGRADE",
                    "original_score": 10,
                    "revised_score": 4,
                    "reasons": ["Call chain from entry to sink is not demonstrated."],
                    "supporting_evidence": ["ev-1"],
                    "counterevidence": ["call-chain-not-proven"],
                    "reviewer": "rule",
                }
            ],
        },
    )
    _write(run / "artifacts" / "local_validation.json", {})
    _write(
        run / "artifacts" / "decompile.json",
        {"status": "degraded", "reason": "no decompiler backend", "fallback": "pyelftools"},
    )
    _write(
        run / "artifacts" / "agent_trace.json",
        {
            "enabled": True,
            "status": "degraded",
            "model": {
                "used": True,
                "provider": "openai_compatible",
                "model": "deepseek-flash",
                "calls": 5,
                "tokens": 100,
            },
        },
    )
    _write(run / "evidence" / "ev-1.json", {"observation": "present"})
    _write(
        run / "artifacts" / "external_findings" / "all.json",
        {
            "status": "skipped",
            "per_tool": {
                "satc": {"status": "skipped", "limitation": "image missing"},
                "firmrec": {"status": "skipped", "limitation": "blind"},
            },
        },
    )

    result = execute_report(str(run))

    assert result["status"] == "ok"
    report = (run / "report.md").read_text(encoding="utf-8")
    assert report.count("\n## ") == 24
    section4 = report.split("## 4. 分析环境", 1)[1].split("## 5.", 1)[0]
    assert "openai_compatible/deepseek-flash" in section4
    assert "模型不参与漏洞结论" in section4
    section5 = report.split("## 5. 解包与根文件系统", 1)[1].split("## 6.", 1)[0]
    assert "解包方式：squashfs" in section5
    section14 = report.split("## 14. 风险排序", 1)[1].split("## 15.", 1)[0]
    assert "| 候选 | 分数 |" in section14
    assert "ntp_server → system" in section14
    assert "未证明" in section14
    section15 = report.split("## 15. 反证验证结果", 1)[1].split("## 16.", 1)[0]
    assert "已复核：1/1" in section15
    assert "DOWNGRADE" in section15
    assert "不代表漏洞不存在" in section15
    section21 = report.split("## 21. 限制与待验证事实", 1)[1].split("## 22.", 1)[0]
    assert "DECOMPILE" in section21
    assert "mipsel" in section21
    assert "调用链恢复仅支持" in section21
    assert "accepted=0" in section21


def test_report_excludes_firmrec_from_normalized_external_count(tmp_path: Path) -> None:
    run = tmp_path / "runs" / "run-firmrec-count"
    _write(
        run / "state" / "task_card.json",
        {"task_id": "run-firmrec-count", "authorization": {"holder": "o", "scope": "s"}},
    )
    _write(run / "artifacts" / "rootfs.json", {"status": "ok"})
    _write(run / "artifacts" / "binary_summaries.json", {"inventory": {}, "summaries": []})
    _write(run / "artifacts" / "attack_surface.json", {"surfaces": []})
    _write(run / "artifacts" / "ranking.json", {"candidates": []})
    _write(run / "artifacts" / "verdict.json", {"run_id": "run-firmrec-count", "verdicts": []})
    _write(run / "artifacts" / "local_validation.json", {})
    _write(
        run / "artifacts" / "external_findings" / "all.json",
        {
            "status": "ok",
            "per_tool": {
                "satc": {"status": "ok", "findings": [{"finding_id": "s1"}]},
                "firmrec": {
                    "status": "ok",
                    "findings": [{"finding_id": "f1"}, {"finding_id": "f2"}],
                },
            },
        },
    )

    execute_report(str(run))

    report = (run / "report.md").read_text(encoding="utf-8")
    section = report.split("## 18. 外部分析器结果", 1)[1].split("## 19.", 1)[0]
    assert "规范化外部发现：1" in section


def test_report_handles_int_findings_and_renders_recurrence(tmp_path: Path) -> None:
    run = tmp_path / "runs" / "run-1"
    _write(
        run / "state" / "task_card.json",
        {
            "task_id": "run-1",
            "authorization": {"holder": "owner", "scope": "analysis-only"},
        },
    )
    _write(run / "artifacts" / "rootfs.json", {"status": "ok"})
    _write(run / "artifacts" / "binary_summaries.json", {"inventory": {}, "summaries": []})
    _write(run / "artifacts" / "attack_surface.json", {"surfaces": []})
    _write(run / "artifacts" / "ranking.json", {"candidates": []})
    _write(run / "artifacts" / "verdict.json", {"run_id": "run-1", "verdicts": []})
    _write(run / "artifacts" / "local_validation.json", {})
    _write(
        run / "artifacts" / "external_findings" / "all.json",
        {
            "status": "ok",
            "findings": 3,
            "per_tool": {"satc": {"status": "ok"}, "firmrec": {"status": "skipped"}},
        },
    )
    _write(
        run / "artifacts" / "external_findings" / "recurrence_findings.json",
        {
            "summary": {"recurrence": 1, "blind_isolated": 1},
            "findings": [
                {
                    "tool": "firmrec",
                    "matched_cve": "CVE-2017-17215",
                    "blind_isolated": True,
                }
            ],
        },
    )

    result = execute_report(str(run))

    assert result["status"] == "ok"
    assert result["section_count"] == 24
    report = (run / "report.md").read_text(encoding="utf-8")
    assert report.count("\n## ") == 24
    assert "自主分析轨迹" in report
    assert "未启用" in report
    assert "规范化外部发现：3" in report
    assert "satc=ok" in report
    assert "复发发现：1 条" in report
    assert "CVE-2017-17215" in report
    assert "不计入 Blind Benchmark 指标" in report
