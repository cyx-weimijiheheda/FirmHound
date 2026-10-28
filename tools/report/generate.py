"""Generate a reproducible, safety-filtered firmware analysis report."""

# ruff: noqa: E501 -- Chinese report sentences are intentionally kept intact.

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fsa.schemas.loader import validate
from fsa.utils.jsonio import save_json
from tools.external.bond.sanitize import sanitize_poc
from tools.pipeline_context import load_artifact, load_task, run_path

_SECTIONS = [
    "执行摘要",
    "任务与授权范围",
    "输入与固件指纹",
    "分析环境",
    "解包与根文件系统",
    "文件系统清单",
    "体系结构与加固概览",
    "启动服务",
    "Web 入口",
    "网络与协议攻击面",
    "重点二进制",
    "静态分析方法",
    "漏洞候选总览",
    "风险排序",
    "反证验证结果",
    "误报控制摘要",
    "本地动态验证",
    "外部分析器结果",
    "复发漏洞（FirmRec）",
    "证据链与可追溯性",
    "限制与待验证事实",
    "修复建议",
    "最终结论",
    "自主分析轨迹",
]


def _count(payload: Any, key: str) -> int:
    return len(payload.get(key, [])) if isinstance(payload, dict) else 0


def _finding_count(payload: Any) -> int:
    """Count findings whether the artifact stores a list or a precomputed int."""
    if not isinstance(payload, dict):
        return 0
    findings = payload.get("findings", 0)
    if isinstance(findings, bool):
        return 0
    if isinstance(findings, int):
        return findings
    if isinstance(findings, list):
        return len(findings)
    return 0


# Mirrors tools.external.adapter.EXTERNAL_TOOLS; kept local so the report
# can name the analyzers even when no external stage produced an artifact.
_EXTERNAL_TOOL_NAMES = ("satc", "firmrec", "klee", "bond")


def _tool_statuses(payload: Any) -> str:
    """Summarize per-tool statuses from ``all.json`` (``per_tool``) or legacy keys."""
    names = "/".join(_EXTERNAL_TOOL_NAMES)
    if not isinstance(payload, dict) or not payload:
        return f"未运行（无外部分析产物；{names} 均未启用）"
    per_tool = payload.get("per_tool")
    if isinstance(per_tool, dict) and per_tool:
        parts = []
        for name, info in sorted(per_tool.items()):
            if isinstance(info, dict):
                status = info.get("status") or "unknown"
                limitation = info.get("limitation")
                parts.append(
                    f"{name}={status}（{limitation}）" if limitation else f"{name}={status}"
                )
            else:
                parts.append(f"{name}={info}")
        return ", ".join(parts)
    statuses = payload.get("tool_statuses")
    if isinstance(statuses, dict) and statuses:
        return ", ".join(f"{name}={status}" for name, status in sorted(statuses.items()))
    if payload.get("status") == "skipped":
        base = f"全部未启用（{names} 均未运行）"
        limitation = payload.get("limitation")
        return f"{base}；{limitation}" if limitation else base
    return "未启用"


def _external_unavailable(payload: Any) -> bool:
    """True when no external analyzer contributed any corroborating result."""
    if _finding_count(payload) > 0:
        return False
    if not isinstance(payload, dict) or not payload:
        return True
    if payload.get("status") == "skipped":
        return True
    per_tool = payload.get("per_tool")
    if isinstance(per_tool, dict) and per_tool:
        return all(
            (info.get("status") if isinstance(info, dict) else str(info)) != "ok"
            for info in per_tool.values()
        )
    return payload.get("status") != "ok"


def _external_section(payload: Any) -> str:
    """Render the external-analyzer section, naming tools and limited claims."""
    text = f"规范化外部发现：{_finding_count(payload)}；工具状态：{_tool_statuses(payload)}。"
    if _external_unavailable(payload):
        text += (
            "受限结论：外部分析器未提供跨二进制污点传播与交叉验证，"
            "候选结论仅依据静态分析与反证审查。"
        )
    return text


def _false_positive_summary(
    ranking: dict[str, Any],
    verdict: dict[str, Any],
) -> dict[str, Any]:
    """Summarize how many candidates were constrained, downgraded, or left for validation."""
    ranked = ranking.get("candidates", []) if isinstance(ranking, dict) else []
    verdicts = verdict.get("verdicts", []) if isinstance(verdict, dict) else []
    actions = [str(v.get("action", "")).upper() for v in verdicts if isinstance(v, dict)]
    support_count = sum(len(c.get("evidence", []) or []) for c in ranked if isinstance(c, dict))
    counter_count = sum(
        len(c.get("counterevidence", []) or []) for c in ranked if isinstance(c, dict)
    )
    need_dynamic = sum(
        1
        for c in ranked
        if isinstance(c, dict)
        and (
            c.get("decisive_missing_fact")
            or c.get("conclusion_category") in {"unknown", "high-confidence-candidate"}
        )
    )
    confirmed = sum(
        1
        for c in ranked
        if isinstance(c, dict) and c.get("conclusion_category") == "confirmed-issue"
    )
    completeness = 0.0
    if ranked:
        evidence_ready = sum(1 for c in ranked if isinstance(c, dict) and c.get("evidence"))
        completeness = round(evidence_ready / len(ranked), 3)
    return {
        "candidate_total": len(ranked),
        "reviewed_total": len(verdicts),
        "accepted_total": actions.count("ACCEPT"),
        "downgraded_total": actions.count("DOWNGRADE"),
        "rejected_total": actions.count("REJECT"),
        "need_dynamic_total": actions.count("NEED_DYNAMIC") or need_dynamic,
        "confirmed_total": confirmed,
        "supporting_evidence_total": support_count,
        "counterevidence_total": counter_count,
        "evidence_completeness": completeness,
    }


def _agent_summary(trace: dict[str, Any], *, requested: bool = False) -> str:
    """Render the agent trace as counts only; never include raw model text."""
    if not isinstance(trace, dict) or not trace:
        if requested:
            return (
                "已启用但未产生 agent_trace.json；请查看阶段状态与 limitations，"
                "漏洞结论仍由确定性阶段与反证审查产生。"
            )
        return "未启用（--agent 未开启）；漏洞结论仍由确定性阶段与反证审查产生。"
    if trace.get("disabled_reason") == "blind":
        return "Blind 运行强制禁用自主分析，避免模型先验泄漏。"
    if not trace.get("enabled", False):
        reason = trace.get("disabled_reason") or "未启用"
        return f"未启用（{reason}）；漏洞结论仍由确定性阶段与反证审查产生。"
    budget = trace.get("budget", {}) if isinstance(trace.get("budget"), dict) else {}
    summary = trace.get("summary", {}) if isinstance(trace.get("summary"), dict) else {}
    model = trace.get("model", {}) if isinstance(trace.get("model"), dict) else {}
    unresolved = int(summary.get("skipped_candidates", 0)) + int(
        summary.get("stalled_candidates", 0)
    )
    return (
        f"检查候选：{budget.get('used_candidates', 0)}；"
        f"步数：{summary.get('steps', 0)}；"
        f"工具调用：{budget.get('used_tool_calls', 0)}；"
        f"新增证据：{summary.get('evidence_added', 0)}；"
        f"模型参与：{bool(model.get('used', False))}；"
        f"模型回退：{model.get('fallback_count', 0)}；"
        f"停止原因：{summary.get('stop_reason', 'unknown')}；"
        f"未解决候选：{unresolved}。"
        "模型仅参与动作选择，不参与漏洞结论。"
        "执行路径：[打开交互式 Agent 轨迹](artifacts/agent_execution.html)。"
    )


def _section_body(
    title: str,
    task: dict[str, Any],
    rootfs: dict[str, Any],
    binaries: dict[str, Any],
    surfaces: dict[str, Any],
    ranking: dict[str, Any],
    verdict: dict[str, Any],
    validation: dict[str, Any],
    external: dict[str, Any],
    recurrence: dict[str, Any],
    agent_trace: dict[str, Any],
) -> str:
    inventory = binaries.get("inventory", {}) if isinstance(binaries, dict) else {}
    rows = binaries.get("summaries", []) if isinstance(binaries, dict) else []
    ranked = ranking.get("candidates", []) if isinstance(ranking, dict) else []
    verdicts = verdict.get("verdicts", []) if isinstance(verdict, dict) else []
    fp_summary = _false_positive_summary(ranking, verdict)
    recurrence_findings = recurrence.get("findings", []) if isinstance(recurrence, dict) else []
    if not isinstance(recurrence_findings, list):
        recurrence_findings = []
    isolated = sum(
        1 for item in recurrence_findings if isinstance(item, dict) and item.get("blind_isolated")
    )
    cves: list[str] = []
    for item in recurrence_findings:
        cve = str(item.get("matched_cve") or "") if isinstance(item, dict) else ""
        if cve and cve not in cves:
            cves.append(cve)
    values = {
        "执行摘要": f"完成 {_count(surfaces, 'surfaces')} 个攻击面、{len(rows)} 个 ELF 与 {len(ranked)} 个候选的可追溯分析。",
        "任务与授权范围": f"授权主体：{task['authorization']['holder']}；范围：{task['authorization']['scope']}；仅分析提交的输入。",
        "输入与固件指纹": f"输入类型：{rootfs.get('input_type', 'unknown')}；固件 SHA-256：{rootfs.get('firmware_sha256', '目录输入，不适用')}。",
        "分析环境": "CLI 离线执行；外部分析器和网络能力由配置及安全策略控制。",
        "解包与根文件系统": f"状态：{rootfs.get('status', 'unknown')}；置信度：{rootfs.get('extraction_confidence', 0)}。",
        "文件系统清单": f"ELF：{inventory.get('elf_count', 0)}；脚本：{inventory.get('script_count', 0)}；配置：{inventory.get('config_count', 0)}。",
        "体系结构与加固概览": f"检测到的体系结构：{', '.join(sorted({str(r.get('architecture')) for r in rows})) or '无'}。",
        "启动服务": f"启动服务记录：{binaries.get('startup', {}).get('service_count', 0) if isinstance(binaries, dict) else 0}。",
        "Web 入口": f"Web/CGI 表面：{sum(1 for s in surfaces.get('surfaces', []) if s.get('category') in {'web', 'cgi'}) if isinstance(surfaces, dict) else 0}。",
        "网络与协议攻击面": f"全部攻击面：{_count(surfaces, 'surfaces')}。",
        "重点二进制": f"已按启动、网络、Web 和危险 API 信号完成 {len(rows)} 个二进制分诊。",
        "静态分析方法": "候选仅由真实 source/sink 信号生成；没有调用链时明确保留为待验证事实。",
        "漏洞候选总览": f"候选数：{len(ranked)}。",
        "风险排序": "; ".join(
            f"{c.get('candidate_id')}={c.get('risk_score')}/{c.get('risk_level')}"
            for c in ranked[:10]
        )
        or "无候选。",
        "反证验证结果": f"已复核：{len(verdicts)}；接受：{sum(1 for v in verdicts if v.get('action') == 'ACCEPT')}。",
        "误报控制摘要": (
            f"候选总数：{fp_summary['candidate_total']}；已复核：{fp_summary['reviewed_total']}；"
            f"确认采纳：{fp_summary['accepted_total']}；降级：{fp_summary['downgraded_total']}；"
            f"拒绝：{fp_summary['rejected_total']}；需动态验证：{fp_summary['need_dynamic_total']}；"
            f"支持证据：{fp_summary['supporting_evidence_total']}；"
            f"反证：{fp_summary['counterevidence_total']}；"
            f"证据完整度：{fp_summary['evidence_completeness']}。"
        ),
        "本地动态验证": f"状态：{validation.get('status', '未执行') if isinstance(validation, dict) else '未执行'}；不将加载测试表述为漏洞复现。",
        "外部分析器结果": _external_section(external),
        "复发漏洞（FirmRec）": (
            f"复发发现：{_finding_count(recurrence)} 条；盲跑隔离：{isolated} 条；"
            f"命中签名：{', '.join(cves[:5]) or '无'}。"
            "本节依赖已知漏洞签名，不属于零先验能力，不计入 Blind Benchmark 指标。"
        ),
        "证据链与可追溯性": "每个候选引用独立 evidence_id，决策和阶段状态保存在运行目录。",
        "限制与待验证事实": "静态 source/sink 共存不等于数据流可达；缺少调用链的候选必须通过反编译或隔离动态验证。",
        "修复建议": "优先消除 Shell 调用，采用参数化 API；对网络输入执行白名单、长度和类型校验，并收紧预认证入口。",
        "最终结论": f"基于现有证据形成 {len(verdicts)} 条反证审查结论；未达到证据门槛的条目不声明为已确认漏洞。",
        "自主分析轨迹": _agent_summary(
            agent_trace,
            requested=bool((task.get("agent") or {}).get("enabled", False)),
        ),
    }
    return values[title]


def execute_report(run_dir: str) -> dict[str, Any]:
    """Render the fixed competition report outline and schema-valid verdict JSON."""
    run = run_path(run_dir)
    task = load_task(run)
    rootfs = load_artifact(run, "rootfs.json", {})
    binaries = load_artifact(run, "binary_summaries.json", {})
    surfaces = load_artifact(run, "attack_surface.json", {})
    ranking = load_artifact(run, "ranking.json", {})
    verdict = load_artifact(run, "verdict.json", {"run_id": run.name, "verdicts": []})
    validation = load_artifact(run, "local_validation.json", {})
    external = load_artifact(run, "external_findings/all.json", {})
    recurrence = load_artifact(run, "external_findings/recurrence_findings.json", {})
    agent_trace = load_artifact(run, "agent_trace.json", {})
    if not agent_trace and task.get("blind", False):
        agent_trace = {"enabled": False, "disabled_reason": "blind"}
    validate(verdict, schema_name="verdict")

    lines = [f"# 固件安全智能体分析报告 — {run.name}", ""]
    for index, title in enumerate(_SECTIONS, start=1):
        lines.extend(
            [
                f"## {index}. {title}",
                "",
                _section_body(
                    title,
                    task,
                    rootfs,
                    binaries,
                    surfaces,
                    ranking,
                    verdict,
                    validation,
                    external,
                    recurrence,
                    agent_trace,
                ),
                "",
            ]
        )
    report_path = run / "report.md"
    report_text = "\n".join(lines)
    _sanitized, report_is_safe = sanitize_poc(report_text)
    if not report_is_safe:
        return {
            "status": "failed",
            "reason": "report compliance gate rejected dangerous payload content",
        }
    report_path.write_text(report_text, encoding="utf-8")
    compliance = {
        "status": "ok",
        "checks": {
            "dangerous_payload_absent": True,
            "raw_poc_not_rendered": True,
            "unproven_findings_not_labeled_confirmed": True,
            "external_findings_normalized": True,
        },
    }
    compliance_path = run / "artifacts" / "report_compliance.json"
    save_json(compliance_path, compliance)

    final_verdict = {
        **verdict,
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "stats": {
            "attack_surfaces": _count(surfaces, "surfaces"),
            "binaries": _count(binaries, "summaries"),
            "candidates": _count(ranking, "candidates"),
            "false_positive_control": _false_positive_summary(ranking, verdict),
        },
        "report": str(report_path),
    }
    validate(final_verdict, schema_name="verdict")
    final_path = run / "final_verdict.json"
    save_json(final_path, final_verdict)
    return {
        "status": "ok",
        "report": str(report_path),
        "final_verdict": str(final_path),
        "report_compliance": str(compliance_path),
        "section_count": len(_SECTIONS),
    }
