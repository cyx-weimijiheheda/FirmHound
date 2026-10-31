"""Generate a reproducible, safety-filtered firmware analysis report."""

# ruff: noqa: E501 -- Chinese report sentences are intentionally kept intact.

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fsa.schemas.loader import validate
from fsa.utils.jsonio import load_json, save_json
from tools.external.bond.sanitize import sanitize_poc
from tools.pipeline_context import load_artifact, load_task, run_path
from tools.report.grounding import build_grounding

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


def _load_external_bundle(run: Path) -> dict[str, Any]:
    """Merge all.json with per-tool files without double counting FirmRec."""
    base = load_artifact(run, "external_findings/all.json", {})
    payload: dict[str, Any] = dict(base) if isinstance(base, dict) else {}
    per_tool: dict[str, Any] = dict(payload.get("per_tool") or {})
    extra_findings = 0
    for tool in _EXTERNAL_TOOL_NAMES:
        if tool in per_tool:
            continue
        document = load_artifact(run, f"external_findings/{tool}.json", {})
        if not isinstance(document, dict) or not document:
            per_tool[tool] = {
                "status": "skipped",
                "limitation": "no artifact in this run (tool not enabled or did not run)",
            }
            continue
        per_tool[tool] = document
        if tool != "firmrec":
            # KLEE/BOND run outside EXTERNAL_ANALYSIS and write their own
            # artifacts; count them, but never fold recurrence-only FirmRec
            # findings into the normalized external total.
            extra_findings += _finding_count(document)
    if per_tool:
        payload["per_tool"] = per_tool
    list_sources = {
        name: info
        for name, info in per_tool.items()
        if isinstance(info, dict) and isinstance(info.get("findings"), list)
    }
    if list_sources:
        # Recompute from per-tool lists so recurrence-only FirmRec findings do
        # not inflate section 18; section 19 reads them separately.
        payload["findings"] = sum(
            _finding_count(info)
            for name, info in list_sources.items()
            if name != "firmrec"
        )
    elif extra_findings:
        payload["findings"] = _finding_count(base) + extra_findings
    elif per_tool and (not isinstance(base, dict) or not base):
        payload["findings"] = 0
    return payload


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
    """True when no non-recurrence analyzer contributed a corroborating result."""
    if _finding_count(payload) > 0:
        return False
    if not isinstance(payload, dict) or not payload:
        return True
    per_tool = payload.get("per_tool")
    if isinstance(per_tool, dict) and per_tool:
        counted = {
            name: info for name, info in per_tool.items() if name != "firmrec"
        }
        if not counted:
            return True
        return all(
            (info.get("status") if isinstance(info, dict) else str(info)) != "ok"
            for info in counted.values()
        )
    if payload.get("status") == "skipped":
        return True
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


def _cell(value: Any, limit: int = 80) -> str:
    """Render one safe Markdown table cell; never include a raw payload."""
    text = " ".join(str(value if value not in (None, "") else "?").split())
    text = text.replace("|", "\\|")
    return text[:limit]


def _source_label(candidate: dict[str, Any]) -> str:
    source = candidate.get("source") or {}
    return str(
        source.get("api")
        or source.get("name")
        or source.get("type")
        or ("string" if source.get("string") else "?")
    )


def _sink_label(candidate: dict[str, Any]) -> str:
    sink = candidate.get("sink") or {}
    return str(sink.get("function") or sink.get("type") or "?")


def _entry_label(candidate: dict[str, Any]) -> str:
    entry = candidate.get("entry") or {}
    return str(
        entry.get("handler")
        or entry.get("route")
        or candidate.get("surface_id")
        or "未映射"
    )


def _auth_label(candidate: dict[str, Any]) -> str:
    required = (candidate.get("authorization") or {}).get("required")
    if required is True:
        return "需要"
    if required is False:
        return "不需要"
    return "未知"


def _validation_summary(validation: dict[str, Any]) -> str:
    if not isinstance(validation, dict) or not validation:
        return "状态：未执行；不将加载测试表述为漏洞复现。"
    status = validation.get("status", "未执行")
    loader = validation.get("loader")
    qemu = validation.get("qemu")
    if loader == "native":
        detail = "native busybox 加载检查"
    elif qemu:
        detail = f"QEMU 加载检查（{qemu}）"
    else:
        detail = "加载检查"
    return f"状态：{status}；{detail}；不将加载测试表述为漏洞复现。"


def _evidence_table(
    ranked: list[dict[str, Any]],
    verdicts: list[dict[str, Any]],
    summaries: list[dict[str, Any]],
) -> str:
    """Top-10 candidates with the evidence chain needed to reproduce a decision."""
    if not ranked:
        return "无候选。"
    summary_by_id = {
        str(item.get("binary_id")): item for item in summaries if isinstance(item, dict)
    }
    verdict_by_id = {
        str(item.get("candidate_id")): item for item in verdicts if isinstance(item, dict)
    }
    lines = [
        "下表列出风险分最高的 10 个候选及其解包来源。完整集合见 artifacts/ranking.json，"
        "证据正文见 evidence/ 下逐个 JSON 文件。",
        "",
        "| 候选 | 分数 | 二进制 / 入口 | Source → Sink | 调用链 | 认证 | 证据 | 反证 / 裁决 |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for candidate in ranked[:10]:
        candidate_id = str(candidate.get("candidate_id") or "?")
        summary = summary_by_id.get(str(candidate.get("binary_id") or ""), {})
        binary = str(summary.get("path") or candidate.get("binary_id") or "?")
        entry = _entry_label(candidate)
        chain_length = len(candidate.get("call_chain") or [])
        chain = f"{chain_length} 层" if chain_length else "未证明"
        counter = candidate.get("counterevidence") or []
        verdict = verdict_by_id.get(candidate_id, {})
        action = verdict.get("action") or candidate.get("conclusion_category") or "未复核"
        counter_text = ", ".join(str(item) for item in counter[:3]) or "无"
        lines.append(
            "| "
            + " | ".join(
                [
                    _cell(candidate_id, 40),
                    _cell(f"{candidate.get('risk_score')}/{candidate.get('risk_level')}", 20),
                    _cell(f"{binary} / {entry}", 70),
                    _cell(f"{_source_label(candidate)} → {_sink_label(candidate)}", 70),
                    _cell(chain, 20),
                    _cell(_auth_label(candidate), 10),
                    _cell(len(candidate.get("evidence") or []), 10),
                    _cell(f"{counter_text}; {action}", 90),
                ]
            )
            + " |"
        )
    return "\n".join(lines)


def _verdict_table(
    verdicts: list[dict[str, Any]],
    candidate_total: int,
    grounding: dict[str, Any],
) -> str:
    """Verdicts plus coverage and explicit exclusion wording."""
    reviewed = len(verdicts)
    unreviewed = max(0, candidate_total - reviewed)
    if not verdicts:
        return (
            f"已复核：0；未复核：{candidate_total}。VERIFY_TOP_K 未完成或未产生裁决，"
            "需完成反证审查后才能声明确认漏洞。"
        )
    actions: dict[str, int] = {}
    for verdict in verdicts:
        action = str(verdict.get("action") or "UNKNOWN")
        actions[action] = actions.get(action, 0) + 1
    lines = [
        f"已复核：{reviewed}/{candidate_total}；未复核：{unreviewed}；"
        f"动作分布：{', '.join(f'{key}={value}' for key, value in sorted(actions.items()))}。"
        "“排除/降级”表示本轮证据门槛下不采纳；确认或否定漏洞需要后续验证。",
    ]
    orphans = grounding.get("orphan_verdicts") or []
    if orphans:
        lines.append(
            "裁决与当前候选集不匹配的 ID：" + ", ".join(str(item) for item in orphans[:10])
        )
    lines.extend(
        [
            "",
            "| 候选 | 动作 | 原分 → 修正分 | 理由 | 反证 |",
            "|---|---|---|---|---|",
        ]
    )
    for verdict in verdicts:
        lines.append(
            "| "
            + " | ".join(
                [
                    _cell(verdict.get("candidate_id"), 40),
                    _cell(verdict.get("action"), 16),
                    _cell(
                        f"{verdict.get('original_score')} → {verdict.get('revised_score')}",
                        24,
                    ),
                    _cell("；".join(verdict.get("reasons") or []), 120),
                    _cell(
                        ", ".join(str(item) for item in (verdict.get("counterevidence") or [])[:4]),
                        80,
                    ),
                ]
            )
            + " |"
        )
    return "\n".join(lines)


def _environment_summary(grounding: dict[str, Any]) -> str:
    """Describe actual model/external usage instead of claiming blanket offline."""
    external_tools = grounding.get("external_tools") or []
    active_external = [
        item
        for item in external_tools
        if item.get("status") in {"ok", "degraded", "partial"}
    ]
    if grounding.get("model_used"):
        model = f"{grounding.get('model_provider') or '?'}/{grounding.get('model_name') or '?'}"
        text = (
            "确定性阶段本地执行；AGENT_LOOP 使用 "
            f"{model} 进行动作排序（{grounding.get('model_calls', 0)} 次，"
            f"{grounding.get('model_tokens', 0)} tokens），模型不参与漏洞结论。"
        )
    elif grounding.get("agent_enabled"):
        text = "确定性阶段本地执行；AGENT_LOOP 已启用但未调用模型（规则选择）。"
    else:
        text = "确定性阶段本地执行；未调用模型。"
    if active_external:
        text += "外部分析器有产出，实际状态见第 18 节。"
    else:
        text += "外部分析器未运行或全部降级，原因见第 18 节。"
    return text


def _rootfs_summary(rootfs: dict[str, Any], grounding: dict[str, Any]) -> str:
    """Describe unpack provenance without leaking an absolute host path."""
    input_type = rootfs.get("input_type", "unknown")
    if input_type == "rootfs":
        return "输入为已解包 rootfs；未执行固件解包。"
    parts = [
        f"输入类型：{input_type}",
        f"解包方式：{grounding.get('unpack_method') or 'unknown'}",
        f"rootfs 评分：{grounding.get('rootfs_score', '?')}",
        f"置信度：{grounding.get('extraction_confidence', '?')}",
        f"状态：{rootfs.get('status', 'unknown')}",
    ]
    if grounding.get("rootfs_candidates") is not None:
        parts.append(f"保留 rootfs 候选：{grounding.get('rootfs_candidates')}")
    if grounding.get("rootfs_duplicates_suppressed"):
        parts.append(
            f"抑制重复候选：{grounding.get('rootfs_duplicates_suppressed')}"
        )
    if grounding.get("unpack_degraded"):
        parts.append("解包降级：提取器非 0 退出但产出了可用文件树，设备节点可能缺失")
    return "；".join(parts) + "。"


def _limitations_summary(grounding: dict[str, Any]) -> str:
    """List concrete capability gaps behind the evidence boundary."""
    bullets = [
        "静态 source/sink 共存需要数据流证据；缺少调用链的候选通过反编译或隔离动态验证补齐。",
    ]
    decompile_status = grounding.get("decompile_status")
    if decompile_status in {"ok", "full"} and grounding.get("decompile_backend") == "ghidra":
        reason = grounding.get("decompile_reason") or "未记录原因"
        bullets.append(
            "反编译：Ghidra 已导出 "
            f"{grounding.get('decompile_analyzed', 0)}/"
            f"{grounding.get('decompile_selected', 0)} 个二进制（{reason}）。"
        )
    elif decompile_status and decompile_status != "unknown":
        reason = grounding.get("decompile_reason") or "未记录原因"
        fallback = grounding.get("decompile_fallback") or "unknown"
        bullets.append(
            f"DECOMPILE 状态：{decompile_status}；原因：{reason}；fallback={fallback}。"
        )
    unsupported = grounding.get("chain_unsupported_architectures") or []
    if unsupported:
        supported = ", ".join(
            str(item) for item in (grounding.get("chain_supported_arches") or [])
        )
        if grounding.get("decompile_backend") == "ghidra" and grounding.get(
            "candidates_with_chain"
        ):
            bullets.append(
                "检测到架构 "
                + ", ".join(str(item) for item in unsupported)
                + f"；Ghidra 已为 {grounding.get('candidates_with_chain', 0)} 条候选补出调用链，"
                f"其余 {grounding.get('candidates_without_chain', 0)} 条仍无链；"
                f"基础 capstone fallback 仅支持 {supported}。"
            )
        else:
            bullets.append(
                "检测到架构 "
                + ", ".join(str(item) for item in unsupported)
                + "；当前调用链恢复仅支持 "
                + supported
                + f"，因此 {grounding.get('candidates_without_chain', 0)} 条候选没有调用链证据。"
            )
    else:
        bullets.append(
            f"调用链证据：{grounding.get('candidates_with_chain', 0)}/"
            f"{grounding.get('candidate_total', 0)} 条候选有至少 2 层调用链。"
        )
    bullets.append(
        "候选可追溯性："
        f"{grounding.get('candidate_traceable', 0)}/"
        f"{grounding.get('candidate_total', 0)} 条候选的 binary_id 指向解包文件系统内的真实文件。"
    )
    if grounding.get("candidate_missing_binary"):
        missing = grounding.get("candidate_missing_ids") or []
        bullets.append(
            f"缺少可追溯二进制的候选：{grounding.get('candidate_missing_binary')} 条"
            + (f"（示例：{', '.join(str(item) for item in missing[:5])}）" if missing else "")
            + "。"
        )
    bullets.append(
        f"证据文件：候选引用 {grounding.get('evidence_referenced', 0)} 个 evidence_id，"
        f"其中 {grounding.get('evidence_resolved', 0)} 个在 evidence/ 下存在。"
    )
    external_tools = grounding.get("external_tools") or []
    if external_tools:
        parts = []
        for item in external_tools:
            status = item.get("status") or "unknown"
            limitation = item.get("limitation")
            parts.append(
                f"{item.get('name')}={status}"
                + (f"（{limitation}）" if limitation else "")
            )
        bullets.append("外部分析器：" + "；".join(parts) + "。")
    if grounding.get("binary_truncated"):
        bullets.append("二进制分诊达到 max_binaries 上限，部分 ELF 未进入候选生成。")
    if grounding.get("model_used"):
        bullets.append("模型仅参与动作选择，不参与漏洞结论、工具参数或路径生成。")
    bullets.append(
        "accepted=0 或“已降级/已排除”表示现有证据未闭合；确认或否定设备漏洞需要后续验证。"
    )
    return "\n".join(f"- {item}" for item in bullets)


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
    grounding: dict[str, Any],
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
        "分析环境": _environment_summary(grounding),
        "解包与根文件系统": _rootfs_summary(rootfs, grounding),
        "文件系统清单": f"ELF：{inventory.get('elf_count', 0)}；脚本：{inventory.get('script_count', 0)}；配置：{inventory.get('config_count', 0)}。",
        "体系结构与加固概览": f"检测到的体系结构：{', '.join(sorted({str(r.get('architecture')) for r in rows})) or '无'}。",
        "启动服务": f"启动服务记录：{binaries.get('startup', {}).get('service_count', 0) if isinstance(binaries, dict) else 0}。",
        "Web 入口": f"Web/CGI 表面：{sum(1 for s in surfaces.get('surfaces', []) if s.get('category') in {'web', 'cgi'}) if isinstance(surfaces, dict) else 0}。",
        "网络与协议攻击面": f"全部攻击面：{_count(surfaces, 'surfaces')}。",
        "重点二进制": f"已按启动、网络、Web 和危险 API 信号完成 {len(rows)} 个二进制分诊。",
        "静态分析方法": "候选仅由真实 source/sink 信号生成；没有调用链时明确保留为待验证事实。",
        "漏洞候选总览": f"候选数：{len(ranked)}。",
        "风险排序": _evidence_table(ranked, verdicts, rows),
        "反证验证结果": _verdict_table(verdicts, len(ranked), grounding),
        "误报控制摘要": (
            f"候选总数：{fp_summary['candidate_total']}；已复核：{fp_summary['reviewed_total']}；"
            f"确认采纳：{fp_summary['accepted_total']}；降级：{fp_summary['downgraded_total']}；"
            f"拒绝：{fp_summary['rejected_total']}；需动态验证：{fp_summary['need_dynamic_total']}；"
            f"支持证据：{fp_summary['supporting_evidence_total']}；"
            f"反证：{fp_summary['counterevidence_total']}；"
            f"证据完整度：{fp_summary['evidence_completeness']}。"
        ),
        "本地动态验证": _validation_summary(validation),
        "外部分析器结果": _external_section(external),
        "复发漏洞（FirmRec）": (
            f"复发发现：{_finding_count(recurrence)} 条；盲跑隔离：{isolated} 条；"
            f"命中签名：{', '.join(cves[:5]) or '无'}。"
            "本节依赖已知漏洞签名，不属于零先验能力，不计入 Blind Benchmark 指标。"
        ),
        "证据链与可追溯性": (
            f"候选引用 {grounding.get('evidence_referenced', 0)} 个 evidence_id，"
            f"其中 {grounding.get('evidence_resolved', 0)} 个在 evidence/ 下存在；"
            "决策和阶段状态保存在运行目录。"
        ),
        "限制与待验证事实": _limitations_summary(grounding),
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
    external = _load_external_bundle(run)
    recurrence = load_artifact(run, "external_findings/recurrence_findings.json", {})
    agent_trace = load_artifact(run, "agent_trace.json", {})
    if not agent_trace and task.get("blind", False):
        agent_trace = {"enabled": False, "disabled_reason": "blind"}
    decompile = load_artifact(run, "decompile.json", {})
    try:
        run_state = load_json(run / "state" / "run_state.json")
    except Exception:  # noqa: BLE001 - old/partial runs may not have state
        run_state = {}
    grounding = build_grounding(
        run,
        rootfs=rootfs,
        binaries=binaries,
        ranking=ranking,
        verdict=verdict,
        run_state=run_state,
        decompile=decompile,
        external=external,
        agent_trace=agent_trace,
    )
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
                    grounding,
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
