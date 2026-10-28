"""Generate an honest snapshot report from whatever a run has produced so far."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fsa.utils.jsonio import load_json
from tools.external.bond.sanitize import sanitize_poc

_ARTIFACTS = {
    "rootfs": "rootfs.json",
    "binaries": "binary_summaries.json",
    "surfaces": "attack_surface.json",
    "candidates": "candidates.json",
    "ranking": "ranking.json",
    "unified": "unified_candidates.json",
    "verdict": "verdict.json",
    "agent_trace": "agent_trace.json",
    "local_validation": "local_validation.json",
}


def _optional_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = load_json(path)
    except Exception:  # noqa: BLE001 - a partial/corrupt artifact must not break the snapshot
        return {}
    return data if isinstance(data, dict) else {}


def _candidates(run: Path, artifacts: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    for key in ("ranking", "unified", "candidates"):
        payload = artifacts.get(key) or {}
        items = payload.get("candidates")
        if isinstance(items, list):
            return [item for item in items if isinstance(item, dict)]
    return []


def _verdicts(artifacts: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    items = (artifacts.get("verdict") or {}).get("verdicts")
    return [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []


def _cell(value: Any) -> str:
    text = str(value if value not in (None, "") else "?")
    return text.replace("|", "\\|").replace("\n", " ")


def _source_label(candidate: dict[str, Any]) -> str:
    source = candidate.get("source") or {}
    # Never render a raw firmware string here; it may contain a real payload.
    return str(
        source.get("api")
        or source.get("name")
        or source.get("type")
        or ("[string]" if source.get("string") else "?")
    )


def _sink_label(candidate: dict[str, Any]) -> str:
    sink = candidate.get("sink") or {}
    return str(sink.get("function") or sink.get("type") or "?")


def _chain_label(candidate: dict[str, Any]) -> str:
    chain = candidate.get("call_chain") or []
    if not chain:
        return "未证明"
    return f"{len(chain)} 层"


def _agent_section(trace: dict[str, Any]) -> list[str]:
    if not trace:
        return ["未启用或 AGENT_LOOP 尚未产生 agent_trace.json。", ""]
    steps = trace.get("steps") if isinstance(trace.get("steps"), list) else []
    model = trace.get("model") if isinstance(trace.get("model"), dict) else {}
    summary = trace.get("summary") if isinstance(trace.get("summary"), dict) else {}
    budget = trace.get("budget") if isinstance(trace.get("budget"), dict) else {}
    actions = summary.get("actions")
    if not isinstance(actions, dict) or not actions:
        actions = {}
        for step in steps:
            if isinstance(step, dict):
                action = str(step.get("selected_action", "unknown"))
                actions[action] = actions.get(action, 0) + 1
    covered = len(
        {
            str(step.get("candidate_id"))
            for step in steps
            if isinstance(step, dict) and step.get("candidate_id")
        }
    )
    status = trace.get("status", "unknown")
    if status == "skipped" and steps:
        status = "in-progress/interrupted"
    lines = [
        f"- 状态：{status}；tier：{trace.get('tier', 'unknown')}；"
        f"启用：{trace.get('enabled')}",
        f"- 已执行动作：{len(steps)}；覆盖候选：{covered}；"
        f"工具调用：{budget.get('used_tool_calls', len(steps))}",
        f"- 模型：{model.get('provider', 'unknown')} / {model.get('model', '')}；"
        f"调用 {model.get('calls', 0)} 次；tokens {model.get('tokens', 0)}；"
        f"回退 {model.get('fallback_count', 0)} 次",
        f"- 停止/当前原因：{summary.get('stop_reason', 'unknown')}",
    ]
    if trace.get("enabled"):
        lines.append("- 执行路径：[打开交互式 Agent 轨迹](artifacts/agent_execution.html)")
    if actions:
        lines.append(
            "- 动作分布："
            + "；".join(f"{name}={count}" for name, count in sorted(actions.items()))
        )
    limitations = trace.get("limitations") or []
    if limitations:
        lines.extend(["", "主要限制："])
        lines.extend(f"- {item}" for item in limitations[:10])
    if len(limitations) > 10:
        lines.append(f"- 其余 {len(limitations) - 10} 条见 agent_trace.json")
    lines.append("")
    return lines


def execute_partial_report(
    run_dir: str | Path,
    *,
    limit: int = 20,
    output_path: str | Path | None = None,
) -> dict[str, Any]:
    """Write report.partial.md from existing artifacts only.

    This function never runs analysis, verifier, or model calls. Missing
    artifacts are reported as missing; nothing is inferred or fabricated.
    """
    run = Path(run_dir).resolve()
    if not run.is_dir():
        raise FileNotFoundError(f"Run directory not found: {run}")

    state = _optional_json(run / "state" / "run_state.json")
    task = _optional_json(run / "state" / "task_card.json")
    final = state.get("status") == "done" and (run / "report.md").is_file()
    artifacts = {
        key: _optional_json(run / "artifacts" / name) for key, name in _ARTIFACTS.items()
    }
    candidates = _candidates(run, artifacts)
    verdicts = _verdicts(artifacts)
    verdict_by_id = {str(item.get("candidate_id")): item for item in verdicts}
    top = candidates if limit <= 0 else candidates[:limit]
    evidence_count = len(list((run / "evidence").glob("*.json")))
    decision_count = len(list((run / "decisions").glob("*.json")))

    rootfs = artifacts.get("rootfs") or {}
    binaries = artifacts.get("binaries") or {}
    surfaces = artifacts.get("surfaces") or {}
    completed = set(state.get("completed_stages", []) or [])
    plan_stages = (
        (state.get("plan") or {}).get("stages", [])
        if isinstance(state.get("plan"), dict)
        else []
    )
    pending = [
        stage
        for stage in plan_stages
        if stage not in completed and stage not in {"INIT", "DONE"}
    ]

    title = "运行快照报告" if final else "中断快照报告"
    banner = (
        "> 运行已完成。本快照只汇总已有产物；最终结论以 report.md / "
        "final_verdict.json 为准。"
        if final
        else "> 本报告只汇总中断时已经落盘的产物。未完成的阶段没有执行，"
        "**不能视为最终结论，也不能据此确认或否定漏洞**。"
    )
    lines: list[str] = [
        f"# {title} — {run.name}",
        "",
        banner,
        "",
        "## 1. 运行状态",
        "",
        f"- status：{state.get('status', 'unknown')}",
        f"- current_stage：{state.get('current_stage', 'unknown')}",
        f"- completed_stages：{', '.join(sorted(completed)) or '无'}",
        f"- failed_stages：{', '.join(state.get('failed_stages', []) or []) or '无'}",
        f"- 尚未完成：{', '.join(pending) or '无'}",
        f"- started_at：{state.get('started_at', 'unknown')}；"
        f"updated_at：{state.get('updated_at', 'unknown')}",
        "",
        "## 2. 输入与解包",
        "",
        f"- firmware_path：{task.get('firmware_path', 'unknown')}",
        f"- firmware_sha256：{rootfs.get('firmware_sha256', 'unknown')}",
        f"- rootfs 状态：{rootfs.get('status', '未落盘')}；"
        f"解包方式：{rootfs.get('unpack_method', 'unknown')}；"
        f"置信度：{rootfs.get('extraction_confidence', 'unknown')}",
        "",
        "## 3. 攻击面与二进制",
        "",
        f"- 攻击面：{len(surfaces.get('surfaces', []) or [])}",
        f"- ELF 二进制：{len(binaries.get('summaries', []) or [])}",
        f"- 静态候选：{len((artifacts.get('candidates') or {}).get('candidates', []) or [])}",
        "",
        "## 4. 候选与排序",
        "",
    ]
    if not candidates:
        lines.extend(["尚无候选产物（STATIC_ANALYSIS / RANK 可能未完成）。", ""])
    else:
        lines.append(f"共 {len(candidates)} 个候选；下表显示前 {len(top)} 个。")
        lines.extend(
            [
                "",
                "| 候选 | 类型 | 分数/等级 | 二进制 | Source → Sink | 调用链 | 结论 |",
                "|---|---|---|---|---|---|---|",
            ]
        )
        for candidate in top:
            verdict = verdict_by_id.get(str(candidate.get("candidate_id")), {})
            conclusion = verdict.get("action") or candidate.get("conclusion_category") or "未裁决"
            lines.append(
                "| "
                + " | ".join(
                    [
                        _cell(candidate.get("candidate_id")),
                        _cell(candidate.get("vuln_class_hypothesis")),
                        _cell(
                            f"{candidate.get('risk_score', '?')} / "
                            f"{candidate.get('risk_level', '?')}"
                        ),
                        _cell(candidate.get("binary_id")),
                        _cell(f"{_source_label(candidate)} → {_sink_label(candidate)}"),
                        _cell(_chain_label(candidate)),
                        _cell(conclusion),
                    ]
                )
                + " |"
            )
        lines.append("")

    lines.extend(["## 5. 反证验证", ""])
    if not verdicts:
        lines.extend(
            [
                "verdict.json 尚未生成：**VERIFY_TOP_K 未完成**，"
                "上述候选均未经过最终反证审查，不能声明为确认漏洞。",
                "",
            ]
        )
    else:
        lines.append(f"已审查 {len(verdicts)} 个候选：")
        lines.extend(["", "| 候选 | 动作 | 原分 → 修正分 | 原因 |", "|---|---|---|---|"])
        for verdict in verdicts:
            lines.append(
                "| "
                + " | ".join(
                    [
                        _cell(verdict.get("candidate_id")),
                        _cell(verdict.get("action")),
                        _cell(
                            f"{verdict.get('original_score', '?')} → "
                            f"{verdict.get('revised_score', '?')}"
                        ),
                        _cell("；".join(verdict.get("reasons", []) or [])),
                    ]
                )
                + " |"
            )
        lines.append("")

    lines.extend(["## 6. Agent 自主分析轨迹", ""])
    lines.extend(_agent_section(artifacts.get("agent_trace") or {}))

    lines.extend(
        [
            "## 7. 证据与决策",
            "",
            f"- 证据文件：{evidence_count}",
            f"- 决策文件：{decision_count}",
            "",
            "## 8. 缺失产物与限制",
            "",
        ]
    )
    missing: list[str] = []
    if not verdicts:
        missing.append("verdict.json 缺失：反证验证未完成。")
    if not (run / "report.md").is_file():
        missing.append("report.md 缺失：完整 REPORT 阶段未完成。")
    if not (run / "final_verdict.json").is_file():
        missing.append("final_verdict.json 缺失：最终裁决未生成。")
    if not artifacts.get("local_validation"):
        missing.append("local_validation.json 缺失：本地动态验证未执行或未落盘。")
    if not (run / "artifacts" / "external_findings" / "all.json").is_file():
        missing.append("外部分析器结果缺失：EXTERNAL_ANALYSIS/FUSION 未完成或未启用。")
    lines.extend(f"- {item}" for item in (missing or ["未发现关键产物缺失。"]))
    recovery = (
        "运行已完成，无需恢复。"
        if final
        else f"恢复分析：fsa resume {run.name}"
    )
    conclusion = (
        "本快照是运行完成后的摘要；最终结论以 report.md / final_verdict.json 为准。"
        if final
        else "本快照不是最终报告。它只汇总中断时已有的候选、证据和 Agent 轨迹；"
        "未完成的阶段没有执行，不能据此确认或否定漏洞。完成 fsa resume 后，"
        "以最终 report.md / final_verdict.json 为准。"
    )
    lines.extend(
        [
            "",
            recovery,
            "",
            "## 9. 结论边界",
            "",
            conclusion,
            "",
        ]
    )

    text = "\n".join(lines)
    _sanitized, safe = sanitize_poc(text)
    if not safe:
        return {
            "status": "failed",
            "reason": "snapshot report compliance gate rejected dangerous payload content",
        }

    target = Path(output_path) if output_path else run / "report.partial.md"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    return {
        "status": "ok",
        "run_id": run.name,
        "report": str(target),
        "run_status": state.get("status", "unknown"),
        "current_stage": state.get("current_stage", "unknown"),
        "candidate_count": len(candidates),
        "verdict_count": len(verdicts),
        "agent_steps": len((artifacts.get("agent_trace") or {}).get("steps", []) or []),
        "final": final,
    }
