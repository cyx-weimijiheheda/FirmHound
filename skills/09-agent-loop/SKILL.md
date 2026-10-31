---
id: 09-agent-loop
title: 受控自主执行（有界 Agent Loop）
tags: [agent, evidence, budget, m15, safety]
---

# Skill 09：受控自主执行（AGENT_LOOP）

## 目标

在 `RANK` 和 `VERIFY_TOP_K` 之间增加一个**有界、证据驱动、可回放**的候选循环：
针对候选的 `decisive_missing_fact`，从封闭动作目录里选择下一步取证动作，补齐
`call_chain`、startup、imports/strings、auth、证据引用等事实。

边界：模型只对规则筛出的合法动作排序/选择；不生成工具名、路径、参数或漏洞结论。
默认关闭；`--agent` 或 `agent.enabled=true` 才启用；Blind Run 强制禁用。

## 输入

- `artifacts/ranking.json`（RANK 产物）
- `artifacts/binary_summaries.json`、`artifacts/attack_surface.json`、
  `artifacts/rootfs.json`
- `state/task_card.json`（`agent` 生效配置、授权、blind）
- `evidence/ev-*.json`、`decisions/dec-*.json`（证据与决策账本）
- 可选：`artifacts/unified_candidates.json` 中已有的 KLEE `symex` 结果

## 输出

- `artifacts/agent_trace.json`：有界轨迹，通过 `agent_trace.schema.json` 校验；
  只含计数、动作、证据 ID、limitation，不写原始 prompt/回复/文件内容。
- enrich 后的 `artifacts/ranking.json`；若存在 `unified_candidates.json`，
  按 candidate_id 就地更新匹配项并保留 summary。
- 新增 `evidence/ev-*.json`（`stage=AGENT_LOOP`）与 `decisions/dec-*.json`
  （`actor=model|rule`）。
- `report.md` 第 24 节「自主分析轨迹」。

## 动作目录

| 动作 | tier | 产出事实 | 说明 |
|---|---|---|---|
| `recover_call_chain` | standard | `call_chain_reachable` | ARM32 capstone 调用链；不支持架构降级 |
| `cross_check_imports_strings` | standard | `source_sink_cross_checked` | 核对 source/sink 是否真实出现在 imports/strings |
| `check_handler_startup` | standard | `handler_started` | 优先读 triage 的 startup，缺失才重新解析 |
| `cross_check_evidence_store` | standard | `contradiction_checked` | 解析悬空 evidence ID、发现 contradicts |
| `verify_auth_hint` | standard | `auth_known` | 仅在 auth matrix 置信度 ≥0.75 时写 required |
| `enrich_from_recovered_handlers` | standard | `entry_mapped` | 只在精确匹配时补 handler/surface |
| `qemu_load_check` | dynamic | `dynamic_load_checked` | 需 `--allow-emulation`；只做 L1 加载检查 |
| `klee_feasibility` | external | `symex_feasibility_checked` | 只消费已有 symex；不运行 KLEE、不改结论 |

## 执行流程

1. 读取 `ranking.json`，取前 `max_candidates` 个候选，推导缺失事实。
2. 按 tier、preconditions、缺失事实、预算和路径策略筛出合法动作；最多保留 4 个。
3. 规则先排序；合法动作多于 1 个且模型可用时，模型只在其中选择一个。
4. 执行固定动作实现，写入证据、决策和 trace；动作前后断言
   `conclusion_category` / `status` / `risk_level` 不变。
5. 用签名比较判断是否有进步；连续无进步或连续失败则停滞该候选。
6. 达到步数/工具调用/时间/候选数预算，或无合法动作时停止。
7. 重排 ranking、更新 unified 副本、写出最终 trace。

## 失败降级路径

| 场景 | 行为 |
|---|---|
| Agent 未启用 | 不插入阶段；报告第 24 节写「未启用」 |
| Blind Run | 强制不插入；trace/报告写 `disabled_reason=blind` |
| 缺 ranking / 无候选 | `skipped` + limitation，不阻断 VERIFY/REPORT |
| 动作前置条件不满足 | 不选择该动作；无动作时标记 `skipped` |
| 调用链架构不支持 | `degraded` + limitation，不伪造 call chain |
| 模型不可用 / JSON 不合法 / endpoint 被拒 | 回退规则选择，trace 记录 fallback 原因 |
| 预算耗尽 | 停止循环，写 `stop_reason`，保留已完成证据 |
| 动作试图修改结论字段 | 恢复字段、标记动作失败、写入 trace |
| 悬空证据引用 | 从 evidence 移除并记入 `evidence_unresolved`，绝不伪造 |

## 验收标准

- 默认不启用时阶段列表与报告行为不变；`--agent` 才在 RANK 后插入 `AGENT_LOOP`。
- `agent_trace.json` 通过 Schema 校验，且不包含原始模型文本或固件内容。
- Agent 动作只写事实字段；`conclusion_category` / `status` / `risk_level` 由反证验证阶段产生。
- Blind Run 不产生 Agent 阶段；`--agent --blind` 报告明确写强制禁用。
- 模型失败、预算耗尽、缺工具时均能降级到规则路径并留下 limitation。
