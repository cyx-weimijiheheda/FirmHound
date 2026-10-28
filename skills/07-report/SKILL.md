---
id: 07-report
title: 漏洞分析报告生成
tags: [report, verdict, compliance, m10, redaction]
---

# Skill 07：漏洞分析报告生成（report.md + final_verdict.json）

## 目标

把整条流水线的产物（candidate / verdict / 证据 / 决策）汇集成**双产物**：

- `report.md` — 人类可读，交付 / 复核用；
- `final_verdict.json` — 机器可读，平台判分 / 自动化用。

核心原则：**可解释、可审计、如实、脱敏**。看到 `system`/`strcpy` ≠ 漏洞，报告必须基于证据链，函数命中共现不构成结论；全部 REJECT 时如实输出「未发现强证据」，不强行报漏洞。

## 输入

- `ranking.json` / `candidates.json`（M6 排序结果）
- `verdicts.json`（M7 裁决）
- `evidence` 索引（M9 证据链）
- `decision.json` 条目（决策记录）
- `dynamic_validation.json`（M8，可选）
- `artifacts/external_findings/fused.json`、`recurrence_findings.json`、
  `unified_candidates.json`（外部轨，可选）
- `artifacts/agent_trace.json`（自主分析轨迹，可选）
- `artifacts/decompile.json`、`state/run_state.json`（反编译/证据边界，可选）

## 输出

- `report.md`：固定 24 节章节（与 `tools/report/generate.py::_SECTIONS` 一致）
- `final_verdict.json`：`{run_id, firmware_sha256, findings:[...], stats:{...}}`
- `report.partial.md`：中断快照（`fsa report <run-id>`），只汇总已有产物；不写
  `report.md` / `final_verdict.json`，不把未验证候选说成确认漏洞。

## 报告 24 节固定骨架

1. 执行摘要
2. 任务与授权范围
3. 输入与固件指纹
4. 分析环境
5. 解包与根文件系统
6. 文件系统清单
7. 体系结构与加固概览
8. 启动服务
9. Web 入口
10. 网络与协议攻击面
11. 重点二进制
12. 静态分析方法
13. 漏洞候选总览
14. 风险排序
15. 反证验证结果
16. 误报控制摘要
17. 本地动态验证
18. 外部分析器结果
19. 复发漏洞（FirmRec）
20. 证据链与可追溯性
21. 限制与待验证事实
22. 修复建议
23. 最终结论
24. 自主分析轨迹

各节证据边界：

- 第 4 节如实写明 Agent 模型是否参与、runtime/model/调用次数；未调用模型时明确写“未调用模型”。
- 第 5 节写输入类型、解包方式、rootfs 评分/置信度、重复候选抑制数、degraded。
- 第 14 节给出 Top 10 证据链表：二进制/入口、Source→Sink、调用链、认证、证据/反证/裁决。
- 第 15 节给出裁决表、reviewed/unreviewed 覆盖、排除措辞、孤立裁决 ID。
- 第 18 节合并 all.json 与各工具产物，列缺失/禁用原因；FirmRec 不计入规范化计数。
- 第 20 节写 evidence 引用数 vs 落盘数。
- 第 21 节写反编译 fallback、架构/调用链能力、候选可追溯性、外部器、模型边界、accepted=0 语义。

## 执行流程

1. **结论表述对齐**
   - 五分类：confirmed-issue / high-confidence-candidate / false-positive / unknown / observation。
   - 裁决动作：ACCEPT（采纳）/ DOWNGRADE（降级）/ REJECT（拒绝）/ NEED_DYNAMIC（需动态验证）。
   - `observation` 级条目不进入评分，只入证据索引。

2. **脱敏渲染（强制）**
   - 模板中禁止出现可复现攻击参数，一律替换为占位符：`<USER_INPUT>`、`<BENIGN_MARKER>`。
   - 不出现真实目标 IP、反弹 shell、持久化、下载执行等可武器化内容。

3. **决策摘要硬规则**
   - 报告中展示的是**可审计决策摘要**（options / selected / reason / confidence / actor）。
   - **绝不输出模型隐式思维链原文**；模型 reasoning 只提炼为一句 `reason`（≤200 字）。

4. **合规扫描 8 项（全过才生成报告）**
   - 无真实 IP；无反弹 Shell 特征；无持久化；无下载执行；无破坏性命令；含安全声明；仅标记验证（`touch`/`echo`/`id`）。
   - 外部 PoC 必须 `poc_sanitized == true`；不满足时整条证据拒绝落盘和渲染。
   - 复用 `tools/emulation/probes.detect_dangerous_payload` + `utils/netcheck.is_private_ip`。

5. **如实报告**
   - 全部 REJECT → 结论写「未发现强证据」，并保留反证清单。
   - `NEED_DYNAMIC` 但安全门不过 → 标注 `dynamic_skipped` 及原因，不虚构验证结果。

6. **双产物写出**
   - `report.md` 用固定 24 节模板渲染；`final_verdict.json` 通过 `verdict.schema.json` 校验。

7. **自主分析轨迹**
   - 只渲染计数：候选数、步数、工具调用、新增证据、模型参与/回退、停止原因、未解决候选。
   - 固定写明「模型仅参与动作选择，不参与漏洞结论」。
   - 不渲染模型原始回复、思维链或候选正文；Blind 运行写「强制禁用」。

## 失败降级路径

| 场景 | 行为 |
|---|---|
| 合规扫描不过 | 报告生成失败，输出违规项清单 |
| 无 candidate | 报告如实写「未发现候选」，骨架仍齐全 |
| M8 未运行 | 「本地动态验证」一节标 `dynamic_skipped` + 原因 |
| 证据索引缺失 | 「证据链与可追溯性」一节标「证据索引不完整」，不阻断报告 |
| 外部工具缺失/超时 | 「外部分析器结果」一节写 `degraded` 与 limitation；主报告继续生成 |
| FirmRec 在 Blind Run 被请求 | 强制 `skipped/FORCED_DISABLE`，只报告隔离事实，不渲染已知 CVE 结果 |
| Agent 未启用 / Blind | 第 24 节写「未启用」或「Blind 强制禁用」，不阻断报告 |
| agent_trace 缺失或损坏 | 第 24 节降级说明，不阻断报告 |
| 分析中断 / 仍在运行 | `fsa report <run-id>` 生成 `report.partial.md`，列出未完成阶段与缺失产物 |

## 验收标准

- 对任一 run 生成报告：24 节齐全、8 项合规扫描通过、`final_verdict.json` 通过 Schema 校验。
- 报告中不出现任何可复现攻击参数（脱敏后）。
- 全部 REJECT 场景如实输出「未发现强证据」。
