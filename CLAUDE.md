# CLAUDE.md

FirmHound（固件猎犬）——IoT 固件漏洞挖掘自动化流水线：`解包 → 攻击面 → 二进制分析 → 静态审计 → 十维评分 → 反证验证 → 动态验证 → 报告`。
所有约束以 **`AGENTS.md` 为准**（本文件与其同步维护）；这里是快速上手与导航。

## 快速上手

```bash
make dev                         # 建 .venv + 装依赖 + editable 安装
make doctor                      # 环境自检
make test                        # 单元测试（462 passed / 1 skipped 为当前基线）
make lint                        # ruff（版本按 requirements.txt）

fsa analyze tmp/unpacked/x/squashfs-root --input-type rootfs \
  --authorization-holder "设备所有者" --depth standard --run-id hunt1
```

- 只支持 **Linux 原生**；不要加 Windows/WSL 兼容代码。
- Python 3.11–3.13；3.14 暂不支持（PyO3 依赖要求 ≤ 3.13）。
- `--depth`：`quick`（10 阶段）/ `standard`（主轨 11 阶段）/ `full`（含四个外部分析器，16 阶段）。
- `--agent` 可选插入 `AGENT_LOOP`（RANK 后、VERIFY 前）；默认关闭，Blind 强制禁用。

## 代码地图

| 想改什么 | 去哪个文件 |
|---|---|
| CLI 子命令、参数、输出 | `fsa/cli.py` |
| 阶段顺序、降级/中止 | `fsa/orchestrator/engine.py`（`Stage` + `TRANSITIONS`） |
| 深度档位、阶段绑定的工具与参数 | `fsa/orchestrator/planner.py`（`build_plan` 的 `stage_configs`） |
| 任务卡解析（自然语言 / zip） | `fsa/orchestrator/planner.py` |
| 断点续跑、状态落盘 | `fsa/orchestrator/state_manager.py` |
| 10 问反证、五分类裁决 | `fsa/orchestrator/verifier.py` |
| 受控自主执行循环、动作目录、模型排序 | `fsa/orchestrator/agent_loop.py` / `agent_catalog.py` / `agent_model.py` |
| 确定性 Agent 动作实现 | `tools/audit/agent_actions.py` |
| 安全红线 | `fsa/safety/policy_engine.py` + `config/safety.yaml` |
| 工具注册（YAML → 动态调用） | `tools/registry/*.yaml` + `fsa/runtime/tool_registry.py` |
| 解包策略、magic carving | `tools/firmware/unpack.py` |
| 攻击面、认证矩阵 | `tools/web/*` |
| ELF 画像、危险函数分级 | `tools/binary/*` |
| source/sink 规则、十维评分、误报过滤 | `tools/analysis/*` |
| 候选生成（阶段入口） | `tools/audit/static.py` |
| 报告 24 节骨架、证据账本、中断快照 | `tools/report/*`（`generate.py` / `partial.py`） |
| 外部分析器（SaTC/FirmRec/KLEE/BOND） | `tools/external/*` |
| 跨阶段数据契约 | `schemas/*.schema.json` |

运行产物：`runs/<run_id>/{state,evidence,decisions,artifacts}/` + `report.md`。
证据与决策**一条一个 JSON 文件**，便于单条引用与反证。

## 五条最容易踩的坑

1. **工具必须返回带 `status` 的 dict**。抛异常会被兜底成 `error`，`required` 阶段直接 ABORTED。
2. **改 Schema 必须同步 `schemas/examples/`**，否则 `fsa doctor`、单测、CI 全红。
3. **不要绕过 PolicyEngine**：路径必须先 `check_path`，动态验证只允许私网，PoC 出栈前过 `sanitize_poc`。
4. **不允许编造结论**：缺工具/超时 → `degraded|skipped` + `limitation`，不要补"看起来合理"的结果。
5. **解析外部工具输出要固定 `LC_ALL=C`**（`run_command(..., env={"LC_ALL": "C"})`）；
   中文 locale 下 `readelf` 的字段名会被本地化，曾导致架构识别静默退化成 `unknown`。

## 提交约定

- 提交前跑 `make lint && make test && make doctor`，三项干净再提交。
- **commit message 禁止 agent 署名**：不加 `Co-Authored-By: Claude` 等共同作者行，不写
  `Generated with ...`、`🤖`、工具名或模型名尾注；作者用本机配置的开发者身份，不加 `--author`。
- 提交信息前缀：`feat: / fix: / docs: / refactor: / test:`。

## 测试约定

- 用 `tests/fixtures/elf_builder.py` 合成 ELF，不依赖真实固件/容器/Ghidra。
- 新增分析逻辑：纯函数放 `tools/`，配 `tests/unit/test_*.py`；阶段入口只做 IO 与编排。
- 集成测试在 `tests/integration/`，缺宿主工具时自动 skip，不要为了让它跑而放松断言。
