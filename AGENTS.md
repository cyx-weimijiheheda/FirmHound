# AGENTS.md — 工程约定（给所有 AI 代理 / 协作者）

FirmHound（固件猎犬）：IoT 固件漏洞挖掘自动化流水线。本文件只写约束，不写介绍；
背景与用法见 `README.md`，架构细节见 `docs/`。`CLAUDE.md` 与本文件必须同步修改。

## 0. 环境前提

- **运行与测试目标为 Linux 原生、跨发行版**（Debian/Ubuntu、Fedora/RHEL、Arch、openSUSE、
  Alpine 容器均需可用）。路径处理、脚本和文档都按这一目标实现。
- 安装文档按发行版并列给出 `apt` / `dnf` / `pacman` / `zypper` 命令，或指向
  `README.md` 的依赖矩阵。
- Python 3.11–3.13（上限由 PyO3 依赖决定，3.14 暂不支持）；项目依赖统一装进 `.venv`。
  入口是 `make`：`make dev` 建环境并 editable 安装，其余目标都走 `.venv/bin/python`。
- 解包与动态验证依赖系统工具：`binwalk`、`unsquashfs`、`sasquatch`、`qemu-*`。
  工具缺失时返回 `degraded/skipped` + `limitation`，主链路继续运行。

## 1. 常用命令

```bash
make dev        # 建 .venv + 装依赖 + editable 安装
make doctor     # 环境自检（发行版 / 路径 / Schema / 工具）
make test       # 单元测试（CI 主门）
make test-all   # 单元 + 宿主集成（缺工具自动 skip）
make lint       # ruff
make smoke      # 走正式 CLI 的最小冒烟

# 等价的手动写法：.venv/bin/python scripts/dev.py <test|lint|smoke>

fsa analyze <firmware|rootfs> --input-type rootfs \
  --authorization-holder "设备所有者" --depth standard --run-id hunt1
fsa explain <run-id> --format markdown
fsa status <run-id> ; fsa resume <run-id>
fsa resume <run-id> --from-stage REPORT   # 已完成的 run 也可回退重跑某阶段及后续
```

## 2. 代码结构与职责边界

| 路径 | 职责 | 实现要求 |
|---|---|---|
| `fsa/cli.py` | click 命令组，负责参数解析与结果输出 | 业务逻辑放在 orchestrator/tools |
| `fsa/orchestrator/` | 阶段机、任务卡、状态持久化、反证审查、受控 Agent 循环 | 通过 ToolRegistry 调用系统工具 |
| `fsa/runtime/` | 运行时适配（offline / openai_compatible）、工具注册表、Skill 加载 | 模型输出必须经过校验与回退 |
| `tools/` | 确定性分析工具（纯函数优先，可单测） | 流程编排放在 orchestrator |
| `schemas/` | 跨阶段数据契约 | 所有产物先过 Schema 校验 |
| `config/` | `dev.yaml` / `models.yaml` / `safety.yaml` | 路径与密钥从配置/环境读取 |
| `skills/` | 领域知识与执行契约（给模型/人看） | 可执行逻辑放在代码 |

新增分析能力时：先定 Schema → 写 `tools/<domain>/` 的纯函数 → 在 `tools/registry/*.yaml`
注册 → 由 `Planner.build_plan` 的 `stage_configs` 绑定到阶段；`engine.py` 保持通用阶段机。

## 3. 工程硬约束

1. **状态契约**：每个被注册的工具返回 dict，并带 `status ∈ {ok, degraded, failed, partial, skipped}`
   （失败时为 `failed/unsafe`）。引擎据此继续 / 回退 / 中止，见 `fsa/orchestrator/engine.py::_execute_stage`。
   失败通过 `status` 表达；异常由调用方兜底为 `error`。
2. **Schema 先行**：跨阶段产物先过 `schemas/*.schema.json` 校验；改 Schema 时同步
   `schemas/examples/`，让 `fsa doctor` 与 CI 保持一致。
3. **安全红线**：`config/safety.yaml` 的路径白名单、命令黑名单、私网限制是硬边界。
   所有文件路径先过 `PolicyEngine.check_path`；动态验证目标限定私网 IP；
   任何 PoC 出栈前过 `tools/external/bond/sanitize.py::sanitize_poc`。
4. **证据先行**：缺工具、缺数据、超时返回 `degraded/skipped/partial` 并写 `limitation`。
   结论、反编译结果和验证结果都由可复核证据支撑。
5. **证据可追溯**：结论指回 `evidence/ev-*.json`；候选带 `counterevidence`
   与 `decisive_missing_fact`。新增判断逻辑时同时写反证和加分证据。
6. **Agent 边界**：`AGENT_LOOP` 默认关闭；Blind Run 强制禁用；模型只在规则筛选出的
   合法动作里排序/选择；工具名、路径、参数和漏洞结论由代码与验证器产生；Agent 动作只写
   事实字段，`conclusion_category` / `status` / `risk_level` 由反证验证阶段产生。
7. **幂等与续跑**：阶段产物写到 `runs/<run_id>/artifacts/`，已存在则覆盖为最新且可重复执行；
   中断后 `fsa resume` 从第一个未完成阶段继续；`--from-stage` 回退前备份
   `run_state.json`，回退只影响目标阶段及其后续。

## 4. 改动守则

- 修 bug 先写/改测试；`tests/unit` 保持全绿，`ruff check fsa tools scripts tests` 保持无告警。
- 测试使用 `tests/fixtures/elf_builder.py` 合成 ELF，保持对真实固件、Docker、KLEE、Ghidra 的独立。
- 日志统一用 `structlog`（JSONL）；`scripts/` 下的命令行脚本可以直接输出。
- 外部工具调用统一经 `fsa/utils/proc.run_command`（返回结构化结果、带超时、可注入 `env`）；
  解析工具输出时把 locale 固定为 `LC_ALL=C`，避免中文环境本地化字段名。
- 文档与代码同步：改阶段、Schema、配置项或安全边界时，同时更新 `README.md` 与相关 `docs/`。

## 5. 提交前检查

```bash
make lint
make test
make doctor
```

三项通过后提交。提交信息用 `feat: / fix: / docs: / refactor: / test:` 前缀。

**commit message 使用本机开发者身份和变更摘要**：

- 正文写改了什么、为什么改；
- 作者信息使用本机 git 配置；
- 需要说明来源时写内容本身。
