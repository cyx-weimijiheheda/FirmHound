# 受控自主执行（AGENT_LOOP）

`AGENT_LOOP` 是 `RANK` 与 `VERIFY_TOP_K` 之间的一个**可选**阶段。它只做一件事：
针对候选的 `decisive_missing_fact`，从封闭动作目录中选择下一步取证动作，把事实
补齐后再交给反证验证。

它是一个**有界 Agent**：模型只在规则筛出的合法动作里排序/选择；工具名、路径、参数、
shell 命令和漏洞结论都由代码产生，所有写入位置固定。

## 启用

```bash
# 单次运行
fsa analyze <rootfs> --input-type rootfs \
  --authorization-holder "设备所有者" --agent --run-id hunt-agent

# 只查看计划
fsa plan --firmware-path <rootfs> --authorization-holder "设备所有者" --agent --json-output
```

或在 `config/dev.yaml`：

```yaml
agent:
  enabled: true
  tier: standard
```

默认关闭。`--no-agent` 可覆盖配置。Blind Run（`--blind`）无论配置如何都强制禁用。

## 动作 tier

| tier | 动作 | 前置条件 |
|---|---|---|
| `standard`（默认） | 调用链恢复、imports/strings 核对、startup 检查、证据引用核对、auth 解析、handler 映射 | 只读已有 rootfs/artifacts，无网络、无仿真 |
| `dynamic` | `qemu_load_check`（L1 加载检查） | `--agent-tier dynamic`、`--allow-emulation`、`agent.dynamic.enabled=true`；只允许私网/本机 |
| `external` | `klee_feasibility`（只消费已有 symex） | `--agent-tier external`、`external.enabled=true`、`agent.external.klee.enabled=true` |

tier 不满足时自动降级到 `standard`，并在 trace/报告的 limitations 中说明。
v1 不在 loop 内运行 BOND；BOND 仍在 `CONSTRAINED_VALIDATION` 阶段。

## 预算

| 参数 | 默认 | 含义 |
|---|---|---|
| `agent.max_candidates` | 10 | 最多检查多少个候选 |
| `agent.max_steps` | 20 | 全局动作步数 |
| `agent.max_steps_per_candidate` | 4 | 单候选动作步数 |
| `agent.max_tool_calls` | 40 | 工具调用上限 |
| `agent.max_seconds` | 120 | 墙钟上限 |
| `agent.no_progress_limit` | 2 | 连续无进步后停滞该候选 |
| `agent.max_action_failures` | 3 | 连续失败后停滞该候选 |

候选按轮次轮转；同一轮优先处理 `risk_score` 较高者。单候选的每轮动作数、全局
步数、工具调用数和墙钟时间仍受上表预算限制。预算用尽但仍有待查事实时，候选
状态会标为 `degraded`，不会被误记成已解决。

对应 CLI 参数：`--agent-max-candidates`、`--agent-max-steps`、
`--agent-max-steps-per-candidate`、`--agent-max-tool-calls`、
`--agent-max-seconds`、`--agent-no-progress-limit`。

## 进度显示

`AGENT_LOOP` 默认每 10 步向 stderr 输出一条明细。终端里明细按内容自动换行，
底部只保留一行原地刷新的状态行：

```text
[5/12] AGENT_LOOP  agent step 123/5000 · cand-c32784f3ddeb ·
  cross_check_imports_strings · selector=model · tok 12400/2000000 ·
  calls 45/2000 · ev 515 · missing 2 · resolved 8/484 · skipped 12
[5/12] AGENT_LOOP  running  42.1s
```

长明细不会再写进刷新行，因此不会出现换行后反复覆盖、把终端刷满的问题。

| 参数 | 默认 | 作用 |
|---|---|---|
| `--progress-interval` | `0.5` | 终端刷新间隔（秒） |
| `--agent-progress-every` | `10` | 每 N 步汇报一次 |
| `--agent-show-tokens` / `--no-agent-show-tokens` | 显示 | token 与模型调用计数 |
| `--agent-print-model` / `--no-agent-print-model` | 关闭 | 打印已校验的模型选择（动作/置信度/理由） |

```bash
fsa analyze <rootfs> --authorization-holder "设备所有者" --agent --progress \
  --progress-interval 0.2 --agent-progress-every 25 \
  --agent-show-tokens --agent-print-model
```

- 进度只写 stderr；`--json-output` 的 stdout 不受影响。
- `--agent-print-model` 不打印原始 prompt、原始回复、思维链或候选正文；只打印
  `parse_model_choice` 校验后的动作、置信度和截断理由。
- 这些设置也可写在 `config/dev.yaml` 的 `agent.progress`；`resume` 时 CLI 参数会
  覆盖并持久化到该 run 的 task card。
- 重定向/CI 下不刷新单行计时，只输出阶段开始/结束行和每秒最多一条 Agent 明细。

## AI 服务配置

模型服务分三层配置：

| 内容 | 文件 |
|---|---|
| 服务地址、模型名、超时、密钥环境变量名 | `config/models.yaml` 的 `runtimes.openai_compatible` |
| 实际密钥 | 项目根 `.env`，变量名由 `api_key_env` 指定（默认 `OPENAI_API_KEY`） |
| 是否启用、用哪个 runtime、Agent 预算 | `config/dev.yaml`：`runtime.default` / `agent.runtime` / `agent.model.*` |

```yaml
# config/models.yaml
runtimes:
  openai_compatible:
    provider: openai
    base_url: https://api.deepseek.com/v1   # 本地端点可写 http://127.0.0.1:11434/v1
    model: deepseek-chat
    timeout: 60
    max_retries: 3
    api_key_env: OPENAI_API_KEY
```

```bash
# 项目根目录 .env（本地文件，已 gitignore）
OPENAI_API_KEY=sk-xxx
```

```yaml
# config/dev.yaml
runtime:
  default: openai_compatible      # 全局默认 runtime
agent:
  runtime: ""                     # 空 -> runtime.default；也可单独指定
  model:
    enabled: auto                 # auto | true | false
    max_calls: 8
    max_tokens: 4000
    allow_public: false
```

注意：

- `offline` / `mock` runtime 不调用模型，`AGENT_LOOP` 自动走规则选择。
- 远程 endpoint 除 `agent.model.allow_public: true` 外，还必须把主机名加入
  `config/safety.yaml` 的 `network.allowed_hosts`；`127.0.0.1` / `localhost` 不需要。
- `load_runtime()` 读取仓库根目录的 `config/models.yaml`；`paths.models` 目前只用于
  `doctor`，不随 `--config` 切换。自定义配置时请改仓库根的同名文件。
- `.env` 不提交；`.env.example` 只是模板。
- `config/dev.yaml` / `models.yaml` / `safety.yaml` 是本地配置，已被 `.gitignore` 忽略；
  `make dev` 会从 `config/*.example.yaml` 复制。缺失时代码也会自动回退到 example。

## 模型参与

默认 `agent.model.enabled: auto`：

- runtime 是 `offline` 时，不调用模型，规则选择；
- runtime 是 `openai_compatible` 时，模型只在 2–4 个合法动作里选一个；
- 模型输出必须是严格 JSON：`{action_id, reason, confidence}`；
- 未知动作、额外字段、markdown 围栏、越界 confidence、网络/主机策略拒绝、
  超时或异常 → 自动回退规则选择。

远程 endpoint 需要同时在 `config/safety.yaml` 的 `network.allowed_hosts` 中显式
列出，并设置 `agent.model.allow_public: true`。本地 OpenAI-compatible 端点
（如 `http://127.0.0.1:.../v1`）不需要放开公网。

## 产物

- `runs/<id>/artifacts/agent_trace.json`：通过 `agent_trace.schema.json` 校验；
  记录候选、动作、选择者、证据 ID、预算、停止原因、limitations。
- `runs/<id>/artifacts/agent_execution.html`：自包含的交互式执行路径图。按真实顺序
  展示候选、规则允许的动作、实际选择、选择来源、结果、证据和待查事实；可按候选
  筛选并打开步骤详情。虚线灰色节点是合法备选；执行记录以实线步骤为准。页面无外部资源，
  可离线打开；分析中每一步完成后会更新。
- `runs/<id>/artifacts/ranking.json`：enrich 后重新评分排序。
- `runs/<id>/evidence/ev-*.json`：`stage=AGENT_LOOP` 的确定性事实。
- `runs/<id>/decisions/dec-*.json`：`actor=model|rule` 的动作选择记录。
- `report.md` 第 24 节「自主分析轨迹」：提供执行路径图链接，只渲染计数和结论边界，
  不渲染模型原文。
- 中断或仍在运行时，可用 `fsa report <run-id>` 生成 `report.partial.md` 快照；
  它只读已有产物，不跑分析、验证或模型。

## 安全边界

- 动作只能读取 run artifacts/rootfs，所有路径先过 `PolicyEngine.check_path`；
- 模型只看到有界候选摘要，不发送固件内容、证据正文或 PoC；
- 候选字符串按不可信输入处理，命中 `config/safety.yaml::model.forbidden_requests`
  时直接回退规则；
- Agent 不允许修改 `conclusion_category`、`status`、`risk_level`；最终结论仍由
  `VERIFY_TOP_K` 产生；
- Blind Run 强制禁用，避免模型先验泄漏。

## 失败语义

| 情况 | 行为 |
|---|---|
| 无 `ranking.json` / 无候选 | `skipped` + limitation |
| 动作前置条件不满足 | 不选择；无动作时 `skipped` |
| 调用链架构不支持 | `degraded` + limitation，不伪造 |
| 模型失败 / 预算耗尽 | 回退规则或停止，trace 记录原因 |
| 悬空证据引用 | 移除并记入 `evidence_unresolved` |
| Agent 阶段失败 | `required=False`，主流程继续到 VERIFY/REPORT |
