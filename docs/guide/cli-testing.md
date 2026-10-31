# CLI 自测方案

> 目的：在交付/演示前证明 CLI **可运行、可解释、可降级**，并说清哪些能力依赖真实环境
> （Docker、KLEE、仿真目标、模型网关）。全部命令在项目根目录、已激活 venv 的 Linux shell 中执行。

## 1. 环境自检

```bash
fsa doctor --json-output
fsa doctor --include-external-probes --json-output
```

通过标准：

- `paths.status=ok`、`schemas.status=ok`
- `runtime.default=offline` 时允许完全离线测试；要用在线模型时再确认 `model_api_key_present=true`
- 外部工具缺失时状态为 `degraded`，命令退出码保持 0

## 2. 任务理解

```bash
fsa plan \
  --task "分析厂商为 Tenda、型号 AC15 的固件，授权测试，完整分析。" \
  --firmware-path firmware_samples/AC15.bin \
  --authorization-holder team1 \
  --json-output
```

通过标准：

- 输出 `status=ok`
- 能抽出或保留 `vendor / model / version / depth`（JSON 现在直接暴露前三个字段）
- `depth=full` 时 `stages` 包含 `EXTERNAL_ANALYSIS / FUSION / SYMEX_PRUNE / CONSTRAINED_VALIDATION`
- 缺授权或缺固件时输出 `requires_human_gate=true` 并列出原因，**不会**伪造继续执行
- `--firmware-path` 指向不存在的文件是硬错误（退出码 1）；只有“缺少槽位”才进入 human gate

## 3. 冒烟（走正式 CLI 入口）

```bash
make smoke
```

通过标准：

- 内部实际调用 `fsa analyze`
- 运行目录为 `runs/dev-smoke-*`
- `state/run_state.json` 中 `status=done`
- 生成 `report.md`、`final_verdict.json`、`artifacts/report_compliance.json`

## 4. 真实固件

已解包 rootfs：

```bash
fsa analyze <ROOTFS_DIR> \
  --input-type rootfs \
  --depth standard \
  --authorization-holder "<授权人或团队名>" \
  --vendor "<厂商>" --model "<型号>" \
  --json-output
```

固件镜像（需要可用的 binwalk/sasquatch）：

```bash
fsa analyze <FIRMWARE_BIN_OR_CHK> \
  --input-type firmware \
  --depth standard \
  --authorization-holder "<授权人或团队名>" \
  --json-output
```

通过标准：

- 主链 `status=done`
- `artifacts/rootfs.json` 记录输入类型、rootfs 来源、解包方式/评分/置信度，以及
  `rootfs_candidates` / `rootfs_duplicates_suppressed` / `unpack_degraded`
- `artifacts/` 下依次出现 `firmware_baseline.json`、`binary_summaries.json`、`candidates.json`、
  `ranking.json`、`verdict.json`
- 报告「外部分析器结果」一节写清缺哪些工具、哪些结论因此受限，**不写假命中**；
  KLEE/BOND 在后续阶段写出的 `klee.json` / `bond.json` 也会合并计入，不显示为 0
- 报告第 14 节列出 Top 候选的二进制/入口、Source→Sink、调用链/认证/证据/裁决；
  第 15 节列出 reviewed/unreviewed 覆盖与排除理由；第 21 节写明反编译 fallback、
  架构与调用链能力、候选可追溯性，以及 accepted=0 的证据边界

实时进度的可验证行为：

```bash
fsa analyze <ROOTFS_DIR> --input-type rootfs \
  --authorization-holder "<授权人>" --progress 2>progress.log
cat progress.log            # 含 [n/total] STAGE 开始行与 ok/degraded 结束行
```

- `--progress` 只写 stderr；`--json-output` 的 stdout 仍可被 `jq` 解析
- `--no-progress` 输出中不出现阶段进度行
- 阶段耗时与状态来自引擎实际执行结果，不是预估
- 加 `--agent` 时，`progress.log` 里应出现 `agent step N/<max> · <candidate> · <action>`
  （每 `--agent-progress-every` 步一条，重定向时每秒最多一条）
- `--agent-show-tokens` 时明细含 `tok <used>/<limit>` 与 `calls <used>/<limit>`；
  `--no-agent-show-tokens` 时两者都不出现
- 终端里明细按宽度自动换行成普通行，状态行只有一行；明细长度超过终端宽度时
  状态行保持单行，明细按终端宽度换行
- `--progress-interval 0.2` 只改变刷新频率，不改变阶段结果
- `--agent-print-model` 只在模型实际参与动作选择时输出经过校验的
  `model chose <action> (confidence ...): <reason>`；默认关闭，且不输出原始 prompt/回复

## 4.1 中断/续跑判定

```bash
# 正常续跑
fsa resume <run_id>
# 回退到指定阶段重跑
fsa resume <run_id> --from-stage AGENT_LOOP
```

通过标准：

- `state/run.lock` 被另一个进程持有时，`fsa resume` 拒绝执行并报出持有者 pid
- 进程被 kill 后（锁已由内核释放），即使 `run_state.json` 仍是 `status=running`，
  `fsa resume --from-stage ...` 也应成功，不需要 `--force`
- 回退前生成 `state/run_state.rewind-*.json` 备份，`metadata.last_rewind.stale_running=true`

## 5. Full Depth 降级

```bash
fsa analyze <ROOTFS_DIR> --input-type rootfs --depth full \
  --authorization-holder "<授权人或团队名>" --json-output
```

通过标准（四器默认全关的情况下）：

- 仍然 `status=done`
- `artifacts/external_findings/` 存在，或阶段产物记录 `skipped/degraded` 与 `limitation`
- FirmRec 的结果不进入 `unified_candidates.json`
- 候选带上 `poc_sanitized=true` 的证据后才进入确认流程

## 5.1 Ghidra / busybox（可选）

```bash
# 写在本地 .env（gitignore）
cat >> .env <<'EOF'
GHIDRA_HEADLESS=/opt/ghidra/support/analyzeHeadless
BUSYBOX_BIN=/usr/bin/busybox
EOF

fsa doctor --json-output   # 看 checks.decompile.ghidra_headless

# 最小固件 rootfs，跑 Ghidra + 本机 busybox 加载检查
fsa analyze firmware_samples/firmhound-lab-0.1.0/rootfs \
  --input-type rootfs --authorization-holder "local-lab" \
  --depth full --allow-emulation --run-id lab-ghidra --no-agent

jq '.status, .backend, .analyzed_binaries' runs/lab-ghidra/artifacts/decompile.json
jq '.loader, .load_ok, .limitation' runs/lab-ghidra/artifacts/local_validation.json
grep -A20 '## 14' runs/lab-ghidra/report.md
```

通过标准：

- `decompile.json` 为 `status=ok`、`backend=ghidra`，至少一个二进制有 `functions`；
- 报告第 14 节对 `QUERY_STRING → system` 等候选显示 2 层调用链；
- `local_validation.json` 在 x86_64 本机为 `loader=native`、`load_ok=true`；
- 找不到 Ghidra 时 `decompile.json` 为 `degraded` + fallback，报告第 21 节说明原因，不阻断运行。

DIR-825 这类 MIPS 固件需要 rootfs 自带 `bin/busybox` + `qemu-mips-static`；Ghidra 会对 top-N
中的 httpd 等二进制导出 callgraph，报告第 21 节会写明哪些架构仍无链、哪些只是加载检查。

## 6. 打开真实外部工具

逐个打开 `config/dev.yaml` 的 `external.enabled` 与对应工具开关，**一次只开一个**，
排查干净再开下一个：

| 工具 | 依赖 | 备注 |
|---|---|---|
| SaTC | Docker 镜像、Ghidra/angr | 需要一个 Web 固件 rootfs |
| KLEE | `backend: local`（LLVM 16 + Z3）或 `docker` | 无源码时走 S2 harness |
| BOND | 隔离仿真目标 | 必须私有网段 IP + 授权 + baseline + 无害 marker |
| FirmRec | Docker + PostgreSQL + 已知漏洞签名 | 仅复发专项，Blind Run 必须关闭 |

通过标准：

- 可用时 `status=ok`，不可用时 `degraded/skipped` + 明确 `limitation`
- 所有 PoC/请求证据均已脱敏，不出现真实攻击载荷

## 7. 测试前需要准备

- 至少 1 个有授权分析的真实固件文件，或已解包的 rootfs 目录
- 厂商 / 型号 / 版本（不知道可留空）
- 授权说明：自有设备、实验室授权、公开固件离线分析等
- 是否允许本地隔离仿真；允许则给出仿真目标私有 IP、端口、无害 marker
- 若测在线模型：网关地址、API key 环境变量名、模型名、调用规范
- 若测 FirmRec：已知漏洞签名来源，并确认属于复发检测专项（不计入零先验指标）

## 8. 验收对照

| 关注点 | 怎么证明 |
|---|---|
| 任务理解与执行设计 | `fsa plan` 展示自然语言/压缩包 → 任务卡与阶段计划 |
| 可部署、可运行、可恢复 | `doctor` → `smoke` → `analyze` → `status` / `resume` |
| 决策逻辑与可解释性 | `decisions/`、`evidence/`、`fsa explain <run-id>`、`report.md` |
| 工具协同与扩展 | `--depth full` 展示四器开关、汇聚与降级 |
| 附加价值的数据支撑 | 真实固件 run 的 External-Only Hits、FP Prune Rate、Confirm Uplift |
