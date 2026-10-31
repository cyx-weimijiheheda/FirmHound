# 外部分析器集成与降级说明

> 本目录三份文档：
>
> | 文档 | 内容 |
> |---|---|
> | **README.md（本文件）** | 编排顺序、开关、能力边界、诚实降级、安全红线 |
> | [`dataset.md`](dataset.md) | L1/L2/L3 样本清单、来源、SHA256、架构 |
> | [`field-testing.md`](field-testing.md) | 真机环境准备与四器逐个跑通 |
>
> 四个工具各自的方法论、命令、配置与踩坑在技能卡里：
> `skills/08-external-analyzers/{satc,firmrec,klee,bond}/SKILL.md`。

## 1. 目标与边界

外部轨补齐跨函数污点追踪、路径可行性判定、约束导向验证和复发漏洞扫描。
它是可选增强，主轨不依赖它。默认配置下 `external.enabled=false`，
CI 与 Blind Benchmark 不下载镜像、不访问网络、不依赖商业软件。

## 2. 固定编排顺序

1. `EXTERNAL_ANALYSIS`：并行运行 SaTC 与 FirmRec；Blind Run 强制跳过 FirmRec。
2. `FUSION`：将 SaTC 与主轨候选按 binary/sink/class 汇聚；FirmRec 独立保存。
3. `SYMEX_PRUNE`：KLEE 回写可达 witness 或不可达 counterevidence。
4. `RANK` / `VERIFY_TOP_K`：仍使用原十维 30 分制与反证规则。
5. `CONSTRAINED_VALIDATION`：mini-BOND 仅对授权仿真环境执行。
6. `REPORT`：在「外部分析器结果」展示交叉验证与限制，在「复发漏洞（FirmRec）」单独展示隔离的复发结论。

## 3. 安装与启用

先在 `config/dev.yaml` 打开总开关，再开启本机具备依赖的工具。CI 配置中
打开重型工具。

```yaml
external:
  enabled: true
  satc:
    enabled: true
  firmrec:
    enabled: false
    backend: auto        # auto | local | docker；推荐本地原生
  klee:
    enabled: true
  bond:
    enabled: false
```

FirmRec 原生后端（不依赖 Docker）的完整安装见
[`../guide/firmrec-native.md`](../guide/firmrec-native.md)：

```bash
FIRMREC_PYTHON=python3.9 python3 scripts/dev.py firmrec-deps   # 独立 .venv-firmrec
make firmrec-doctor                          # 检查 repo/python/Ghidra/PostgreSQL
make firmrec-smoke RUN_DIR=runs/<id>         # 对已有 run 执行
```

本机若已按项目约定准备 LLVM 15、Z3 与 KLEE，可直接使用
[`../guide/lab-firmware.md`](../guide/lab-firmware.md) 中的 native 配置运行 KLEE；
该配置默认只打开 KLEE，不会自动启用 SaTC、FirmRec 或 BOND。

探测不会执行分析，也不会因缺失返回非零：

```bash
make ext-smoke
```

运行完整链：

```bash
python scripts/run_pipeline.py --benchmark-fixtures --depth full --out-dir runs/ext_full
```

默认是 Blind Run。只有已获授权的复发扫描专项才可使用 `--no-blind`，并且必须在报告
中保留“依赖已知漏洞签名，不属于零先验发现”的声明。

## 4. 能力与诚实降级

| 工具 | 依赖 | 缺失时状态 | 不可声称的能力 |
|---|---|---|---|
| SaTC | Docker、Ghidra、angr | skipped | 未跑真实镜像时结论保持 skipped/degraded |
| FirmRec | 本地：Python 3.9 + Ghidra 10.2.2 + PostgreSQL；或 Docker 镜像；已知漏洞签名 | skipped/FORCED_DISABLE | Blind 指标单独统计；`our` fixture 模式没有漏洞固件时保持无命中 |
| KLEE | LLVM bitcode、KLEE/Z3 | skipped/timeout/failed | harness 可达性验证合成模型；infeasible 表示当前模型不可达，真实固件安全性需要额外验证 |
| mini-BOND | 可选 Ghidra、隔离仿真目标、安全门 | skipped/unsafe | 内置限界 HTTP 探针；模拟模式不生成 finding |

当前仓库提供完整 Adapter、Parser、fixture、融合与降级测试；真实工具复现数据必须在
对应 `benchmarks/external/<tool>/README.md` 中记录版本、镜像、commit、机器环境和耗时。

## 5. 安全红线

- 工作目录仅允许 `./tmp/external/<tool>/<run_id>/`；
- FirmRec 的 `repo_dir` 必须位于 `allowed_paths` 内（推荐 `./vendor/FirmRec`），
  外部路径需显式加入 `config/safety.yaml`；
- BOND 目标只允许仿真与私有网段，且四道安全门全部通过；
- 验证环境限定为仿真实例、私有网段和无害探针（反弹 shell、持久化、下载执行与破坏性命令由安全策略拦截）；
- FirmHound 侧的 LLM 调用走项目运行时；FirmRec 上游如果启用 LLM，使用其自身
  `config.yaml` 的 `llm_key/llm_url/llm_model`，不经过本项目运行时；
- 只有 `poc_sanitized=true` 的 marker/crash 证据可确认候选。

## 6. CI 与验收

CI 运行确定性单元测试、Schema 示例校验、8 种开关降级测试、lint、外部探测以及
`--depth full` 全关闭回归。主机相关解包集成测试使用 `make test-all`（或 `.venv/bin/python scripts/dev.py integration`）
单独运行，避免重型容器/工具拖死基础 CI。
