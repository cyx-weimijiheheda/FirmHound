---
id: 08-external-analyzers-klee
title: 外部分析器 · KLEE 符号执行路径剪枝
tags: [external, klee, symex, harness, m-external]
---

# Skill 08 · 外部分析器：KLEE

> 阶段：`SYMEX_PRUNE`。吃汇聚后的候选，回答「这条 source→sink 路径在约束上走不走得通」，
> 只把可达的交给 BOND，降低定向 fuzz 的开销。
> 代码位置：`tools/external/klee/`。

## 1. 目标

KLEE 3.2（LLVM 16 + Z3）做动态符号执行：输入符号化、沿路径收集约束、交给 SMT 求解器
判定可达性，可达时给出具体输入（witness）。它执行的是 LLVM bitcode 语义，天然跨架构，
不需要 qemu、不关心字节序。

三条前提必须先说清：

- KLEE 只吃 LLVM bitcode（`.bc`），固件是 MIPS/ARM 二进制，bitcode 要自己造。
- `infeasible` 表示「在当前 harness 模型下不可达」；真实固件可达性需要额外验证。
- 超时与路径爆炸不改分，只记 `limitation`。

## 2. 适用场景 / 输入

- **输入**：`artifacts/candidates.json`（或 `fused.json`）、已解包 rootfs、`config/dev.yaml` 的 `external.klee`。
- **触发**：`SYMEX_PRUNE` 阶段，且 `external.klee.enabled=true`。
- **不适用**：候选缺 sink 签名、宿主无 clang/LLVM 工具链且无可用镜像 → `skipped`。

## 3. 输出

- `runs/<id>/artifacts/external_findings/klee.json`：每条候选一条 `symex` 结论。
- 字段：`reachable`（`true` / `false` / `null`）、`reason`、`witness_input`、`harness_version`、`stats`。

## 4. 执行流程

1. **probe()**：`klee --version` 探活；后端 `local` 与 `docker`（`kleever/klee:llvm-16`）二选一，`auto` 先本地后镜像。
2. **造 bitcode**：按策略表选路径（见 §5），拿不到 `.bc` 就按降级路径处理，不编造。
3. **run()**：`--max-forks=64 --max-depth=200 --search=dfs`，外层套硬超时（`max_time_s`）。
4. **parse()**：`prune.py` 读 `klee-out-N/` 全部产物——6 类 `.err`、`.ktest`、`info`、`run.stats`、`warnings.txt`、`.path`。
5. **回写**：可达写 evidence 与 `witness_input`；不可达写 **counterevidence**，绝不删候选。
6. **execute()**：异常一律兜住，返回 `status=skipped/failed`，不中断主链。

## 5. 三条 bitcode 策略

| 路径 | 适用 | 做法 | 时间盒 |
|---|---|---|---|
| **S1 源码 wllvm** | 有源码的组件（合成固件 `httpd.c`/`upnpd.c`、开源 Boa/goahead） | `wllvm -O0 -g` → `extract-bc` | 必成 |
| **S2 harness 桩**（主推） | 真实固件无源码 | 从候选 sink 签名生成 C 桩 → `clang -emit-llvm` | 主路径 |
| **S3 二进制提升** | 理论上通用 | mcsema / retDec 抬成 LLVM IR | 4h 硬上限，失败即放弃并记 limitation |

选择逻辑（`_select_strategy`）：`auto` 下候选带 `source_path` 走 S1，否则 S2；`mode=source`
无源码则降级 S2；`mode=binary` 走 S3。

### 5.1 harness 生成规则（`harness_gen.py`）

`HarnessSpec`（来自候选 sink 签名）→ 渲染 C 桩 → 编成 `.bc`：

- **符号化输入**：`klee_make_symbolic(input, ...)` + `klee_assume` 限定可打印范围（`0x20..0x7e`）。
- **sink 必须桩化**：`#define system(x) __fsa_sink(x)`，桩只记录「参数到达了 sink」，不真调 shell。
- **溢出型**：buffer 大小取反汇编推断的 `buf_size`（缺省 `DEFAULT_BUF_SIZE=256`），让 `strcpy` 真的越界，触发 `ptr.err`。
- **版本号**：`HARNESS_VERSION="v1"` 盖在每个 harness 与 finding 上，误杀防护要能追溯。
- 命令注入 / 溢出 / 格式串三种模板见 `templates/{command_injection,overflow,format_string}.harness.c`。

## 6. 判定与 `symex` 字段（`prune.py`）

| KLEE 结果 | `symex.reachable` | `symex.reason` | 动作 |
|---|---|---|---|
| 走到 sink + witness | `true` | `ok` | 写 evidence；`witness_input` 给 BOND |
| `ptr.err` | `true` | `ok` | 强证据：可达 + 内存错误，升级 `vuln_class=overflow` |
| 所有路径 UNSAT | `false` | `infeasible` | 写 counterevidence，交 Verifier 判 |
| 超时 | `null` | `timeout` | 不改分，记 `limitation` |
| 路径爆炸 | `null` | `path_explosion` | 不改分，记 `limitation` |
| `model.err` / `exec.err` | `null` | `unsupported_arch` | 记 `limitation`，非漏洞 |

误杀防护三条硬约束：

1. 只写 counterevidence，**绝不删候选**；是否判 `false-positive` 交给 Verifier。
2. `reason` 必须带 `harness_version`，报告写明「基于 harness v1 的建模假设」。
3. 剪枝率 > 70% 触发人工抽检 5 条（`needs_manual_audit` / `sample_for_audit`）。

## 7. 命令与配置

```bash
# 单工具
python -m tools.external.adapter run_klee <run_dir> --config-path config/dev.yaml

# 全链路（--depth full 下 SYMEX_PRUNE 自动路由到本工具）
python scripts/run_external.py --tool klee --run-dir runs/<id>

# 单测
make test
pytest tests/unit/test_external_klee.py tests/unit/test_harness_gen.py \
       tests/unit/test_external_klee_runner.py
```

`config/dev.yaml` 关键开关（默认关闭）：

```yaml
external:
  klee:
    enabled: false
    harness: auto                  # auto | source | binary
    backend: auto                  # auto | local | docker
    solver: z3
    image: kleever/klee:llvm-16
    max_time_s: 14400
    max_forks: 64
    max_depth: 200
    search: dfs
```

## 8. 验收与降级（八档不 abort）

- KLEE 缺失 → `probe()` 返回 `available=False` → `skipped` + limitation，主链照常出报告。
- 超时、路径爆炸 → `symex.reachable=null`，候选分数不变。
- 8 种开关组合全部返回 `status ∈ {ok, skipped}`，不抛异常、不中断（`tests/unit/test_external_integration.py`）。

## 9. 与其他阶段协作

- **上游**：主轨候选与 SaTC 的 `call_trace` 是输入。
- **下游 BOND**：只消费 `reachable=true` 且带 `witness_input` 的候选。
- **Verifier**：拿 `infeasible` 的 counterevidence 判断是否降为 `false-positive`，KLEE 自己不下结论。

---

## 踩坑表

| 坑 | 症状 | 处理 |
|---|---|---|
| 拿不到 bitcode | MIPS/ARM 二进制无法提升 | 走 S2 harness；S3 超 4h 放弃 |
| uClibc 只完备支持 x86 | MIPS/ARM 的 libc 调用跑不了 | sink 用自定义桩绕开 libc |
| 路径爆炸 | 状态数飙升 | `--max-forks=64 --max-depth=200 --search=dfs`；超时降级为 `path_explosion` |
| 外部函数无法符号化 | `exec.err` 满屏 | 全部写桩；`exec.err` 归 limitation |
| `model.err` 被误当漏洞 | 误报变多 | parser 显式把 `model.err`/`exec.err` 路由 limitation（单测覆盖） |
| harness 过度简化误杀 | 剪枝率异常高 | 抽检 + `harness_version` 可追溯 + 只写反证不删候选 |
| 宿主没有 KLEE | 未安装 LLVM 16 + Z3 | 用 Docker（`kleever/klee:llvm-16`）或按官方文档安装 |

---

## 反哺主轨

- **A1**：harness 模板沉淀回 `tools/analysis/`，让静态规则能复用同一套 sink 签名。
- **A2**：`symex.stats`（instructions / states / paths / time）并入报告，作为候选评估成本的量化依据。
