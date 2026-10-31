---
id: 08-external-analyzers-firmrec
title: 外部分析器 · FirmRec 复发漏洞检测
tags: [external, firmrec, recurrence, ccs24, m-external]
---

# Skill 08 · 外部分析器：FirmRec

> 把 FirmRec（CCS'24, seclab-fudan/FirmRec）接入 FirmHound 流水线，
> 产出标准化的 `external_finding`。本 Skill 提供方法论与排错表，
> 靠通用解析定位，不依赖 CVE 特征库。

## 1. 目标

用 FirmRec 从**已知漏洞的利用过程语义签名**出发，在固件里找它的**复发变体**
（同厂商跨型号 / 跨版本，经代码复用或定制演变出的同类漏洞）。它补的是主轨
能力边界：**利用「这个洞在别处出现过」这条信息去扫变体**。

**关键定位（特殊性）**：FirmRec **不进主链**。它要求已知漏洞签名，与系统「零 CVE
先验、不泄露 Ground Truth」的核心前提直接冲突。因此它是本项目**唯一需要防污染**
的工具——隔离机制（§隔离）是它的第一交付物，比跑通更重要。实际运行中最可能的
快速成果一招：**给了 CVE 之后，扫同厂商跨型号变体**。

## 2. 适用场景 / 输入

- **输入（上游真实契约）**：
  - `inout/firmware/images/<VENDOR>/<IMAGE>`：固件镜像（不是解包后的 rootfs）；
  - `inout/vuln_info/<VENDOR>/<NAME>/{meta.json, 漏洞固件}`：已知漏洞签名；
  - `inout/experiment.json`：`{"name": ..., "vulns": [...], "images": [...]}`。
  - 本项目 `UNPACK` 产物是 rootfs；只有 rootfs 时 `prepare()` 会打成 tar 作为近似
    image，并写 `limitation`。真实签名提取应使用 `vuln_info_dir`/`official`。
- **触发**：`EXTERNAL_ANALYSIS` 阶段，且 `config/dev.yaml` 中
  `external.firmrec.enabled=true`。**盲跑（blind=true）时由代码强制禁用**（见 §隔离）。
- **不适用**：纯盲评 benchmark（会被强制关）；合成固件（x86，FirmRec 主打 MIPS/ARM）。

## 3. 输出

- `runs/<id>/artifacts/external_findings/firmrec.json`：归一化 findings
  （schema `external_finding`，每条带 `matched_cve` = 命中的已知 CVE）。
- `runs/<id>/artifacts/external_findings/recurrence_findings.json`：**FirmRec 专属分流
  文件**，与主链 `fused.json` 完全分开。
- 每条 finding 必含：`finding_id`、`tool=firmrec`、`binary_id`、`vuln_class`、
  `sink`(function+addr)、`confidence`、`status`；单签名实验会带 `matched_cve`，
  多签名实验不猜 CVE，只在 `notes` 记录 `vuln_refs`。
- 上游结果来自 `inout/emu_results/result.csv`（部分版本为 `simexp_results/result.csv`），
  解析器会依次搜索这些位置。

## 4. 执行流程

1. **probe()**：按 `backend: auto | local | docker` 选择执行后端。**永不抛异常**。
   - local：检查 `repo_dir`、`python_bin`、Ghidra headless、`firmrec-static.jar`，
     并对 `repo_dir` 过路径白名单；缺失返 `available=False + missing=[...]`；
   - docker：检查 daemon + `xylearn/firmrec-base` 镜像；
   - 两种后端都要求至少一个可用的上游 `vuln_info` 条目，否则 skipped。
2. **prepare()**：在 `tmp/external/firmrec/<run_id>/inout/` 生成上游真实目录：
   `firmware/images/<VENDOR>/<IMAGE>`、`vuln_info/<VENDOR>/<NAME>/meta.json`、
   `experiment.json`。只有 rootfs 时打 tar 并记 limitation。
3. **run()**：
   - local：用 FirmRec 专用 Python 执行 `native_wrapper.py`，先 `all` 再 `4.4`；
     wrapper 在导入 `firmrec.consts` 前注入 per-run `gconfig`，不改上游 checkout；
   - docker：在**同一个容器**内启动 PostgreSQL、跑 `all` 和 `4.4`（`--rm` 会销毁库）；
   - PostgreSQL 未就绪、超时或失败都记 `limitation`，不伪造成功。
4. **parse()**：优先解析上游 `inout/**/result.csv`（`emu_results`/`simexp_results`/
   根目录都搜），字段归一化为 `external_finding`；旧版 `VULNS.md`/`pg_*.csv`/
   `poc_info/` 作为兼容回退保留。
5. **normalize()**：逐条过 schema 校验，非法 finding 丢弃并计数（`dropped`）。
6. **execute()**：以上任一步异常都被兜住，返回 `status=skipped/failed`，**绝不 abort 主链**。

## 5. 命令与配置

```bash
# 依赖检查（不跑分析）
make firmrec-doctor

# 调试：单工具独立跑（不经编排器）
python scripts/run_external.py --tool firmrec --run-dir runs/<id>

# 对已有 run 执行（Make 包装）
make firmrec-smoke RUN_DIR=runs/<id>

# 全量：整条外部链
python scripts/run_external.py --tool all --run-dir runs/<id>
```

`config/dev.yaml` 关键开关（默认全关）：

```yaml
external:
  enabled: false
  firmrec:
    enabled: false
    backend: auto                 # auto | local | docker
    repo_dir: ./vendor/FirmRec    # 本地上游 checkout
    python_bin: ./.venv-firmrec/bin/python
    ghidra_headless: /opt/ghidra/support/analyzeHeadless
    firmrec_static_jar: ./vendor/FirmRec/firmentry/firmrec-static.jar
    pg_user: root
    pg_password: firmrec          # 或 FSA_FIRMREC_PG_PASSWORD
    image: xylearn/firmrec-base   # Docker 回退
    vuln_info_dir: ""             # 上游签名目录树（优先）
    official_vuln_info_path: ""   # source=official
    vuln_firmware_dir: ""         # source=our 的漏洞固件
    signature_db: ./benchmarks/CVEs
    vuln_info_source: our         # our | official
    mode: signature_only          # 盲跑时保持关闭
    timeout_s: 7200
```

**运行策略**：Blind Benchmark 中保持 FirmRec 关闭；在「已经掌握某个 CVE，扫同厂商
变体」的明确场景开启，且其结论单列、不计入零先验指标。

## 6. 验收与降级（八档不 abort）

- FirmRec 缺失 / 未启用 → `probe()` / `_resolve_external_config` → `skipped` + 记
  limitation，主链照常出报告。
- 8 种开关组合（全关 / firmrec±/ 叠加 satc·klee·bond 等）全部返回
  `status ∈ {ok, skipped}`，**不抛异常、不中断**。
- `pytest tests/unit/test_external_integration.py` 固化这 8 档；
  `pytest tests/unit/test_recurrence_isolation.py` 固化隔离三保证。

## 7. 与其他阶段协作

- **融合层**：FirmRec findings 全部带 `matched_cve`，`finding_fusion` 把它们标
  `blind_isolated=True`、**不计入 `external_only` 增量**、并单独落 `recurrence_findings.json`，
  主链 `fused.json` 永不混入 FirmRec 条目（守零 CVE 先验红线）。
- **报告层**：`report.md` 的「复发漏洞（FirmRec）」一节单列，开头明写
  「本节依赖已知漏洞签名，不属于零先验能力，不计入 Blind Benchmark 指标」。
- **下游**：FirmRec 检出的变体可反向喂给主轨做「已知变体特征」规则沉淀（限非盲场景）。

---

## 隔离说明（唯一防污染闸门）

四道隔离**全部实现**，缺一不可：

1. **默认关闭**：`config/dev.yaml` 的 `firmrec.enabled: false`。
2. **盲跑强制禁用（代码断言）**：`tools/external/adapter._resolve_external_config`
   在 `run_ctx.blind=True` 时强制 `firmrec.enabled=False`，结果 limitation 带
   `FORCED_DISABLE`，并有单测 `test_adapter_forces_disable_on_blind_run` 固化。
3. **产物不进主链**：`finding_fusion` 把 FirmRec 分流到 `recurrence_findings.json`，
   主链 `fused.json` 不含任何 `tool=firmrec`（`test_unified_candidates_contain_no_firmrec_findings`）。
4. **报告单列标注**：报告章节开头声明其结论依赖已知签名、不计入盲评指标。

---

## 踩坑表（不写等于白踩）

| 坑 | 症状 | 处理 |
|---|---|---|
| `repo_dir:path_whitelist` | 本地 checkout 被安全策略拒绝 | 直接 clone 到 `./vendor/FirmRec`（使用真实目录；符号链接会解析到白名单外），或把绝对路径加入 `config/safety.yaml` |
| Python 版本不对 | angr/psycopg2 装不上 | 用 `FIRMREC_PYTHON=python3.9 python3 scripts/dev.py firmrec-deps` 建独立 `.venv-firmrec` |
| Ghidra/JAR 缺失 | `ghidra_headless` / `firmrec_static_jar` missing | 装 Ghidra 10.2.2，执行 `support/buildGhidraJar` 与 `firmentry/build_jar.sh` |
| PostgreSQL 起不来 | `psql` 连不上 / peer auth | 启动服务、改 `pg_hba.conf` 为 `md5`、核对 `pg_user/pg_password` |
| `vuln_info` 格式不对 | 上游找不到 `meta.json` | 用上游目录树 `vuln_info/<VENDOR>/<NAME>/meta.json`；旧的 `vulns.json` 已不再喂 upstream |
| `our` 模式没有漏洞固件 | probe 报 `vuln_firmware_images` | 配置 `vuln_info_dir`/`official_vuln_info_path`，或在 `vuln_firmware_dir/<CVE>/` 放漏洞固件 |
| `result.csv` 找不到 | 解析 0 条 | 确认 step 4.4 跑过；搜索 `emu_results/`、`simexp_results/`、`inout/result.csv` |
| 只有 rootfs | 上游解包失败 | 允许 tar 兜底并记录 limitation；最好提供原始固件镜像 |
| 合成固件是 x86 | FirmRec 主打 MIPS/ARM | 记录是否支持；不支持则 L1 不作为验收必需项（comparison 注明） |
| Docker 回退失败 | 镜像/挂载/数据库 | 挂载点是 `/root/inout` 与 `/root/config.yaml`；同一容器内起 PG 并跑 `all`+`4.4` |
| PoC 含危险 payload | 落盘即违规 | `poc_info` 全经 `sanitize_poc`，拒绝的直接丢弃（`dropped_unsafe` 计数） |

---

## 反哺主轨（进阶项）

- **A**：把 FirmRec 检出的「已知变体特征」（函数名 + 调用模式）沉淀进
  `source_sink_rules` 的厂商封装函数字典，作为非 CVE 先验的通用模式（不写死 CVE）。
- **B**：复发专项实验（§comparison.md）若在某固件检出 0 变体，本身是个结论——说明
  这批固件属不同代码谱系，可在报告里正面呈现。
