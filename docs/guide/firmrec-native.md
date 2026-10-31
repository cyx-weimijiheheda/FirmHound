# FirmRec 原生后端安装与接入（无 Docker）

> 适用：希望在本机直接运行上游 [seclab-fudan/FirmRec](https://github.com/seclab-fudan/FirmRec)，
> 而不是通过 `xylearn/firmrec-base` 镜像。上游官方只提供 Docker 安装；本文是按
> 其 `Dockerfile-base`、`requirements.txt`、`config.yaml`、`INPUT.md` 还原的等价步骤。

## 1. 版本矩阵（必须锁定）

| 组件 | 版本 |
|---|---|
| JDK | OpenJDK **18.0.2** |
| Ghidra | **10.2.2** |
| Gradle | **7.6**（仅构建 Ghidra） |
| Maven | **3.9.8** |
| Python | **3.9**（FirmRec 专用环境） |
| PostgreSQL | 11+（上游镜像内为 11） |
| binwalk | 2.3.x（v2，不是 Rust v3） |
| 其他 | sasquatch、unsquashfs、fakeroot、fakechroot、jefferson（可选） |

FirmRec 的 Python 依赖装在独立环境：

```bash
FIRMREC_PYTHON=python3.9 python3 scripts/dev.py firmrec-deps
# 等价于：
python3.9 -m venv .venv-firmrec
.venv-firmrec/bin/pip install -r requirements-firmrec.txt
```

> FirmHound 项目自己的 `.venv` 仍要求 Python 3.11–3.13（PyO3 依赖上限）；
> 这里的 3.9 环境只用于 FirmRec 上游分析器，与 FirmHound 的 `.venv` 分开。

## 2. 宿主依赖

Fedora / RHEL：

```bash
sudo dnf install -y git curl wget unzip bison flex gcc gcc-c++ make \
  python3-devel libffi-devel xz-devel zlib-devel \
  postgresql-server postgresql-contrib \
  fakeroot fakechroot squashfs-tools binwalk
```

Debian / Ubuntu：

```bash
sudo apt install -y git curl wget unzip bison flex build-essential \
  python3-dev libffi-dev liblzma-dev zlib1g-dev \
  postgresql postgresql-contrib fakeroot fakechroot squashfs-tools binwalk
```

`sasquatch` 需要源码编译：

```bash
git clone https://github.com/devttys0/sasquatch.git
cd sasquatch && ./build.sh && sudo cp sasquatch /usr/local/bin/
```

## 3. JDK 18、Gradle 7.6、Ghidra 10.2.2

```bash
# JDK 18
sudo mkdir -p /opt/jdk18 && cd /tmp
wget https://download.java.net/java/GA/jdk18.0.2/f6ad4b4450fd4d298113270ec84f30ee/9/GPL/openjdk-18.0.2_linux-x64_bin.tar.gz
sudo tar -xzf openjdk-18.0.2_linux-x64_bin.tar.gz -C /opt/jdk18 --strip-components=1
export JAVA_HOME=/opt/jdk18
export PATH="$JAVA_HOME/bin:$PATH"

# Gradle 7.6
wget https://services.gradle.org/distributions/gradle-7.6-all.zip
sudo unzip -d /opt/gradle gradle-7.6-all.zip
export PATH="/opt/gradle/gradle-7.6/bin:$PATH"

# Ghidra 10.2.2（官方 release；也可按上游 Dockerfile 从源码构建）
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.2.2_build/ghidra_10.2.2_PUBLIC_20230105.zip
sudo unzip -d /opt ghidra_10.2.2_PUBLIC_20230105.zip
sudo mv /opt/ghidra_10.2.2_PUBLIC /opt/ghidra
cd /opt/ghidra && sudo -E ./support/buildGhidraJar
```

## 4. 构建 `firmrec-static.jar`

```bash
# 在 FirmHound 项目根目录执行，直接把 checkout 放到安全白名单内
mkdir -p vendor
git clone https://github.com/seclab-fudan/FirmRec.git vendor/FirmRec
cd vendor/FirmRec

mkdir -p firmentry/analyzer/lib
cp /opt/ghidra/ghidra.jar firmentry/analyzer/lib/ghidra.jar
cd firmentry && ./build_jar.sh
ls -l firmrec-static.jar
```

## 5. PostgreSQL

```bash
sudo postgresql-setup --initdb            # Debian: sudo -u postgres initdb ...
sudo systemctl enable --now postgresql

sudo -u postgres psql -c \
  "CREATE ROLE root WITH SUPERUSER LOGIN PASSWORD 'firmrec';"
```

FirmHound 会为每个 run 使用独立数据库名（`firmrec_<run_id>` 和 `..._vuln`），
上游 step 2.1 负责 `DROP/CREATE DATABASE`，同名库由上游创建。

若报 `Peer authentication failed`，在 `pg_hba.conf` 中允许本地密码认证：

```conf
local   all   all                 md5
host    all   all   127.0.0.1/32  md5
```

然后 `sudo systemctl reload postgresql`。

## 6. 配置 FirmHound

步骤 4 已经把 checkout 放到安全白名单内的 `./vendor/FirmRec`；使用真实目录，符号链接会被解析到白名单外：
`PolicyEngine` 会按真实路径解析，指向 `/opt/FirmRec` 的链接仍会被拒绝。

如果必须使用 `/opt/FirmRec`，把它显式加入 `config/safety.yaml` 的
`allowed_paths`，并把 `repo_dir` 配成绝对路径；或者复制一份到白名单内：

```bash
mkdir -p vendor
cp -a /opt/FirmRec vendor/FirmRec
```

`config/dev.yaml`：

```yaml
external:
  enabled: true
  firmrec:
    enabled: true
    backend: auto              # auto | local | docker
    repo_dir: ./vendor/FirmRec
    python_bin: ./.venv-firmrec/bin/python
    ghidra_headless: /opt/ghidra/support/analyzeHeadless
    firmrec_static_jar: ./vendor/FirmRec/firmentry/firmrec-static.jar
    pg_user: root
    pg_password: firmrec       # 或 FSA_FIRMREC_PG_PASSWORD
    vendor: acme
    allow_rootfs_tar: true
    # 真实复发检测需要上游格式的签名库：
    vuln_info_dir: ""
    official_vuln_info_path: ""
    vuln_firmware_dir: ""
```

如果 checkout 不在白名单内（例如 `/opt/FirmRec`），必须把它显式加入
`config/safety.yaml` 的 `allowed_paths`，否则 probe 会返回路径策略错误。

## 7. 上游输入契约

FirmRec 读取的是**固件镜像**，不是解包后的 rootfs：

```text
inout/
├── firmware/images/<VENDOR>/<IMAGE>
├── vuln_info/<VENDOR>/<NAME>/
│   ├── meta.json
│   └── <vulnerable firmware image>
└── experiment.json
```

`experiment.json`：

```json
{
  "name": "dir859-recurrence",
  "vulns": ["huawei/HG532e-CVE-2017-17215"],
  "images": ["dlink/DIR859_FW102b03.bin"]
}
```

`meta.json` 支持结构化输入或原始输入：

```json
{"firmware_filename": "vuln.bin", "input": {"kv": {"NewStatusURL": "BENIGN"}}}
```

```json
{"firmware_filename": "vuln.bin", "input": {"raw": ["<base64>"]}}
```

FirmHound 的 `prepare()` 会自动生成上述目录；如果 run 只有 rootfs，会把 rootfs
打成 tar 作为 image，并在 `limitation` 中注明这是近似输入。真实签名提取应使用
`vuln_info_dir` 或 `official_vuln_info_path` 指向已经准备好的上游目录树；
`benchmarks/CVEs` 的 9 个 fixture 没有漏洞固件和 PoC，默认会被跳过（不会伪造）。

## 8. 运行与验收

```bash
# 只做依赖检查（不跑分析）
make firmrec-doctor

# 先跑一次普通分析，拿到 run 目录
fsa analyze tmp/unpacked/squashfs-root --input-type rootfs \
  --authorization-holder "设备所有者" --depth full --run-id firmrec-demo

# 对已有 run 单独跑 FirmRec
make firmrec-smoke RUN_DIR=runs/firmrec-demo

# 或者直接走外部分析器入口
python scripts/run_external.py --tool firmrec --run-dir runs/firmrec-demo
```

上游实际执行的是两步，FirmHound 已自动串好：

```bash
python -m firmrec.pipeline all
python -m firmrec.pipeline 4.4       # 收集 result.csv
```

结果位置（上游版本之间存在差异，解析器会全部搜索）：

```text
inout/emu_results/result.csv
inout/simexp_results/result.csv
inout/result.csv
```

FirmHound 归一化后的产物：

```text
runs/<run_id>/artifacts/external_findings/firmrec.json
runs/<run_id>/artifacts/external_findings/recurrence_findings.json
```

`report.md` 的「复发漏洞（FirmRec）」一节会单列这些结果，并注明依赖已知签名、
不计入零先验指标。FirmRec 永远不会进入 `unified_candidates.json` / `fused.json`。

## 9. 盲跑隔离

```bash
fsa analyze <rootfs> --input-type rootfs \
  --authorization-holder "设备所有者" --depth full --blind --run-id blind-1
```

`task_card.json` 写入 `blind: true` 后，Adapter 会把 FirmRec 强制禁用，
`external_findings/firmrec.json` 的 `limitation` 带 `FORCED_DISABLE`。

## 10. 常见问题

| 症状 | 处理 |
|---|---|
| `repo_dir:path_whitelist` | 把 checkout 放到 `./vendor` 或加入 `config/safety.yaml` |
| `python_bin` 缺失 | 用 `FIRMREC_PYTHON=python3.9 python3 scripts/dev.py firmrec-deps` |
| `ghidra_headless` 缺失 | 安装 Ghidra 10.2.2 并执行 `support/buildGhidraJar` |
| `firmrec_static_jar` 缺失 | 重新执行 `firmentry/build_jar.sh` |
| PostgreSQL 认证失败 | 改 `pg_hba.conf` 为 `md5`，确认 `pg_user/pg_password` |
| `vuln_firmware_images` | `our` 模式缺少漏洞固件；改用 `vuln_info_dir`/`official` |
| `result.csv` 缺失 | 确认 step 4.4 已执行；查看 `tmp/external/firmrec/<run>/logs/` |
| 合成 x86 固件检出少 | FirmRec 主打 MIPS/ARM，优先用真实固件 |
| 内存不足 | Ghidra/模拟执行建议 ≥16G RAM；降低并发或分批判 |
| Docker 回退 | 设置 `backend: docker`，镜像内会自动启动 PostgreSQL |
