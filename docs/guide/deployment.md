# FirmHound Linux 部署与演示指南

> 适用场景：在一台干净的 Linux 环境（虚拟机 / 物理机 / 云主机 / 容器均可）上，从零把 FirmHound 拉下来、配好环境、跑通完整 CLI 流程。

**发行版覆盖**：Debian/Ubuntu（含 Kali、Raspberry Pi OS）、Fedora/RHEL/CentOS Stream/Rocky/Alma、Arch/Manjaro、openSUSE Leap/Tumbleweed、Alpine（容器）。各发行版的包名差异见下文 §3 的对照表；工具链缺项只会让对应阶段降级，不会阻断静态分析。

## 0. 部署目标

本指南跑通以下内容：

1. 在 Linux 虚拟机中安装系统依赖。
2. 从 GitHub 下载 FirmHound 项目。
3. 创建 Python 虚拟环境。
4. 安装 FirmHound CLI。
5. 安装固件解包工具：binwalk、unsquashfs、sasquatch。
6. 运行环境自检。
7. 复制真实固件样本。
8. 运行 AC15、OpenWrt、BE3LPro 三个演示案例。
9. 查看报告、证据链和测试结果。

## 1. 前置准备

你需要准备：

- 一台 Linux 环境（虚拟机、物理机、云主机或容器，2 核 4G 起步即可）。
- 可以联网。
- 已安装 Git，或允许通过包管理器安装。
- 三个授权固件样本：
  - `US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin`
  - `openwrt-23.05.0-ramips-mt7620-zbtlink_zbt-we826-16m-squashfs-sysupgrade.bin`
  - `US_BE3LProV1.0mt_V16.03.60.62_cn_TDC01.bin`
- GitHub 仓库地址：

```text
https://github.com/cyx-weimijiheheda/FirmHound.git
```

## 2. 更新系统

按发行版选择对应命令：

```bash
# Debian / Ubuntu
sudo apt update && sudo apt upgrade -y

# Fedora / RHEL 系
sudo dnf upgrade --refresh -y

# Arch / Manjaro
sudo pacman -Syu --noconfirm

# openSUSE
sudo zypper refresh && sudo zypper update -y

# Alpine
sudo apk update && sudo apk upgrade
```

## 3. 安装基础依赖

按发行版的安装命令、包名差异与排错表统一在 [`install.md`](install.md)，本节不再重复。

装完后的自检：

```bash
python3 --version      # 需要 3.11–3.13（3.14 暂不支持 PyO3 依赖）
make doctor
```

`fsa doctor` 报 `status: ok`，或只有 `commands: degraded`（缺可选工具），就算就绪。

## 4. 安装 sasquatch

`sasquatch` 的编译依赖、安装步骤与验证方法见 [`install.md`](install.md) 的 §3。

不装也能跑纯 Python 的静态分析；Tenda AC15 这类厂商魔改固件会解包不完整。

## 5. 从 GitHub 下载项目

建议把项目放在用户目录下：

```bash
cd ~
git clone https://github.com/cyx-weimijiheheda/FirmHound.git
cd FirmHound
```

查看项目结构：

```bash
ls
tree -L 2 | head -120
```

你应该能看到这些目录：

```text
fsa/
tools/
skills/
schemas/
config/
tests/
benchmarks/
docs/
scripts/
```

如果以后要更新代码：

```bash
cd ~/FirmHound
git pull
```

## 6. 创建 Python 虚拟环境

进入项目目录：

```bash
cd ~/FirmHound
```

一条命令建环境并安装（`make` 自己创建 `.venv`）：

```bash
make dev
```

`make dev` 依次执行 `python3 -m venv .venv`、`pip install -r requirements.txt`、`pip install -e .`。
装完激活一次，`fsa` 就进 PATH：

```bash
source .venv/bin/activate      # 终端提示符出现 (.venv)
fsa --help
```

手动等价写法（不想用 make 时）：

```bash
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt
.venv/bin/pip install -e .
```

如果提示 `fsa: command not found`，使用下面的方式也可以：

```bash
fsa --help
```

## 7. 第一次环境自检

执行：

```bash
fsa doctor --json-output
```

或者：

```bash
fsa doctor --json-output
```

正常情况下应该看到类似：

```json
{
  "status": "ok",
  "checks": {
    "paths": {"status": "ok"},
    "schemas": {"status": "ok"},
    "runtime": {"status": "ok"},
    "commands": {
      "status": "ok"
    }
  }
}
```

重点看：

- `paths.status=ok`
- `schemas.status=ok`
- `runtime.status=ok`
- `binwalk=true`
- `unsquashfs=true`

如果 `decompile.status=degraded`（未找到 Ghidra）或 `klee=false`，这是可以接受的。Ghidra 和 KLEE 是可选深度分析工具，不影响基础演示；Ghidra 路径通过本地 `.env` 的 `GHIDRA_HEADLESS` 或 `decompile.ghidra_headless` 提供。

## 8. 运行基础测试

先跑一组轻量测试：

```bash
python -m pytest tests/unit/test_safety.py tests/unit/test_schemas.py -q
```

再跑完整测试：

```bash
make test
```

代码风格检查：

```bash
python -m ruff check .
```

如果完整测试耗时较久，演示时可以只展示：

```bash
python -m pytest tests/unit/test_safety.py tests/unit/test_schemas.py -q
python -m ruff check .
```

## 9. 准备固件样本目录

FirmHound 默认安全策略只允许读取白名单目录。固件样本建议统一放到：

```bash
~/FirmHound/firmware_samples/
```

创建目录：

```bash
cd ~/FirmHound
mkdir -p firmware_samples
```

## 10. 把固件样本放进工作目录

固件可能来自本机下载、共享目录、U 盘、另一台机器或对象存储，按场景选一种方式。

### 方式 D：容器 / 远程机器（推荐做法）

容器运行时用 volume 挂载，避免把样本烤进镜像：

```bash
docker run --rm -it -v "$PWD/firmware_samples:/work/firmware_samples" \
  -v "$PWD:/work" -w /work debian:12 bash
```

远程 Linux 主机直接从本机推过去（Linux/macOS 通用）：

```bash
scp ./firmware_samples/*.bin <用户名>@<主机>:~/FirmHound/firmware_samples/
```

也可以用 `wget`/`curl` 在目标机上直接取：

```bash
wget -P firmware_samples/ "https://<授权样本地址>/xxx.bin"
```

> 只下载**已获授权**的固件；安全策略会校验路径白名单（`firmware_samples/`、`tmp/`）。

### 方式 A：VMware / VirtualBox 共享文件夹

如果你配置了共享文件夹，假设共享目录挂载在：

```text
/mnt/hgfs/share
```

或：

```text
/media/sf_share
```

复制：

```bash
cp /mnt/hgfs/share/US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin firmware_samples/
cp /mnt/hgfs/share/openwrt-23.05.0-ramips-mt7620-zbtlink_zbt-we826-16m-squashfs-sysupgrade.bin firmware_samples/
cp /mnt/hgfs/share/US_BE3LProV1.0mt_V16.03.60.62_cn_TDC01.bin firmware_samples/
```

如果你的共享目录不同，把 `/mnt/hgfs/share` 换成实际路径。

### 方式 B：用 U 盘复制

插入 U 盘后，Linux 通常会挂载到 `/media/<用户名>/` 下。

查看：

```bash
ls /media/$USER
```

假设 U 盘目录是 `/media/$USER/USB`：

```bash
cp /media/$USER/USB/US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin firmware_samples/
cp /media/$USER/USB/openwrt-23.05.0-ramips-mt7620-zbtlink_zbt-we826-16m-squashfs-sysupgrade.bin firmware_samples/
cp /media/$USER/USB/US_BE3LProV1.0mt_V16.03.60.62_cn_TDC01.bin firmware_samples/
```

### 方式 C：用 scp 从另一台机器传进来

先在目标 Linux 上查看 IP：

```bash
ip addr
```

找到类似 `192.168.x.x` 的地址。然后在源机器上执行（Windows PowerShell、macOS/Linux 终端同理，只需换路径写法）：

```bash
scp ./firmware_samples/*.bin <用户名>@<目标IP>:~/FirmHound/firmware_samples/

# Windows PowerShell 写法
scp "D:\firmware\US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin" <用户名>@<目标IP>:~/FirmHound/firmware_samples/
```

把 `<用户名>` 和 `<目标IP>` 换成你自己的。目标机没有 SSH 服务时按发行版安装：

```bash
sudo apt install -y openssh-server          # Debian / Ubuntu
sudo dnf install -y openssh-server          # Fedora / RHEL
sudo pacman -S --needed openssh             # Arch
sudo zypper install -y openssh              # openSUSE
sudo apk add openssh                        # Alpine
sudo systemctl enable --now ssh
```

## 11. 确认固件已经放好

```bash
cd ~/FirmHound
ls -lh firmware_samples
```

应该能看到：

```text
US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin
openwrt-23.05.0-ramips-mt7620-zbtlink_zbt-we826-16m-squashfs-sysupgrade.bin
US_BE3LProV1.0mt_V16.03.60.62_cn_TDC01.bin
```

## 12. 演示 1：任务规划

这个命令展示“智能体如何把自然语言任务转成执行计划”。

```bash
fsa plan \
  --task "分析 Tenda AC15 路由器固件，已获得授权，执行完整固件漏洞挖掘流程" \
  --firmware-path firmware_samples/US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin \
  --authorization-holder "team-authorized" \
  --vendor Tenda \
  --model AC15 \
  --version V15.03.05.19_multi_TD01 \
  --depth full \
  --json-output
```

讲解重点：

- `plan` 只规划，不执行。
- 展示任务理解能力。
- 展示授权主体。
- 展示 full depth 阶段。

## 13. 演示 2：分析 Tenda AC15 固件

这是最推荐作为主演示的案例。

```bash
fsa analyze firmware_samples/US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin \
  --input-type firmware \
  --depth standard \
  --authorization-holder "team-authorized" \
  --vendor Tenda \
  --model AC15 \
  --version V15.03.05.19_multi_TD01 \
  --run-id demo-ac15-linux \
  --json-output
```

查看状态：

```bash
fsa status demo-ac15-linux --json-output
```

查看输出目录：

```bash
find runs/demo-ac15-linux -maxdepth 3 -type f | sort | head -120
```

查看报告：

```bash
sed -n '1,220p' runs/demo-ac15-linux/report.md
```

查重点候选：

```bash
grep -n "候选\|httpd\|formWifiConfigGet\|NEED_DYNAMIC\|system\|CRITICAL\|HIGH" runs/demo-ac15-linux/report.md | head -50
```

讲解重点：

- AC15 能完整解包。
- 系统会生成 rootfs、攻击面、二进制摘要、候选、报告。
- 发现的是静态候选，不直接等同确认漏洞。
- 报告会提示待动态验证事实。

## 14. 演示 3：查看证据链和决策链

查看运行目录：

```bash
ls runs/demo-ac15-linux
ls runs/demo-ac15-linux/artifacts
ls runs/demo-ac15-linux/state
```

查看决策文件：

```bash
find runs/demo-ac15-linux/decisions -type f | head -5
```

打开第一个决策文件：

```bash
python -m json.tool "$(find runs/demo-ac15-linux/decisions -type f | head -1)"
```

查看证据文件：

```bash
find runs/demo-ac15-linux/evidence -type f | head -5
```

打开第一个证据文件：

```bash
python -m json.tool "$(find runs/demo-ac15-linux/evidence -type f | head -1)"
```

讲解重点：

- FirmHound 不只是输出最终结论。
- 每个阶段有 evidence 和 decision。
- 审阅者可以复核每条判断的来源。

也可以直接使用新增的“漏洞证据账本”命令：

```bash
fsa explain demo-ac15-linux --format markdown --limit 5
```

如果只想解释某一个候选：

```bash
fsa explain demo-ac15-linux --candidate-id <candidate-id> --format markdown
```

讲解重点：

- `explain` 会把候选的 source、sink、调用链、支持证据、反证、十维评分和下一步建议集中展示。
- 这条链路的作用是让结论可复核：每条判断都能追到证据。

## 15. 演示 4：分析 OpenWrt WE826 固件

这个案例用于展示“正常固件完整跑通，但不乱报高危”。

```bash
fsa analyze firmware_samples/openwrt-23.05.0-ramips-mt7620-zbtlink_zbt-we826-16m-squashfs-sysupgrade.bin \
  --input-type firmware \
  --depth standard \
  --authorization-holder "team-authorized" \
  --vendor OpenWrt \
  --model zbt-we826-16m \
  --version 23.05.0 \
  --run-id demo-openwrt-linux \
  --json-output
```

查看报告：

```bash
sed -n '1,180p' runs/demo-openwrt-linux/report.md
```

讲解重点：

- OpenWrt 样本可完整解包。
- 安全工具不应该为了演示而强行报漏洞。
- 无高危候选也是可信结果的一部分。

## 16. 演示 5：分析 BE3LPro 加密固件

这个案例用于展示加密固件识别和诚实降级。

先做解包性诊断：

```bash
fsa unpack-diagnose firmware_samples/US_BE3LProV1.0mt_V16.03.60.62_cn_TDC01.bin \
  --json-output
```

讲解重点：

- `unpack-diagnose` 不执行完整分析，只判断固件可解包性。
- 对加密固件，它会提示 OpenSSL Salted/加密载荷、魔数 offset、提取器状态和下一步所需材料。

```bash
fsa analyze firmware_samples/US_BE3LProV1.0mt_V16.03.60.62_cn_TDC01.bin \
  --input-type firmware \
  --depth standard \
  --authorization-holder "team-authorized" \
  --vendor Tenda \
  --model BE3LPro \
  --version V16.03.60.62_cn_TDC01 \
  --run-id demo-be3lpro-linux \
  --json-output
```

查看状态：

```bash
fsa status demo-be3lpro-linux --json-output
```

查找加密切片：

```bash
find tmp -iname "*encrypted*" -o -iname "*openssl*" | head
```

讲解重点：

- BE3LPro 检测到 OpenSSL Salted 加密载荷。
- 没有密钥/密码/厂商升级工具解密逻辑时，不伪造解包成功。
- 系统会保存加密切片并提示需要解密材料。
- 这体现的是逆向分析里的“边界识别”和“诚实降级”。

## 17. 演示 6：安全策略

查看安全配置：

```bash
sed -n '1,220p' config/safety.yaml
```

运行安全测试：

```bash
python -m pytest tests/unit/test_safety.py tests/unit/test_sanitize.py -q
```

讲解重点：

- 路径白名单。
- 命令黑名单。
- 私有 IP 限制。
- 动态验证必须授权。
- 危险 payload 会被拒绝或脱敏。

## 18. 演示 7：工程质量

查看 CI：

```bash
sed -n '1,220p' .github/workflows/ci.yml
```

运行测试：

```bash
make test
```

运行 lint：

```bash
python -m ruff check .
```

查看 CVE 基准：

```bash
ls benchmarks/CVEs
find benchmarks/CVEs -maxdepth 2 -type f | sort | head -80
```

打开一个 CVE candidate：

```bash
python -m json.tool benchmarks/CVEs/CVE-2017-17215/candidate.json | head -120
```

讲解重点：

- 项目有自动化测试。
- 有 CI。
- 有历史 CVE fixture。
- 有 Schema 契约。
- 可重复执行。

## 19. 演示录制建议顺序

建议按这个顺序拍：

```bash
cd ~/FirmHound
source .venv/bin/activate

fsa doctor --json-output

fsa plan \
  --task "分析 Tenda AC15 路由器固件，已获得授权，执行完整固件漏洞挖掘流程" \
  --firmware-path firmware_samples/US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin \
  --authorization-holder "team-authorized" \
  --vendor Tenda \
  --model AC15 \
  --version V15.03.05.19_multi_TD01 \
  --depth full \
  --json-output

fsa analyze firmware_samples/US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin \
  --input-type firmware \
  --depth standard \
  --authorization-holder "team-authorized" \
  --vendor Tenda \
  --model AC15 \
  --version V15.03.05.19_multi_TD01 \
  --run-id demo-ac15-linux \
  --json-output

fsa status demo-ac15-linux --json-output
sed -n '1,220p' runs/demo-ac15-linux/report.md
find runs/demo-ac15-linux -maxdepth 3 -type f | sort | head -120

fsa analyze firmware_samples/openwrt-23.05.0-ramips-mt7620-zbtlink_zbt-we826-16m-squashfs-sysupgrade.bin \
  --input-type firmware \
  --depth standard \
  --authorization-holder "team-authorized" \
  --vendor OpenWrt \
  --model zbt-we826-16m \
  --version 23.05.0 \
  --run-id demo-openwrt-linux \
  --json-output

fsa analyze firmware_samples/US_BE3LProV1.0mt_V16.03.60.62_cn_TDC01.bin \
  --input-type firmware \
  --depth standard \
  --authorization-holder "team-authorized" \
  --vendor Tenda \
  --model BE3LPro \
  --version V16.03.60.62_cn_TDC01 \
  --run-id demo-be3lpro-linux \
  --json-output

fsa status demo-be3lpro-linux --json-output

python -m pytest tests/unit/test_safety.py tests/unit/test_schemas.py -q
python -m ruff check .
```

## 20. 常见问题

### 20.1 `fsa: command not found`

确认虚拟环境已激活：

```bash
source .venv/bin/activate
```

如果仍然不行，用：

```bash
fsa --help
```

### 20.2 `binwalk` 或 `unsquashfs` 找不到

按发行版重装（包名差异见 §3.2）：

```bash
sudo apt install -y binwalk squashfs-tools        # Debian / Ubuntu
sudo dnf install -y binwalk squashfs-tools        # Fedora / RHEL
sudo pacman -S --needed binwalk squashfs-tools    # Arch（binwalk 走 AUR）
sudo zypper install -y binwalk squashfs           # openSUSE
sudo apk add binwalk squashfs-tools               # Alpine
```

### 20.3 AC15 解包失败

大概率缺 `sasquatch`。重新安装：

```bash
cd /tmp
git clone --depth 1 https://github.com/onekey-sec/sasquatch.git
cd sasquatch
make
sudo make install
```

### 20.4 BE3LPro 为什么失败？

这是正常现象。该样本是加密固件，完整解包需要密钥或厂商解密逻辑。演示时将它讲成“加密固件识别和诚实降级能力”。

### 20.5 `pytest` 很慢怎么办？

演示时可以先跑轻量测试，把完整测试留到 CI：

```bash
python -m pytest tests/unit/test_safety.py tests/unit/test_schemas.py -q
```

完整测试结果以 CI 为准，本地只做快速回归即可。

### 20.6 GitHub 下载很慢怎么办？

可以在任意机器下载 zip 后拷进环境：

```bash
unzip FirmHound-main.zip
cd FirmHound-main
```

但长期使用更推荐 `git clone`，便于拉取更新与切分支。

## 21. 演示收尾总结词

可以这样收尾：

> FirmHound 覆盖固件漏洞挖掘的完整流程：自然语言任务规划、固件解包、攻击面识别、二进制审计、风险评分、反证验证、报告生成。安全策略、证据链和决策链保证过程可复现、可解释、可降级。正常固件能稳定跑通；加密固件会明确提示需要解密材料，并如实标注降级结果。
