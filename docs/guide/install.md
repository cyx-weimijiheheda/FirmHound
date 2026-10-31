# 各发行版安装指南

> 目标：在一台干净的 Linux 上把 FirmHound 跑起来。按你手上的发行版跳到对应小节，照抄命令即可。
>
> 全文只讲"装什么、为什么装、装完怎么验"。使用流程见 [`hunting-workflow.md`](hunting-workflow.md)。

## 0. 先确认环境

```bash
cat /etc/os-release      # 发行版与版本
uname -m                 # CPU 架构
python3 --version        # 需要 3.11–3.13（3.14 暂不支持）
```

FirmHound 面向 Linux 原生工具链。x86_64 与 aarch64 都可以；glibc 和 musl 都支持，区别只在包名。

> **Python 版本上限**：依赖链中的 PyO3 扩展（如 `pydantic-core`、`rpds-py`）目前要求
> Python ≤ 3.13，Python 3.14 会在 `pip install` 阶段报
> `pyo3 ... requires Python <= 3.13` 一类错误。Fedora 44 等新发行版的默认 `python3`
> 可能已经是 3.14，请显式安装/使用 Python 3.13，并执行
> `make dev PYTHON=python3.13 && make doctor`。

## 1. 依赖分三档

| 工具 | 用途 | 缺失时的降级行为 |
|---|---|---|
| `python3` 3.11–3.13 + `venv` | 跑 CLI | 装不上（3.14 暂不支持 PyO3 依赖） |
| `git`、`gcc`、`make` | 拉代码、编译 sasquatch | 部分解包能力缺失 |
| `file`、`binutils`（`readelf`/`strings`/`objdump`） | 文件识别、ELF 解析、反汇编 | 二进制阶段降级 |
| `binwalk` | 固件签名扫描 | 解包阶段无法自动识别布局 |
| `unsquashfs`（`squashfs-tools`） | 标准 SquashFS 解包 | 解包阶段失败 |
| `sasquatch` | 厂商魔改 SquashFS 解包 | 大量路由固件解不开 |
| `cpio` | initramfs、部分容器格式 | 对应格式解不开 |
| `7z`（`7zip` / `p7zip`） | ZIP / 7z / 部分 LZMA 容器 | 对应格式解不开 |
| `qemu-<arch>-static` | 用户态动态验证 | `LOCAL_VALIDATION` 阶段跳过 |
| `busybox` | 本机架构的 L1 加载自检；或 rootfs 里的目标 busybox | 对应架构的加载检查跳过 |
| `analyzeHeadless`（Ghidra） | 可选：DECOMPILE 的函数/调用图导出 | DECOMPILE 退回 pyelftools 符号/字符串摘要 |
| KLEE / BOND / SaTC / FirmRec | 外部分析器 | `EXTERNAL_ANALYSIS` 及以后跳过 |

前四档里任何一项缺失，只会让对应阶段降级，主流程仍然跑完并给出报告。装齐了才谈得上完整覆盖。

Ghidra 路径放在本地 `.env`（已被 gitignore），仓库配置保持通用：

```bash
GHIDRA_HEADLESS=/opt/ghidra/support/analyzeHeadless
BUSYBOX_BIN=/usr/bin/busybox
```

`fsa`/`scripts/run_external.py` 启动时会读取仓库根目录的 `.env`；也可以直接在 shell 里 export。
`fsa doctor` 会显示 `decompile` 是否找到 Ghidra。

FirmRec 的外部分析器需要额外的一整套工具链（JDK 18 / Ghidra 10.2.2 / Maven / PostgreSQL /
Python 3.9）。原生安装步骤与版本矩阵见
[`firmrec-native.md`](firmrec-native.md)；不安装时 FirmRec 阶段自动 `skipped`，不影响主链。

## 2. 按发行版安装

### 2.1 Debian / Ubuntu / Kali / Raspberry Pi OS / Mint

```bash
sudo apt update
sudo apt install -y \
    python3 python3-venv python3-dev \
    build-essential git \
    file binutils cpio \
    binwalk squashfs-tools p7zip-full \
    qemu-user-static
```

需要注意的点：

- Ubuntu 23.04+ 与 Debian 12+ 启用 PEP 668，`pip install` 会被拒绝。本项目全程用 `.venv`，不受影响；Python 包由 `.venv` 或 `pipx` 管理。
- Debian 12 仓库里的 binwalk 是 2.3.x，行为与 3.x 有差异；版式识别够用，自动解包建议直接上 `sasquatch`。
- `qemu-user-static` 一个包带全部架构，不需要按架构单独装。

### 2.2 Fedora

```bash
sudo dnf install -y \
    python3 python3-devel \
    gcc make git \
    file binutils cpio \
    binwalk squashfs-tools 7zip \
    qemu-user-static
```

需要注意的点：

- Fedora 仓库里**没有** `sasquatch`，只能源码编译，见 §3。
- Fedora 44+ 的默认 `python3` 可能是 3.14；请安装 `python3.13` 并用
  `make dev PYTHON=python3.13 && make doctor`，否则依赖链里的 PyO3 扩展会报
  `requires Python <= 3.13`。
- Fedora 40+ 的 `binwalk` 是 3.x（Rust 重写版），扫描更快，但解包仍然调用外部 `sasquatch` / `unsquashfs`，外部工具需要全部安装。
- `squashfs-tools` 4.6.1 起自带 lzma 解码，`unsquashfs -s` 能读出 `Compression lzma` 的超级块。部分厂商镜像的 fragment table 仍会解崩，这类镜像需要 `sasquatch`。
- Fedora 40 起 `p7zip` 已退役，7z 由 `7zip` 包提供。老版本仍是 `p7zip` + `p7zip-plugins`。

### 2.3 RHEL / CentOS Stream / Rocky / AlmaLinux

```bash
sudo dnf install -y epel-release
sudo dnf install -y \
    python3 python3-devel \
    gcc make git \
    file binutils cpio \
    binwalk squashfs-tools p7zip p7zip-plugins \
    qemu-user-static
```

需要注意的点：

- `binwalk`、`p7zip`、`qemu-user-static` 都在 EPEL，先装 `epel-release`。RHEL 10 / CentOS Stream 10 起 7z 换成了 `7zip` 包，`p7zip` 装不到就换它。
- RHEL 8 的默认 `python3` 是 3.6，太旧。装 `python3.11` 后用 `make dev PYTHON=python3.11 && make doctor`，或 `update-alternatives` 切换。
- 系统订阅未注册时 `dnf` 会直接报错，此时改用 Rocky / AlmaLinux 容器更方便。

### 2.4 Arch / Manjaro / EndeavourOS

```bash
sudo pacman -S --needed \
    python git base-devel \
    file binutils cpio \
    binwalk squashfs-tools p7zip

yay -S --needed qemu-user-static sasquatch
```

需要注意的点：

- `sasquatch` 与 `qemu-user-static` 都在 AUR，`pacman` 装不到，得用 `yay` / `paru`，或者走 §3 自己编译。
- `binwalk` 若在当前镜像的仓库里找不到，用 `yay -S binwalk` 或 `pipx install binwalk`。
- Arch 滚动更新频繁，升级后先 `make clean-venv && make dev` 重建 venv，再跑 `make doctor`。

### 2.5 openSUSE Leap / Tumbleweed

```bash
sudo zypper install -y \
    python3 python3-devel \
    gcc make git \
    file binutils cpio \
    squashfs p7zip \
    qemu-linux-user
```

需要注意的点：

- SquashFS 的包名是 **`squashfs`**，没有 `squashfs-tools`。`unsquashfs` 就在这个包里。
- QEMU 用户态包叫 `qemu-linux-user`，不是 `qemu-user-static`。
- `binwalk` 不在官方仓库，用 `pipx install binwalk`。

### 2.6 Alpine（容器场景）

```bash
apk add --no-cache \
    python3 py3-pip py3-virtualenv \
    build-base git \
    file binutils cpio \
    squashfs-tools p7zip zlib-dev xz-dev lzo-dev
```

需要注意的点：

- Alpine 用 musl，多数 Python 依赖有预编译 wheel，`capstone` 也在其中；万一没有，`build-base` 已经装好，pip 会本地编译。
- `qemu-arm`、`qemu-aarch64`、`qemu-mipsel` 要按目标架构分别装，没有 `qemu-user-static` 那种一次性全包。
- 容器里跑完整流程建议用 `debian:12` 或 `ubuntu:24.04` 做基础镜像，工具链最齐；Alpine 适合只需要静态分析的轻量场景。

### 2.7 其他发行版

| 发行版 | 基础依赖 |
|---|---|
| Void Linux | `sudo xbps-install -S python3 squashfs-tools cpio binutils p7zip file gcc make git` |
| Gentoo | `emerge dev-lang/python sys-fs/squashfs-tools app-arch/cpio sys-devel/binutils app-arch/p7zip sys-apps/file` |
| NixOS | `nix-shell -p python3 squashfsTools cpio binutils p7zip file gcc gnumake git` |

## 3. 编译 sasquatch

厂商固件里的 SquashFS 经常是改过的：头部字段不同、压缩参数不同、fragment table 编码不同。标准 `unsquashfs` 遇到这类镜像会报 `Unsupported compression` 或 `File system corruption detected`，`sasquatch` 就是给 `unsquashfs` 打上这些补丁的版本。

Debian 系与 Arch 有现成包；其余发行版源码编译。

### 3.1 编译依赖

```bash
# Debian / Ubuntu
sudo apt install -y zlib1g-dev liblzma-dev liblzo2-dev

# Fedora / RHEL 系
sudo dnf install -y zlib-devel xz-devel lzo-devel

# Arch
sudo pacman -S --needed zlib lzma lzo

# openSUSE
sudo zypper install -y zlib-devel xz-devel lzo-devel

# Alpine
apk add zlib-dev xz-dev lzo-dev
```

### 3.2 取源码

`devttys0/sasquatch` 仓库里只有 `build.sh`、`patches/patch0.txt` 和 README。squashfs-tools 4.3 的源码包不在仓库里，是 `build.sh` 运行时用 `wget` 现下的，所以 clone 完直接 `tar -zxf squashfs4.3.tar.gz` 会报找不到文件。

自己下比让 `build.sh` 跑更可控：`build.sh` 每次执行都会 `rm -rf squashfs4.3` 重新解压，下一步改过的编译选项会被冲掉；它的依赖安装那一步也只认 `apt-get`。

```bash
git clone --depth 1 https://github.com/devttys0/sasquatch.git
cd sasquatch

# 和 build.sh 用的是同一份源码包
curl -L -o squashfs4.3.tar.gz \
  https://downloads.sourceforge.net/project/squashfs/squashfs/squashfs4.3/squashfs4.3.tar.gz

tar -zxf squashfs4.3.tar.gz
cd squashfs4.3
patch -p0 < ../patches/patch0.txt
cd squashfs-tools
```

没有 `curl` 就把那行换成 `wget https://downloads.sourceforge.net/project/squashfs/squashfs/squashfs4.3/squashfs4.3.tar.gz`，地址一样。

### 3.3 放宽编译选项

Makefile 第 129 行是 `-Wall -Werror`，而 squashfs-tools 4.3 是 2014 年的代码，现代 gcc 会对它发三条告警，被 `-Werror` 直接顶成错误：

| 报错 | 原因 | 补的选项 |
|---|---|---|
| `error: this 'if' clause does not guard... [-Werror=misleading-indentation]` | gcc 13 起缩进告警更严格 | `-Wno-error` |
| `error: passing argument 2 of 'signal' from incompatible pointer type` | 老代码写的是 `void handler()`，gcc 14 起这条默认就是错误 | `-Wno-incompatible-pointer-types` |
| `multiple definition of 'verbose'`（链接阶段） | `error.h` 里在头文件定义变量，gcc 10 起默认 `-fno-common` 不再合并 | `-fcommon` |

一条命令加齐：

```bash
sed -i 's/-Wall -Werror/-Wall -Wno-error -Wno-incompatible-pointer-types -fcommon/' Makefile
```

前两条出现在编译 `unsquashfs.c` 时，第三条出现在最后的 `g++` 链接时。只去掉 `-Werror` 会在链接阶段再失败一次，三个选项要一起加。

### 3.4 编译安装

```bash
make -j"$(nproc)"
sudo make install
```

`make` 只在当前目录生成一个 `sasquatch` 二进制，不会进 `PATH`，所以编完还是 `command not found`。安装是下一步 `make install`：它做的是 `cp sasquatch $(INSTALL_DIR)`，默认 `INSTALL_DIR` 是 `/usr/local/bin`。

不想用 `sudo` 就换个装的位置，前提是那个目录在 `PATH` 里：

```bash
make install INSTALL_DIR="$HOME/.local/bin"
```

### 3.5 验证

```bash
command -v sasquatch && sasquatch -version
```

版本号显示 `unsquashfs version 4.3` 是正常的——sasquatch 就是打了补丁的 unsquashfs，沿用上游版本号。

### 3.6 换一个分支

`onekey-sec/sasquatch` 基于 squashfs-tools 4.5.1，已经修掉上面三处编译问题，不需要 `sed`：

```bash
git clone --depth 1 https://github.com/onekey-sec/sasquatch.git
cd sasquatch/squashfs-tools
make -j"$(nproc)" && sudo make install
```

代价是多一个依赖：Fedora 上要 `sudo dnf install -y lz4-devel`，Debian 上是 `liblz4-dev`，否则编到 `lz4_wrapper.c` 会因缺 `lz4.h` 中断。

## 4. 装项目本体

```bash
git clone https://github.com/cyx-weimijiheheda/FirmHound.git
cd FirmHound
make dev
make doctor
```

`make dev` 建 `.venv`、装 `requirements.txt`、以 editable 方式装本项目，并从
`config/*.example.yaml` 复制出本地 `config/dev.yaml`、`config/models.yaml`、
`config/safety.yaml`；`make doctor` 单独跑一次环境自检。本地配置已被
`.gitignore` 忽略，你的模型地址、预算和安全白名单修改不会进提交。

手动等价写法：

```bash
python3.13 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/pip install -e .
.venv/bin/python -m fsa.cli doctor
```

只想要命令、不读源码：

```bash
pipx install .
```

Python 解释器不在默认路径时用 `make dev PYTHON=python3.13 && make doctor`；请保持在 3.11–3.13
范围内运行；3.14 尚未满足 PyO3 依赖要求。

## 5. 验证

```bash
make doctor
```

输出里的 `platform` 一行给出当前发行版、包管理器与 libc；`commands` 一行列出缺失的工具，并按当前发行版的包名给出安装提示（Fedora 上是 `dnf: squashfs-tools`，openSUSE 上是 `zypper: squashfs`）。

手工核对一遍关键工具：

```bash
for t in binwalk unsquashfs sasquatch cpio 7z readelf strings; do
    printf '%-12s %s\n' "$t" "$(command -v "$t" || echo MISSING)"
done
```

`MISSING` 不影响 `make test`，只影响真实固件的解包与动态验证。

## 6. 排错

| 现象 | 原因 | 处理 |
|---|---|---|
| `pip` 报 `externally-managed-environment` | PEP 668 | 用 `.venv` 或 `pipx` 管理包 |
| `binwalk: command not found` | pipx 装的没进 PATH | `export PATH="$HOME/.local/bin:$PATH"` |
| `unsquashfs: command not found` | 包名不符 | openSUSE 装 `squashfs`，其余装 `squashfs-tools` |
| `sasquatch: command not found` | Fedora / RHEL 无包 | §3 源码编译 |
| `sasquatch` 编译报错 | 缺 `zlib`/`xz`/`lzo` 开发包，或 gcc 太新 | 补齐 dev 包；编译选项按 §3 的三条改（`-Wno-error -Wno-incompatible-pointer-types -fcommon`） |
| `sasquatch` 链接报 `multiple definition` | gcc 10+ 默认 `-fno-common` | 加 `-fcommon` 后 `make clean && make` |
| `7z x` 报 `Cannot open the file as archive` | 该镜像不是 7z 认识的容器 | 正常现象，交给 `unsquashfs` / `sasquatch` |
| `fsa analyze` 报 `no rootfs candidate found` | 解包器没产出 rootfs | `fsa unpack-diagnose <固件>` 看卡在哪层，补齐 §1 的工具 |
| QEMU 报 `Could not open ... : No such file` | 缺对应架构的 qemu | Debian 系装 `qemu-user-static`；Alpine 按架构装 `qemu-<arch>` |
| `make test` 很慢 | 含覆盖率统计 | `pytest tests/unit -q --no-cov` 只跑单测 |

## 7. 容器里跑

一份能直接用的镜像定义，省掉按发行版逐个装：

```dockerfile
FROM debian:12
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-venv python3-dev build-essential git \
        file binutils cpio binwalk squashfs-tools p7zip-full qemu-user-static \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /work
```

固件目录与 `runs/` 挂载进容器即可，CLI 的路径白名单按 `config/safety.yaml` 生效。

---

返回 [README](../../README.md) · 下一步：[`hunting-workflow.md`](hunting-workflow.md)
