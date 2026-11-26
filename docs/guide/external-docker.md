# SaTC / FirmRec Docker 接入

宿主系统依赖按 [README 依赖矩阵](../../README.md) 安装。先确保
`docker version` 能访问 daemon；支持现有 rootless Docker context。
项目 Python 命令仍使用 `.venv/bin/python`。

## 构建工作镜像

SaTC 的上游入口启动交互 shell；FirmHound 使用非交互包装，启动容器内的
JS 解析服务，并执行 runner 传入的命令，不发布宿主端口。

```bash
docker pull smile0304/satc:latest
docker build -f docker/satc.Dockerfile -t firmhound/satc:local docker
docker run --rm firmhound/satc:local python satc.py --help
```

FirmRec 需要基础依赖镜像和上游工作源码。checkout 保存在项目白名单目录内：

```bash
git clone --depth 1 https://github.com/seclab-fudan/FirmRec.git vendor/FirmRec
docker pull xylearn/firmrec-base:latest
docker build -f "$PWD/docker/firmrec.Dockerfile" -t firmhound/firmrec:local vendor/FirmRec
docker run --rm firmhound/firmrec:local -lc 'python -c "import angr, psycopg2"'
```

上游来源：[SaTC](https://github.com/NSSL-SJTU/SaTC)、
[FirmRec](https://github.com/seclab-fudan/FirmRec)。记录本地镜像 ID 和源码 commit，
以便复现；`latest` 会随上游变动。
FirmRec 工作镜像默认 `PARALLEL=1`，并恢复 login shell 中的 conda/JDK 路径。

## 配置与运行

`config/external-docker.example.yaml` 提供独立配置；只默认启用 SaTC。
对已有且属于授权范围的 run 执行：

```bash
.venv/bin/python scripts/run_external.py --tool satc --run-dir runs/<id> \
  --config config/external-docker.example.yaml
```

FirmRec 还需要上游格式的已知漏洞树（`<VENDOR>/<NAME>/meta.json` 和对应固件）。
可从上游 README 的 `inout.tar.gz` 示例提取 `vuln_info` 到
`vendor/firmrec-data/vuln_info`。这份数据不在工作镜像内，必须单独保留。
准备好数据后，将配置复制到本地配置文件，设置 `external.firmrec.enabled: true`，
再执行 `--tool firmrec`。镜像存在不代表样本库完整或漏洞已验证。
入口自检也需要挂载任务数据：

```bash
docker run --rm -v "$PWD/tmp/external/firmrec/<id>/inout:/root/inout" \
  firmhound/firmrec:local -lc 'python -c "from firmrec.pipeline.gen_cmds import firmrec_main; print(\"pipeline import ok\")"'
```

FirmRec 仅用于复发检测，Blind Run 仍强制禁用。

KLEE 的本地安装继续使用 `config/external-native.example.yaml`。
BOND 使用项目内置实现，目标和授权约束见原有配置。

## 共用 Ghidra 与清理构建材料

`decompile.backend: auto` 优先使用 `decompile.docker_image`（默认
`firmhound/firmrec:local`）；`docker` 模式缺镜像时直接降级，`ghidra` 模式显式使用
本机工具。主流程和 BOND 共用导出器；容器只挂载选中的 ELF、只读脚本和输出目录，
网络关闭。输入和输出路径先经过 `PolicyEngine.check_path`。
`make firmrec-doctor` 按实际选择的后端检查：Docker 模式检查镜像和样本配置，
不再要求宿主重复安装 Python 3.9、PostgreSQL 或 Ghidra。

该镜像使用 Ghidra 10.2.2；本机其他版本不能视为完全等价，删除前应验证实际使用的
导出脚本和目标架构。工作镜像就绪且所需数据已移出 checkout 后，可删除
`vendor/FirmRec` 的构建源码；以后重建时按上述步骤重新 clone。
KLEE 仍使用独立的 native LLVM 15 工具链，必须保留 `vendor/klee-install15` 和
`vendor/klee-deps15`，不能因 FirmRec 镜像存在而删除它们。

镜像启动、依赖检查与完整固件分析分别验证；无结果、缺数据或超时必须保留
`limitation`。下载和构建日志可放在已忽略的 `tmp/docker-setup/`。
