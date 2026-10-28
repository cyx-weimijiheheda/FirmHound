# 本地多漏洞固件样本

项目提供一个完全合成的实验固件，用于验证解包、攻击面发现、ELF 分析、候选排序和外部分析器接入。
它不监听网络，也不连接外部主机；其中的漏洞是刻意写入的，只应在本地测试目录中使用。

## 构建

```bash
make lab-firmware
```

产物：

- `firmware_samples/firmhound-lab-0.1.0/rootfs/`：可直接作为 `rootfs` 输入；
- `firmware_samples/firmhound-lab-0.1.0.squashfs`：可作为 `firmware` 输入；
- `firmware_samples/firmhound-lab-0.1.0/lab_firmware.json`：预期漏洞清单；
- `usr/src/lab_httpd.c`：复制进 rootfs 的源代码，方便 KLEE harness 模式建模。

## 运行 FirmHound

```bash
fsa analyze firmware_samples/firmhound-lab-0.1.0.squashfs \
  --input-type firmware \
  --authorization-holder "local-lab" \
  --depth standard \
  --run-id lab-firmware-standard
```

如果只想测试已经生成的 rootfs：

```bash
fsa analyze firmware_samples/firmhound-lab-0.1.0/rootfs \
  --input-type rootfs \
  --authorization-holder "local-lab" \
  --depth standard \
  --run-id lab-rootfs-standard
```

预期可见 `system`、`strcpy`、`printf`、`fopen` 和 CGI `eval` 相关候选。它们是测试夹具中的已知事实，不代表真实产品漏洞。

## 原生 KLEE

当前仓库的原生 KLEE 安装位置约定为：

- `vendor/klee-install15/bin/klee`；
- `vendor/klee-deps15/usr/lib64/llvm15/bin/clang`；
- `vendor/klee-deps15/usr/lib64/libz3.so`。

使用 `config/external-native.example.yaml` 作为外部分析器配置：

```bash
python scripts/run_external.py \
  --tool klee \
  --run-dir runs/lab-firmware-standard-2 \
  --config config/external-native.example.yaml
```

KLEE 的 S2 harness 会把危险 sink 替换为桩函数，不会执行 shell 或向网络发包；`infeasible` 结果仍只作为反证，不会自动删除候选。
