# vuln-firmware-fixture — 故意植入漏洞的固件测试样本

一个**小而确定**的路由器固件样本，为 FirmHound 这类固件分析流水线
准备：每个漏洞都真实存在于二进制/脚本/配置中，入口、源、汇、所在
函数全部写死在 [EXPECTED.md](EXPECTED.md) 里 —— 分析器应检出什么、
不该检出什么，一一对应，可直接当回归基准（oracle）使用。

## 为什么需要它

真实固件（如 DIR-859）适合做压力测试，但没有标准答案：检出 0 个
确认漏洞时，分不清是工具不行还是证据链断了。本样本补上这一环：

- **ARM32 目标**：调用链恢复走 ARM32 反汇编路径，本样本的候选应当
  能拿到同函数调用链 —— 这是 MIPS 样本给不了的验证点；
- **同函数源/汇**：每个二进制漏洞的 source 与 sink 都在同一个函数
  里，排除跨函数数据流的干扰，失败即可定位到具体环节；
- **带负样本**：`safed` 用白名单 + 长度检查 + `snprintf` 安全处理
  同类输入，被确认即误报；
- **两种输入形态**：SquashFS 镜像与 rootfs 目录各一份，结论应一致。

## 构建与试跑

```bash
# 依赖（Debian/Ubuntu 示例，其他发行版见仓库 README 的依赖矩阵）
sudo apt install gcc-arm-linux-gnueabi squashfs-tools

bash build.sh      # 或 chmod +x build.sh 后 ./build.sh

../../../.venv/bin/fsa --config ../../../config/dev.yaml analyze \
  dist/fixture-fw-v1.0.bin --input-type firmware --depth full \
  --authorization-holder "fixture 作者" --run-id fixture-v1
```

| 文件 | 说明 |
|------|------|
| `dist/fixture-fw-v1.0.bin` | 构建产物：SquashFS 固件镜像（分析器输入，不入库） |
| `dist/rootfs/` | 构建产物：同一 rootfs 的目录形态 |
| `src/` | 全部源码（httpd / upnpd / wandetect / libnvram / safed） |
| `rootfs/` | 静态骨架（CGI 脚本、启动脚本、配置） |
| `build.sh` | 一键重建（需 `gcc-arm-linux-gnueabi`、`squashfs-tools`） |
| `EXPECTED.md` | 标准答案：V1–V10 正样本、N1 负样本、通过标准 |
| `RESULTS.md` | 在当前主线上的实测结果（分数、裁决与已知分歧） |

## 漏洞速览

- httpd：`formPing` 命令注入（QUERY_STRING → system）、`formLogin`
  Cookie 溢出（→ strcpy 32B 缓冲）、硬编码口令；
- upnpd：`recv` → `strcpy` 溢出、网络数据作 `syslog` 格式串；
- wandetect：`nvram_get` 配置值 → `popen` 命令注入；
- 脚本/配置：CGI 无引号展开、`telnetd -l /bin/sh`、弱口令与明文
  WiFi 口令、私钥文件占位（不含真实密钥材料）。

## 安全说明

本样本仅供本地离线分析测试：二进制不会被部署到任何真实设备，
镜像内不含真实密钥/口令材料（口令均为虚构的出厂默认值样式，
主机私钥文件为占位文本）。请勿刷入真实硬件。
