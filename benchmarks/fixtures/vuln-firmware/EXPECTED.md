# EXPECTED.md — 预期分析结果（标准答案）

本固件是**故意植入漏洞的分析器测试样本**：每个漏洞都有确定的
入口 / 源（source）/ 汇（sink）/ 所在函数，分析器应检出什么、
不该检出什么，全部写死在这里，可直接用作回归基准。

构建：`./build.sh` → `dist/fixture-fw-v1.0.bin`（SquashFS 镜像）
与 `dist/rootfs/`（同一 rootfs 的目录形态，两种输入都应可分析）。

目标平台 ARM32（little-endian，动态链接，已 strip）——因为调用链
恢复走 ARM32 反汇编路径，这是该样本与 MIPS 真实固件样本的关键区别：
本样本的候选**应当能拿到同函数调用链**，而不只是 source/sink 共存。

## 正样本：应当检出

| ID | 载体 | 类型 | 入口 / 源 | 汇 | 关键事实 |
|----|------|------|-----------|----|----------|
| V1 | `usr/sbin/httpd` → `formPing` | 命令注入 | `getenv("QUERY_STRING")` | `sprintf` → `system` | 源与汇同函数；无任何校验；handler 经 `websFormDefine("formPing", …)` 注册；httpd 在 `etc/init.d/rcS` 中启动 |
| V2 | `usr/sbin/httpd` → `formLogin` | 栈溢出 | `getenv("HTTP_COOKIE")` | `strcpy` → 32 字节栈缓冲 | 源与汇同函数；httpd 无栈保护、无 PIE（加固检查应报警） |
| V3 | `usr/sbin/httpd` → `formLogin` | 硬编码口令 | 字符串 `admin:defaultpass` 与 cookie 值 `strcmp` 比较 | — | 字符串证据即可定位 |
| V4 | `usr/sbin/upnpd` → `handle_request` | 栈溢出 | `recv()` 网络数据 | `strcpy` → 64 字节栈缓冲 | 源与汇同函数；upnpd 在 rcS 中启动 |
| V5 | `usr/sbin/upnpd` → `handle_request` | 格式化字符串 | `recv()` 网络数据 | `syslog(LOG_INFO, request)` 直接作格式串 | 与 V4 同一入口、不同汇 |
| V6 | `usr/sbin/wandetect` → `main` | 命令注入 | `nvram_get("wan_ipaddr")`（动态导入，`lib/libnvram.so`） | `sprintf` → `popen` | 配置源；wandetect 在 rcS 中启动。**口径分歧点**：候选会生成且评分最高档（实测 17），但当前反证规则把 config 源判为「非真实外部输入」而 REJECT——而该类产品中 nvram 值实际可经 Web 界面设置（多个真实 CVE 即此路径）。本样本在此钉住现状：若项目调整该口径，此行预期需同步更新 |
| V7 | `www/cgi-bin/ping.cgi` | 命令注入（脚本） | `$QUERY_STRING` | 无引号展开进 shell 命令行 | CGI 表面应被枚举到 |
| V8 | `etc/init.d/rcS` | 不安全的服务暴露 | `telnetd -l /bin/sh &` | — | 无口令 telnet 直接给 shell |
| V9 | `etc/config/wireless` | 弱/默认口令 | WPA 口令 `defaultpass` 明文、文件权限 0666 | — | 配置面问题 |
| V10 | `etc/dropbear/dropbear_rsa_host_key` | 镜像内嵌私钥（占位） | 固件镜像携带主机私钥文件 | — | 文件为占位文本，不含真实密钥材料；只验证「该路径/类目被注意到」，不要求内容级判定 |

## 负样本：不应当被确认（误报控制）

| ID | 载体 | 为什么安全 |
|----|------|-----------|
| N1 | `usr/sbin/safed` → `handle_status` | 同样读 `QUERY_STRING`，但有白名单（`strncmp`）、长度检查（`strlen`）与有界 `snprintf`，且无 `system`/`popen`/`strcpy`。**允许**出现低分候选，**不允许**被确认（confirmed / high-confidence）。safed 编译时开启栈保护 + PIE，加固检查应对照组给出好评。 |

## 通过标准（建议）

1. V1、V2、V4、V6 至少进入候选集，且风险分位于全样本前列；
2. V1/V2/V4 的候选应带有**已演示的同函数调用链**（这是本样本与
   DIR-859 等 MIPS 样本的预期差异点；若拿不到，调用链恢复即存在缺口）；
3. V7 应出现在 CGI / Web 攻击面枚举中；
4. N1 不得被确认；
5. 两种输入形态（`.bin` 固件镜像、`rootfs/` 目录）结论应一致。
