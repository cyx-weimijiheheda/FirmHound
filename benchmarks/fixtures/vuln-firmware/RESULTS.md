# RESULTS.md — 实测结果（FirmHound，2026-10-27）

环境：FirmHound 上游 main `5ae35a3`（含 PR #2），`--depth full`，
本机离线运行。两种输入各跑一次，结论一致。

## 总览

| 输入 | 攻击面 | ELF | 候选 | 复核（Top-5） |
|------|--------|-----|------|----------------|
| `fixture-fw-v1.0.bin` | 7 | 5 | 8 | NEED_DYNAMIC 2 / DOWNGRADE 1 / REJECT 2 |
| `rootfs/` 目录 | 7 | 5 | 8（同分同序） | 与左完全一致 |

候选风险分：17, 17, 14, 14, 14, 11, 11, 10。

## 逐项对照 EXPECTED

- **V1（httpd formPing → system）**：17 分，映射到 `/goform/formPing`
  表面，**同函数调用链已演示**（2 步），反证 10 问**无一条成立**，
  裁决 NEED_DYNAMIC 且**保留满分 17**——静态路径能拿到的最强结论。✅
- **V2（httpd formLogin → strcpy）**：与 V1 的 sprintf 候选同为 14 分
  并进入复核，NEED_DYNAMIC 保留满分。✅（注：httpd 三个候选共用
  formPing 表面归属，handler 级粒度目前到二进制+首选表面为止。）
- **V4（upnpd recv → strcpy）**：11 分、调用链已演示，进入候选集；
  未进 Top-5 复核（复核名额被更高分候选占满）。✅
- **V5（upnpd → syslog 格式串）**：10 分进入候选集。✅（syslog 不在
  调用链汇名单内，chain 为空属预期。）
- **V6（wandetect nvram → popen）**：17 分（并列最高）、调用链已演示，
  但裁决 **REJECT**，理由「Source is not a real external input
  (e.g., constant or config key)」——即 EXPECTED 中标注的口径分歧点，
  现状已钉住。⚠️
- **V7（ping.cgi）**：出现在 CGI 攻击面枚举中（cgi 类共 3 个表面：
  ping.cgi + formPing + formLogin）。✅
- **N1（safed 负样本）**：产生 1 条 format_string 候选
  （`__snprintf_chk`，11 分），复核后因无调用链 **DOWNGRADE 至 1 分**，
  未被确认。✅ 误报控制通过。
- V3/V8/V9/V10（硬编码口令、telnet、弱配置、私钥占位）：属字符串/
  配置面证据，不在二进制候选口径内，未单独核验。

## 顺带发现的两个环境/工具问题

1. **子进程 stdin 未重定向可致流水线挂起**：`fsa/utils/proc.py` 的
   `run_command` 未设置 `stdin`，子工具继承调用方 stdin；当 stdin 是
   不关闭的管道时，解包阶段的 `7z x` 会无限等待（实测挂起 6 分钟以上，
   手动以 `</dev/null` 运行同一命令瞬间成功）。以 `</dev/null` 启动
   CLI 后全程约 90 秒完成。建议 `run_command` 默认 `stdin=DEVNULL`。
2. **SquashFS 位于偏移 0 时解包会双重提取**，同一批二进制以两种
   相对路径各进一次候选集（16 条重复候选）；加 116 字节厂商头使
   偏移非零后恢复单份（8 条）。真实固件均有头，故影响面有限，
   但偏移 0 的裸镜像输入会触发。
