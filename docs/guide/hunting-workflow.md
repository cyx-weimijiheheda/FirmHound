# FirmHound 固件猎犬 · 小白全链路挖洞教程

> 从「下载一个固件」到「拿到一份漏洞报告」，全程手把手。
> 面向新加入的工程师：跟着走一遍就能独立完成一次授权范围内的固件评估。
> 本文假设你在 **Linux** 上操作，发行版不限（Debian/Ubuntu、Fedora/RHEL、Arch、openSUSE、Alpine 容器均可），只有包名和工具安装方式不同；Windows/WSL 不在支持范围内。

---

## 0. 先回答你最关心的问题：需要什么环境？

**结论：一台 Linux 机器（或云主机 / 容器）就够，所有步骤都在同一个 shell 里完成。**

| 环节 | 命令 | 依赖 |
|---|---|---|
| 下载固件 | 浏览器 / `wget` | — |
| **解包固件** | `binwalk` / `sasquatch` / `unsquashfs` | Linux 工具链（各发行版包名见 [deployment.md §3.2](deployment.md)） |
| 静态分析 | `fsa analyze` | 纯 Python，无额外依赖 |
| 人工审计 | `strings` / `readelf` / `objdump` / Ghidra | 可选 |
| 动态验证 | `qemu-*-static` | 可选，需安全门四项全过 |

装好工具链后，两条命令就能跑完整个静态流程：

```bash
binwalk -e -M firmware_samples/xxx.bin -C tmp/unpacked
fsa analyze tmp/unpacked/_xxx.bin.extracted/squashfs-root --input-type rootfs \
  --authorization-holder "设备所有者" --run-id hunt1
```

---

## 1. 准备工作（只做一次）

### 1.1 拿到项目并进到项目根目录

```bash
git clone https://github.com/<你的账号>/FirmHound.git ~/FirmHound
cd ~/FirmHound
```

**以后所有命令都在这个目录里执行**（下文叫"项目根目录"）。

### 1.2 建虚拟环境并安装

```bash
make dev                        # 建 .venv + 装依赖 + editable 安装
source .venv/bin/activate       # 让 fsa 进 PATH
```

`fsa` 装在 `.venv/bin`，每个新 shell 先 `source .venv/bin/activate`。不想用 make 时，手动跑
`python3 -m venv .venv && .venv/bin/pip install -r requirements.txt && .venv/bin/pip install -e .`。

### 1.3 确认解包工具就绪（一次性）

```bash
which binwalk unsquashfs sasquatch strings readelf
```

四个以上有输出就说明解包与二进制工具 OK。缺 sasquatch 时按 README 的「安装 sasquatch」一节编译一份——很多路由固件用的是非标准 SquashFS，`unsquashfs` 解不开。

### 1.4 自检（跑通证明环境 OK）

```bash
fsa doctor
make test
```

`fsa doctor` 显示 `status: ok`、测试最后一行看到全部 passed，就可以开始挖洞了。缺外部工具只会显示 degraded，不影响静态分析。

---

## 2. 第一步：选目标品牌，下载固件

结合你们队复现过的 CVE 品牌，优先选**还在更新固件的**产品（最新固件才有挖新洞的价值）。

| 品牌 | 复现过的型号（历史 CVE） | 官方固件下载入口 | 说明 |
|---|---|---|---|
| **Tenda 腾达** | AC15（CVE-2020-10987） | <https://www.tenda.com.cn/api/product/help/AC15> | AC15 最新 V15.03.05.19（2017 后未更新，可换 AC 系列新型号） |
| **D-Link** | DIR-859（CVE-2019-17621）、DIR-850L 等 | <https://support.dlink.com> | DIR 系列仍在更新，DIR-X 新系列也可看 |
| **NETGEAR 网件** | R7000（CVE-2021-31802） | <https://www.netgear.com/support/product/R7000.aspx> | R7000 最新 1.0.11.216 / 1.0.12.216（2025-07 仍在发安全更新） |
| **TP-Link** | Archer 系列（CVE-2020-9373） | <https://www.tp-link.com/cn/support/download/> | 搜索型号即可 |
| **华为** | HG532e（CVE-2017-17215） | <https://support.huawei.com> | 企业级产品更新频繁，可挖 |
| **MikroTik** | RouterOS（CVE-2023-32154） | <https://mikrotik.com/download> | RouterOS 7.x 持续更新，靶子多 |

**新手建议选**：D-Link DIR-859（有现成复现经验 + 固件还在更新）或 NETGEAR R7000（官方持续发安全补丁，说明漏洞在被修，同类新洞概率高）。

下载时注意：

1. 选 **Router Firmware / 升级软件** 那一栏；
2. 文件一般是 `.zip` 或 `.bin`，下载完**解压 zip**，拿到 `.bin` 固件文件；
3. 记录下载的**版本号**（如 V1.0.12.216），后面报告要用。

---

## 3. 第二步：把固件放到指定文件夹

在项目根目录下建一个 `firmware_samples/`（CLI 的安全白名单允许目录），把固件放进去：

```
~/FirmHound/firmware_samples/
    └── DIR-859_Ax_FW_113b03.bin     ← 你的固件（举例）
```

> 注意：把固件放进 `firmware_samples/`、`runs/`、`tmp/` 或 `tests/fixtures/`，这四个目录在安全策略白名单内。

---

## 4. 第三步：解包固件（关键一步）

固件是个"打包文件"，解包后才能看到里面的程序（httpd、upnpd、cgi 等）。

```bash
cd ~/FirmHound
binwalk -e -M firmware_samples/DIR-859_Ax_FW_113b03.bin -C tmp/unpacked
```

参数解释：

- `-e` 提取；`-M` 递归提取（固件里可能还有嵌套的压缩层）
- `-C` 指定输出目录

跑完后检查解包结果：

```bash
ls tmp/unpacked
```

**找 rootfs 目录**：一般叫 `squashfs-root`、`_rootfs`、`_squashfs`，里面有 `bin/`、`etc/`、`usr/`、`www/` 等目录。**后面分析就认准这个目录**。

> 如果 binwalk 没解出 squashfs-root：用 `sasquatch` 单独解：
>
> ```bash
> sasquatch -d tmp/squashfs-root firmware_samples/<固件名>.bin
> ```
>
> 还不行就用 `fsa unpack-diagnose <固件>` 看它建议的下一步（是加密、是自定义头、还是需要别的提取器）。工具会如实报告需要解密材料。

---

## 5. 第四步：跑 CLI 静态分析（重点！）

解包出 rootfs 后，执行：

```bash
fsa analyze tmp/unpacked/_DIR-859_Ax_FW_113b03.bin.extracted/squashfs-root \
  --input-type rootfs \
  --authorization-holder "设备所有者" \
  --run-id hunt1
```

> `--authorization-holder` 是必填项（只做授权测试）。路径换成第 4 步实际找到的 rootfs。

命令会按阶段自动执行：解包确认 → 目录清单 → Web 枚举 → 启动脚本 → ELF 分析 → 静态审计 → 十维评分 → 反证验证 → 出报告。

**实时进度**：默认在终端显示当前阶段，每 0.5 秒刷新耗时；长阶段不会看起来像卡死。

```text
[2/11] BASELINE  ok  0.0s
[3/11] UNPACK  running  6.4s
[4/11] SURFACE  ok  1.2s
[5/12] AGENT_LOOP  agent step 123/5000 · cand-c32784f3ddeb ·
  cross_check_imports_strings · selector=model · tok 12400/2000000 ·
  calls 45/2000 · ev 515 · missing 2 · resolved 8/484 · skipped 12
[5/12] AGENT_LOOP  running  42.1s
```

最后一个 `[5/12] AGENT_LOOP running 42.1s` 是原地刷新的状态行；上面的明细按终端
宽度自动分行，写入 scrollback，不会再覆盖或反复堆叠把终端盖满。`--agent` 时
Agent 每 10 步汇报一次当前候选、动作、token/调用数、证据数和候选进度。可以调整：

```bash
# 0.2 秒刷新；每 25 步汇报；显示 token；打印模型选择
fsa analyze <rootfs> --authorization-holder "设备所有者" --agent --progress \
  --progress-interval 0.2 --agent-progress-every 25 \
  --agent-show-tokens --agent-print-model

# 不显示 token / 不打印模型选择
... --no-agent-show-tokens --no-agent-print-model
```

`--agent-print-model` 只打印已验证的模型选择（动作、置信度、理由），不打印原始
prompt、原始回复或思维链。

后台跑时把进度写进日志，再用 `tail -f` 看：

```bash
nohup fsa analyze tmp/unpacked/<extracted>/squashfs-root \
  --input-type rootfs \
  --authorization-holder "设备所有者" \
  --run-id hunt1 --progress \
  > runs/hunt1.out 2> runs/hunt1.progress.log &

tail -f runs/hunt1.progress.log     # 另开一个终端看实时阶段
```

不需要进度行时加 `--no-progress`；用 `--json-output` 时默认关闭，显式 `--progress`
也只会写 stderr，JSON 仍从 stdout 输出。

跑完看到：

```
status: done
run_dir: /home/<你>/FirmHound/runs/hunt1
```

就成功了。报告在 `runs/hunt1/report.md`，结构化结果在 `runs/hunt1/candidates.json`。

写报告时重点看三节：

- 第 14 节「风险排序」：Top 10 候选的二进制/入口、Source→Sink、调用链、认证和证据；
- 第 15 节「反证验证结果」：哪些候选被复核、哪些未复核、为什么降级/排除；
- 第 21 节「限制与待验证事实」：反编译是否降级、固件架构是否支持调用链恢复、
  候选是否能追溯到解包文件。`accepted=0` 表示证据未闭合；确认或否定设备漏洞需要后续验证。

---

## 6. 第五步：看报告（人工审计开始）

打开 `runs/hunt1/report.md`（也可以直接拖给 WorkBuddy 让它渲染成网页）。报告开头就是摘要：

**报告怎么看（小白版）：**

1. **看「检出候选」表**：有没有 HIGH/CRITICAL 的候选？Sink 是不是 `system`/`eval`？
   ```
   | 候选              | 二进制      | Sink   | 分数 | 等级 |
   | e2e-elf-httpd     | bin/httpd   | system | 23   | HIGH |
   ```
2. **看分数**：≥24 CRITICAL、18–23 HIGH。HIGH 以上才值得花时间人工审。
3. **看证据链**：报告会写清楚 source（输入在哪）→ sink（危险函数在哪），以及它自己列出的**反证**（`counterevidence`）。

想看单个候选的完整账本：

```bash
fsa explain hunt1 --candidate-id <候选ID> --format markdown
```

---

## 7. 第六步：人工审计

CLI 负责"找可疑点"，**人工审计负责"确认真漏洞"**。对每个 HIGH 以上候选，按下面 10 问逐一排查（Skill 05 的方法论）：

| # | 问题 | 怎么查 |
|---|---|---|
| 1 | 输入真的来自外部？ | 是 HTTP 参数 / Header / Cookie / SOAP 吗？ |
| 2 | 攻击者能控制吗？ | 值能被请求里任意设置吗？ |
| 3 | 真的到危险函数了？ | 反编译看调用链：handler → ... → system |
| 4 | 中间有过滤吗？ | 有没有白名单 / 黑名单 / 长度检查？ |
| 5 | 调用链可达吗？ | 这个 handler 有没有被 httpd 路由注册？ |
| 6 | 程序启动了吗？ | `etc/init.d` 或 `rcS` 里有它吗？ |
| 7 | 需要认证吗？ | 登录后才有权限，还是有认证绕过？ |
| 8 | 是调试功能吗？ | 函数名含 debug/test/diag？ |
| 9 | 有平台限制吗？ | 编译开关 / 特定硬件才走这条路径？ |
| 10 | 有矛盾证据吗？ | 有没有证据说明它不可达？ |

**人工审计工具**：

```bash
# 反编译（任选）
ghidra  或  objdump -d httpd | grep -A 20 formexeCommand

# 看字符串（找可疑的命令拼接模板）
strings httpd | grep -E "%s|system|reboot"

# 看导入（确认调用了 system）
readelf -s httpd | grep system
```

**判定规则**（写报告时用）：

- 10 问全过 → `confirmed-issue`（确认漏洞）
- 有认证/过滤但可绕过 → `high-confidence-candidate`
- 有一项不满足 → 降级或标为 `false-positive`，报告保留未证实项

---

## 8. 第七步（可选进阶）：动态验证

想证明漏洞"真的能触发"，在本地做仿真（安全门四项全过才放行：授权 + 本地实验 + 私有网段 + 基线就绪）：

```bash
# qemu 用户态模式（适合单程序）
qemu-mips-static -L tmp/unpacked/_DIR-859_Ax_FW_113b03.bin.extracted/squashfs-root \
  tmp/unpacked/_DIR-859_Ax_FW_113b03.bin.extracted/squashfs-root/usr/sbin/upnpd
```

**红线（必须遵守）**：

- 只打自己下载的固件，目标 IP 必须私有网段
- 发送的 payload 限定为无害命令（`id`、`touch /tmp/lab_marker`）；反弹 shell、持久化、下载执行由安全策略拦截
- 验证完不留后门、不改系统

---

## 8.5 中断时生成快照报告（可选）

分析跑到一半，或 `AGENT_LOOP` 还在执行时，可以只根据已有产物生成一份快照，
不会重新跑分析、验证或模型：

```bash
fsa report hunt1 --limit 20
# 输出：runs/hunt1/report.partial.md
```

快照会列出：

- 当前 `status` / `current_stage` / 已完成与未完成阶段
- 解包结果、攻击面与二进制数量
- 当前候选与 Top N 排序
- 如果有 `verdict.json`，附上已有裁决；没有就明确写「VERIFY_TOP_K 未完成」
- `AGENT_LOOP` 已执行的动作、模型调用、token、回退与 limitations
- 缺失产物和恢复命令 `fsa resume <run-id>`；如果 run 已经标成 done，用
  `fsa resume <run-id> --from-stage <STAGE>` 回退到指定阶段重跑（会先备份 `run_state.json`）
- 如果进程被 kill 但状态还写着 `running`：`state/run.lock` 的 `flock` 会随进程退出自动释放，
  `fsa resume` 会把这种状态判定为中断并直接续跑；只有锁仍被另一个进程持有时才会拒绝

它不会写 `report.md` 或 `final_verdict.json`，也不会把未验证候选说成确认漏洞。
恢复完成后，仍以最终 `report.md` 为准。

---

## 9. 常见问题（小白高频踩坑）

| 问题 | 原因 | 解决 |
|---|---|---|
| `fsa: command not found` | 没激活 venv / 没 `pip install -e .` | `source .venv/bin/activate` 后重装 |
| `binwalk: command not found` | 没装或不在 PATH | `pipx install binwalk`（跨发行版通用），或把 `~/.local/bin` 加进 PATH |
| `rootfs not found: xxx` | rootfs 路径写错了 | 先 `ls tmp/unpacked` 确认目录存在 |
| `Policy rejected` | 固件在白名单外 / 命令含黑名单词 | 把固件放进 `firmware_samples/`，命令使用白名单工具 |
| 解包没出 rootfs | 固件加密 / 特殊格式 | 换 sasquatch 手动解，或 `fsa unpack-diagnose` 看建议 |
| `Permission denied` | 脚本缺可执行位 | `chmod +x scripts/*.sh` |
| 报告全是 LOW / 无候选 | 固件没漏洞或目标太老 | 换个还在更新的型号，或加大分析范围 |

---

## 10. 完整流程速查（复制粘贴版）

```bash
# ① 进环境 + 自检（每次新 shell 都要 activate）
cd ~/FirmHound && source .venv/bin/activate
fsa doctor

# ② 固件放 firmware_samples/ 后解包
binwalk -e -M firmware_samples/<固件名>.bin -C tmp/unpacked

# ③ 找 rootfs
ls tmp/unpacked            # 找 squashfs-root

# ④ 跑分析
fsa analyze tmp/unpacked/<extracted>/squashfs-root --input-type rootfs \
  --authorization-holder "设备所有者" --run-id hunt1

# ⑤ 看报告
less runs/hunt1/report.md
```

**祝你挖到新洞！挖到后记得：**

1. 记录复现路径（哪个请求、哪个参数、哪条调用链）
2. 写进报告（`fsa analyze` 已自动生成固定章节的报告，人工补齐反证与修复建议）
3. 沉淀成新的 Skill（`skills/04-audit/` 下新增，让下次更快）
