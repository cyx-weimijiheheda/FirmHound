---
id: 04-audit
title: 静态审计分析模型与漏洞分类路由
tags: [static, audit, dataflow, source_sink, m5]
---

# Skill 04：静态审计分析模型

## 目标

把 M3 攻击面与 M4 二进制摘要交叉，按统一分析模型产出 `candidates.json`。本 Skill 只管跨漏洞类共用的部分：数据流模板、证据要求、误报排除规则、路由。具体漏洞类的判定方法见「子技能分工」。

## 输入

- `binaries_summary.json`：M4 结构化摘要
- `attack_surface.json`：M3 攻击面
- `auth_matrix.json`：M3 认证矩阵

## 输出

- `candidates.json`：漏洞候选列表（`candidate.schema.json`）

## 子技能分工

| 子技能 | 覆盖的漏洞类 | 命中条件 |
|---|---|---|
| `04-audit-command-injection` | `system`/`popen`/`execve` 类命令注入 | 攻击面含 `http_param`、`soap_arg`、`cgi`、`header` |
| `04-audit-buffer-overflow` | 定长 buffer 上的 `strcpy`/`memcpy`/`sprintf` 越界 | 攻击面含 `header`、`body`、`socket_buf`，且长度来自外部 |

两个子技能各自给出入口定位、危险函数分级、过滤绕过与评分口径。本 Skill 不复述这些步骤，只负责把它们产出的候选收敛到同一契约。

## 分析模型

```text
Entry → Source → Transform → Validation → Authorization → Sink
      → Reachability → Counterevidence → Conclusion
```

## 共性规则

1. **七层数据流模板（HTTP 入口）**
   - Request → Route → C Handler → IPC/xmldb → PHP Receive → PHP Sink → Shell Execute。
   - 每层记录过滤器存在性与 `file:line` 证据。

2. **socket 入口变体**
   - 报文 → `recvfrom` → 拷贝/格式化 → sink。

3. **变量使用验证（强制）**
   - 变量定义点与使用点必须同时存在，否则标记反证（`verify_variable_usage`）。

4. **误报排除五规则（fp_filter）**
   - CLI 工具排除；命令模板无 `%s` 降级；纯内部 IPC 降级；无可达外部入口标记待确认；dead code / 未启动服务降级。

5. **候选生成要求**
   - 每个候选 ≥2 条独立证据；`observation` 级不进入评分。
   - `conclusion_category` 五分类：`confirmed-issue` / `high-confidence-candidate` / `false-positive` / `unknown` / `observation`。

## 执行流程

1. **加载输入**
   - 读 `attack_surface.json`、`binaries_summary.json`、`auth_matrix.json`，任一缺失按「失败降级路径」处理。

2. **按攻击面路由**
   - 统计每个 surface 的 `input_sources`，命中哪个子技能的覆盖范围就把该 surface 分派过去。
   - 一个 surface 可同时进入两个子技能（长 header 既可能是溢出，也可能是注入）。
   - CGI/ASP 必须绑到 httpd 类二进制；同一 ELF 多条 surface 时，优先 handler/表单字段出现在函数字符串里的那条。
   - source 优先 CGI 字段名 / `get_cgi` / `websGetVar`，不要被 `fgets` 抢先。
   - 调用链优先与 CGI/字段 token 重叠的命名调用者（DIR-825：`get_ping_app_stat` → `parse_special_char`）。
   - 厂商 helper `.so`（如 `libproject.so`）没有自己的 web 面时，继承导入方二进制上匹配辅助符号的 CGI 面。

3. **收集子技能候选**
   - 两个子技能各自产出候选列表，字段必须满足 `candidate.schema.json`。

4. **归一与去重**
   - 按 `(binary_id, sink.addr, vuln_class)` 合并，保留证据条数多的那条，并集双方的 `evidence`。
   - 同一 sink 上注入与溢出并存时分别保留，`vuln_class` 不同不算重复。

5. **落盘**
   - 写 `candidates.json` 并执行 Schema 校验；校验失败修字段后重校验。

## 失败降级路径

| 场景 | 行为 |
|---|---|
| 无函数级反编译 | 用 imports + strings 交叉证据生成候选，confidence 降级 |
| source 与 sink 无法连通 | 不生成候选，输出 observation |
| 变量未定义或未使用 | 标记 counterevidence，降级为 observation |
| 规则库未覆盖的 API | 落 observation 并标注 `unmatched_sink` |

## 验收标准

- 对 HG532e：产出 P0 候选（upnp / snprintf→system / NewDownloadURL、NewStatusURL），与 CVE-2017-17215 对照表吻合。
- 对 Tenda AC15：产出 formexeCommand / `cmdinput`→`doSystemCmd`→`system()` 候选。
- 每个候选含 ≥2 条独立证据，且能追到子技能的具体步骤依据。
- `candidates.json` 通过 Schema 校验。
