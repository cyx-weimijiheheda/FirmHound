# FirmHound 文档索引

> 文档按**用途**分四类，不按作者、不按日期。新文档先想清楚属于哪一类，再落盘。

```
docs/
├── guide/            上手与操作：装、跑、演示、自测
├── external/         外部分析器：总纲 + 数据集 + 真机测试
├── design/           设计决策记录（为什么这样设计）
└── archive/          历史运行记录（只读，不代表当前实现）
```

四份工具的具体方法论、命令与踩坑已经落在技能卡里：
`skills/08-external-analyzers/{satc,firmrec,klee,bond}/SKILL.md`。

---

## 1. 按目的找

| 我想… | 文档 | 说明 |
|---|---|---|
| 在任意 Linux 发行版上装好依赖 | [`guide/install.md`](guide/install.md) | 六类发行版的安装命令、包名差异、sasquatch 编译、排错表 |
| 从零部署并录制演示 | [`guide/deployment.md`](guide/deployment.md) | 装好之后的部署流程 → venv → 7 个演示脚本 → 录屏顺序 |
| 从固件挖到第一个漏洞 | [`guide/hunting-workflow.md`](guide/hunting-workflow.md) | 选目标 → 解包 → `fsa analyze` → 读报告 → 10 问人工审计 |
| 交付前做一次完整自测 | [`guide/cli-testing.md`](guide/cli-testing.md) | doctor / plan / analyze / 降级 / 安全策略的验收标准 |
| 理解外部分析器怎么编进流水线 | [`external/README.md`](external/README.md) | 固定编排顺序、开关、能力边界、诚实降级、安全红线 |
| 准备外部工具的运行环境 | [`external/field-testing.md`](external/field-testing.md) | 硬件要求、镜像、四器逐个跑通步骤与踩坑 |
| 不用 Docker 原生跑 FirmRec | [`guide/firmrec-native.md`](guide/firmrec-native.md) | JDK/Ghidra/PostgreSQL/Python 全栈、上游输入契约、`make firmrec-doctor` |
| 开启受控自主取证循环 | [`guide/agent-loop.md`](guide/agent-loop.md) | `--agent`、tier、预算、模型回退、trace 与安全边界 |
| 查固件样本清单与来源 | [`external/dataset.md`](external/dataset.md) | L1/L2/L3 三档数据集、SHA256、架构、下载脚本 |
| 接入/维护某个外部工具 | `skills/08-external-analyzers/<tool>/SKILL.md` | 目标 → 输入输出 → 执行流程 → 命令 → 验收降级 → 踩坑表 |
| 查某个设计为什么这么做 | [`design/design-rationale.md`](design/design-rationale.md) | 关键取舍、边界、常见质疑的答法 |
| 回看某次真实固件运行到底发生了什么 | [`archive/`](archive/) | 带日期的回归与检出记录，**仅作历史证据** |

---

## 2. 各类文档的边界

**`guide/` 讲"人怎么用"**：面向第一次接触项目的人，命令可直接复制执行。
不写内部实现细节，不写未来计划。发行版差异只在这里列，其他文档不重复。

**`external/` 讲"这四个工具怎么接、怎么降级"**：产品级契约（顺序、开关、状态、红线）
放 `README.md`，样本清单与真机准备各自成篇。单个工具的方法细节在技能卡里，避免两处维护。

**`design/` 讲"为什么这样设计"**：只留长期有效的取舍记录，不写计划、不写汇报结构。

**`archive/` 讲"当时跑出了什么"**：带日期的真实固件回归、检出效果与四器接入核验。
其中的环境、路径、开关可能与当前实现不一致，**排障时以当前实现为准**。

---

## 3. 维护约定

- 新增面向用户的操作文档 → `guide/`；外部工具契约 → `external/`；设计取舍 →
  `design/`；一次性的实验记录 → `archive/<主题>-YYYY-MM-DD.md`。
- 文件名用 `kebab-case` 英文，标题（H1）用中文；同一目录内保持一套命名风格。
- 文档里引用代码位置时写**文件 + 符号**（如 `fsa/orchestrator/engine.py::_execute_stage`），
  同时给出符号名或文件路径。
- 阶段顺序、Schema 字段、配置项、安全边界一旦改动，同步改本文索引涉及的那一份，
  并在 `README.md` 的项目结构里保持目录名一致。
- 被替代的文档移入 `archive/` 并在开头加一行"已归档"说明；纯计划类、材料类文档直接删除，不进仓库。
