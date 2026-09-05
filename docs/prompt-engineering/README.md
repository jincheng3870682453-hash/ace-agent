# AI Agent 系统提示词工程（prompt-engineering 文档）

> **本目录是什么**：这是「AI Agent 系统提示词」从 v1.0 到 v7.0 的**迭代规范文档归档**（原为独立工作区，现并入 ace 仓库统一维护）。
> **可运行的实现在哪**：提示词的真正落地在仓库根的代码里——`execution_layer.py`（权限裁决/安全闸门）、`tools/`（工具执行）、`prompts/`（运行时提示词 v7/v8/tools 版）。本目录保留的是规范演进过程与设计说明，两者以 [版本演进](#版本演进) 和 [与代码实现的分工](#与代码实现的分工) 对应。

## 设计取向

一句话概括这条提示词工程路线：**模型只负责理解和输出，权限与安全由执行层裁决，不由提示词承诺。**

- **思考链分离** —— 模型内部推理（`<INTERNAL>`）对外不可见，只暴露最终结果（`<EXTERNAL>`）
- **禁止自我审查** —— 模型先调用工具，权限由执行层裁决，不能提前拒绝用户
- **格式绝对刚性** —— `<INTERNAL>`/`<EXTERNAL>` 协议解析零容错，防止模型绕过格式约束
- **先执行、后判断** —— `[REASON]` 步骤只能选工具，不能替执行层预判权限

## 目录内容

| 文件 | 说明 | 状态 |
|---|---|---|
| `README.md` | 本文档 | 当前 |
| `agent_system_prompt_v7.md` | v7 提示词规范全文（**独立规范版**，21 KB） | 历史归档 |
| `agent_system_prompt.md` | v6 基础沙盒版 | 历史归档 |
| `v7_improvements.md` | v7 相对 v6 的改进说明 | 历史归档 |
| `context_package.md` | v1→v6 的开发上下文包（约 15 轮对话纪要） | 历史归档 |

> ⚠️ 注意：本目录的 `agent_system_prompt_v7.md` 与仓库根 `prompts/agent_system_prompt_v7.md`（14 KB）**内容不同**——前者是独立迭代的规范文档，后者是运行时实际加载的提示词（已演进到 v8/tools 分支），修改提示词请以 `prompts/` 为准。

## 版本演进

| 版本 | 核心特性 | 状态 |
|------|---------|------|
| v1.0 | 基础沙盒 Agent | 已废弃 |
| v2.0 | 真实 Agent 化（ReAct 循环 PLAN→REASON→ACT→OBSERVE→REPLAN→CHECK） | 已废弃 |
| v3.0 | 解析器零容错版（硬标记分离、`answer.` 前缀、模式 A/B 严格区分） | 已废弃 |
| v4.0 | 禁止自我审查版（先执行后判断、权限归执行层、列 5 种禁止句式） | 已废弃 |
| v5.0 | 文档解析器接入版（`parse_document` 工具） | 已废弃 |
| v6.0 | 顶级实践融合版（分层架构 11 层、Plan Mode 5 阶段、Hooks 安全层、任务跟踪） | 已废弃 |
| **v7.0** | **生产级分层提示词**（15 层架构、31 个工具、6 阶段计划模式、专业层） | 当前规范 |

v7.0 主要改进：

1. **增强思考链** - 新增 ANALYZE、GENERATE、OPTIMIZE、TEST 状态标签
2. **扩展工具集** - 新增 7 个专业工具（git_status、code_analyze、test_execute 等）
3. **新增专业层** - 代码质量层、代码生成层、代码审查层
4. **升级计划模式** - 从 5 阶段扩展到 6 阶段
5. **融合最佳实践** - 遵循 PEP 8、Airbnb Style Guide 等业界标准
6. **增强错误处理** - 专业的错误诊断和修复建议

## 实测基准（取代早期「性能对比」）

> 早期版本对比表（如「代码理解深度 +200%」「测试覆盖率 +80%」）属于**不可复现的预估数字**，已移除。代码的真实能力请以实测为准——执行层的正确率与耗时由 [`benchmarks/bench_core.py`](../../benchmarks/bench_core.py) 一键复现（纯标准库、不联网），报告存于 [`benchmarks/results/bench_report.md`](../../benchmarks/results/bench_report.md)。

本机实测摘要（2026-09-05 · Windows 11 x64 · Python 3.12.14，样本与完整说明见报告）：

| 能力 | 实测值 | 样本 |
|---|---|---|
| 正确性检查（解析/权限/守门/AST/回滚/记忆） | **24/24 通过** | 24 |
| 文档解析 · 文本格式直接解析覆盖 | **7/7**（md/py/txt/json/csv/xml/html/yaml） | 7 |
| 文档解析 · Markdown 平均耗时 | **0.16 ms** | 30 |
| 工具链路 · terminal_view 往返延迟 | **0.03 ms** | 120 |
| 工具链路 · 权限不足裁决延迟（readonly→授权请求） | **0.01 ms** | 60 |
| L4 守门 · 吞吐 | **≈15.1 万次/s** | 2000 |
| AST 行为检测 · 6 条违规样本单次全检 | **0.54 ms** | 300 |
| 快照回滚 · 快照+修改+回滚整循环 | **17.4 ms/次**（字节一致 100%） | 150 |
| SimHash 记忆 · 写入吞吐 | **≈5157 条/s** | 2000 |

复现命令：

```bash
python benchmarks/bench_core.py          # 全量（默认）
python benchmarks/bench_core.py --quick  # 样本减半（CI 冒烟）
```

## 与代码实现的分工

| 本目录（规范/历史） | 仓库根（实现/运行时） |
|---|---|
| 提示词分层设计、迭代记录 | `prompts/`：运行时 v7/v8/tools 提示词（实际加载） |
| 格式协议说明（INTERNAL/EXTERNAL） | `execution_layer.py`：协议解析 + 权限裁决 + 安全闸门 |
| 文档解析设计目标 | `universal_document_parser.py`：N 合一解析器（真实实现） |
| 能力演进设想 | `tools/`、`gateway_v2/`、`work.py`、`guardian.py`：工具与安全支撑 |
| —— | `test_all.py`：全模块端到端测试（纯 stdlib） |
| —— | `benchmarks/`：实测基准与报告 |

## 最佳实践

### 代码风格

- **Python**: PEP 8
- **JavaScript**: Airbnb Style Guide
- **Java**: Google Style Guide

### 设计原则

- 单一职责、开闭原则、依赖倒置、DRY

### 安全实践

- 参数化查询（防 SQL 注入）、输入验证、敏感信息保护、权限控制

> 提示词层只负责“引导模型行为”，真正的强制边界在 `execution_layer.py` 与沙箱档位（见仓库根 `README.md` 安全模型一节）。

## 工作流程示例（规范示意）

### 代码生成任务

```
用户：生成一个 REST API
Agent 会：
1. [EXPLORE] 查看项目结构
2. [ANALYZE] 分析现有代码风格
3. [DESIGN] 设计 API 接口
4. [GENERATE] 生成代码
5. [TEST] 执行测试
6. [OPTIMIZE] 优化性能
```

### 测试生成任务

```
用户：帮我写测试
Agent 会：
1. [ANALYZE] 分析代码结构
2. [DESIGN] 设计测试用例
3. [GENERATE] 生成测试代码
4. [TEST] 执行测试
5. [OPTIMIZE] 优化测试覆盖率
```

## 后续方向

- [x] 实测基准落地（`benchmarks/bench_core.py` + 报告）——替代不可复现的预估百分比
- [ ] 规范文档与 `prompts/` 运行时版单向同步，杜绝双份漂移
- [ ] 多语言支持（Java、Go、Rust）示例
- [ ] IDE 集成（VS Code 插件）与云端协作

## 参考来源

- **Claude Code** (Anthropic) - 条件性提示词、Plan Mode、Hooks、Memory
- **Anthropic 多代理研究** - 工具描述质量显著影响任务完成时间
- **Devin** (Cognition) - 证据驱动、引用驱动
- **Manus** - 事件驱动、权限申请标准化
- **OpenAI Computer Use** - 原生工具调用机制

## 许可证与维护

- 本目录与 ace 仓库共用 MIT 许可证（见仓库根 `LICENSE`）
- 仓库主页: <https://github.com/jincheng3870682453-hash/ace-agent>
