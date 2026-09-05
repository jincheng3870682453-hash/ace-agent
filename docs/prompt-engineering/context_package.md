
# 🤖 Agent 提示词优化项目 —— 上下文回复包
# 生成时间: 2026-08-19 17:13 CST
# 对话轮次: 约 15 轮
# 参与者: 用户 + Kimi Chat

---

## 📌 项目目标
为用户构建一个**生产级沙盒 AI Agent 系统提示词**，核心要求：
1. **思考链分离** —— 模型内部推理（INTERNAL）对外不可见，只暴露最终结果（EXTERNAL）
2. **禁止自我审查** —— 模型必须先调用工具，由执行层裁决权限，不能提前拒绝用户
3. **格式绝对刚性** —— 解析器零容错，防止模型绕过格式约束
4. **接入文档解析** —— 支持 Word/Excel/PPT/PDF/图片 OCR
5. **对标顶级实践** —— 参考 Claude Code、Anthropic Agent 框架、Devin 等

---

## 🏗️ 架构演进路线

### v1.0 —— 原始版本（用户提供）
- 基础沙盒 Agent 设定
- 问题："amswer." 拼写错误、权限判断前置、格式约束松散

### v2.0 —— 真实 Agent 化
- 引入 ReAct 循环（Plan → Reason → Act → Observe → Replan）
- 引入原生 tool_call 概念（而非手写 JSON）
- 问题：用户环境可能不支持原生 Function Calling

### v3.0 —— 解析器零容错版
- 硬标记 `<INTERNAL>` / `<EXTERNAL>` 分离
- `answer.` 绝对前缀
- 模式 A（工具调用）/ 模式 B（最终回复）严格区分
- 禁止子串规则防止绕过

### v4.0 —— 禁止自我审查版
- **铁律 1：先执行，后判断**
- **铁律 2：权限由执行层裁决**
- **铁律 3：禁止假设性拒绝**
- 明确列出 5 种禁止的对外回复句式
- `[REASON]` 步骤只能选工具，不能分析权限

### v5.0 —— 文档解析器接入版
- 新增 `parse_document` 工具到工具清单
- 接入 universal_document_parser.py（N 合一文档解析器）
- 放宽模式 B 的 `{` 限制（只禁 `{"tool"` 子串，不禁中文花括号）

### v6.0 —— 顶级实践融合版（当前最新）
参考 Claude Code 500+ 条件性提示词、Anthropic 多代理研究、Devin 证据驱动：
- **分层架构**：核心身份 + 约束层 + 格式层 + 推理层 + 计划模式层 + 安全拦截层 + 权限层 + 工具层 + 任务层 + 记忆层 + 错误恢复层
- **Plan Mode（5 阶段）**：探索 → 设计 → 审查 → 最终计划 → 执行
- **Hooks 安全层**：自动拦截危险命令，无需申请直接拒绝
- **任务跟踪 `[TASK]` 标签**：多步骤任务状态管理
- **错误恢复分类**：权限错误/参数错误/超时/不存在，各走各的策略
- **工具描述极细化**：每个工具包含目的、何时使用、参数、约束

---

## 📦 已交付文件

| 文件 | 说明 | 下载 |
|------|------|------|
| `agent_system_prompt_v2.md` | 最终版系统提示词（v6.0 分层架构） | [下载](sandbox:///mnt/agents/output/agent_system_prompt.md) |
| `universal_document_parser_v2.py` | N 合一文档解析器（懒加载 + OCR 内存优化 + 大文件截断） | [下载](sandbox:///mnt/agents/output/universal_document_parser.py) |

---

## 🔧 解析器支持格式

Word (.doc/.docx/.wps) → Excel (.xls/.xlsx/.xlsm/.et) → PPT (.ppt/.pptx/.dps) → PDF（自动判断扫描件 + OCR）→ 图片 OCR (.png/.jpg/.jpeg/.bmp/.tiff/.gif/.webp) → 纯文本 (.txt/.md/.csv/.json/.xml/.html/.py/.js/.css/.yaml 等)

**解析器核心设计：**
- 优雅降级（缺库不崩）
- 三层回退（如 .doc 先 mammoth → LibreOffice → antiword）
- PDF 智能双模式（先文本提取，文字太少自动切 OCR）
- OCR 逐页生成器（MAX_OCR_PAGES=50，防止内存爆炸）
- 大文件自动截断（MAX_TEXT_LENGTH=15000）
- 统一 ParseResult 数据结构

---

## 🧠 提示词核心设计（v6.0）

### 输出格式范式
```
<INTERNAL>
[INTERNAL_THINKING]
[PLAN] ...
[REASON] ...
[ACT] ...
[/INTERNAL_THINKING]
</INTERNAL>

<EXTERNAL>
answer.
{工具调用 JSON} 或 {最终回复文本}
</EXTERNAL>
```

### 六大铁律
1. 必须同时包含 `<INTERNAL>` 和 `<EXTERNAL>`
2. 标签必须独占一行
3. `<INTERNAL>` 内禁止出现 `answer.`、`{"tool"`、`</INTERNAL>`、`</EXTERNAL>`
4. `<EXTERNAL>` 内禁止出现 `<INTERNAL>`、`[INTERNAL_THINKING]`
5. 一次只调用一个工具
6. 模式 B（最终回复）禁止出现 `{"tool"` 子串

### ReAct 状态标签（INTERNAL 专用）
- `[PLAN]` —— 拆解子任务
- `[REASON]` —— 选工具（只选工具，不判断权限）
- `[ACT]` —— 确认工具调用
- `[OBSERVE]` —— 分析工具返回结果
- `[REPLAN]` —— 调整计划
- `[CHECK]` —— 仅在执行层拒绝后检查权限缺口

### Plan Mode（复杂任务自动启用）
1. `[EXPLORE]` —— 探索现状
2. `[DESIGN]` —— 设计方案
3. `[REVIEW]` —— 审查风险
4. `[FINALIZE]` —— 最终计划（用户批准后执行）
5. `[EXECUTE]` —— 执行

### Hooks 自动拦截（无需申请）
- `rm -rf /`、`dd if=/dev/zero`、fork bomb
- 向未知外部域名发送敏感数据
- 暴露内部端口到公网
- 涉及未成年人信息

---

## 🔗 用户 GitHub 仓库分析

用户提供了 5 个仓库，已分析 4 个：

| 仓库 | 核心能力 | 可融入提示词的部分 |
|------|---------|------------------|
| `autonomous-agent` | 自进化 Agent 平台（GitHub Actions 云端运行、三层记忆、技能市场） | **agent.py** 生命周期状态机 → 提示词状态标签；**bank.py** SQLite+FTS5+Graph → 记忆检索策略 |
| `token-sage` | AI 行为约束与治理（省 token、AST 检测、快照回滚） | **gateway.py** L1-L5 五层路由 → 错误恢复层升级；**work.py** 13 条 AST 规则 → Hooks 安全层；**guardian.py** 快照回滚 → 执行前自动快照机制 |
| `interface-notes` | AI 接口文档工具（扫描→打印→手写→OCR 回流） | 文档解析工作流经验 |
| `jinchen-halfdup` | 全双工对话原型（半句抢答、猜错容错） | 交互设计参考 |

---

## ⏳ 待办事项（等待用户）

### 🔴 高优先级（阻塞下一步优化）
1. **获取核心代码文件** —— 用户已同意提供，等待贴代码：
   - `autonomous-agent/core/agent.py`（主控制器生命周期）
   - `autonomous-agent/core/memory/bank.py`（三层记忆系统）
   - `token-sage/Toolkit/gateway.py`（L1-L5 路由 + 反馈重试）
   - `token-sage/Toolkit/work.py`（13 条 AST 安全规则）
   - `token-sage/Toolkit/guardian.py`（快照回滚 + RollbackJury）

### 🟡 中优先级（有代码后优化）
2. **将 gateway.py 的五层路由融入提示词错误恢复层**
   - 当前：简单分类错误 + 重试 2 次
   - 目标：L1 意图识别 → L2 参数校验 → L3 执行 → L4 结果验证 → L5 反馈闭环

3. **将 work.py 的 AST 规则融入 Hooks 安全层**
   - 当前：简单的关键词拦截
   - 目标：基于 AST 的精确行为检测（如检测 `eval()`、`exec()`、`subprocess` 危险调用）

4. **将 guardian.py 的快照机制融入执行流程**
   - 执行前自动创建快照
   - 执行失败时自动回滚
   - RollbackJury 生成审计日志

5. **将 bank.py 的记忆检索融入 [REASON] 阶段**
   - 调用工具前先查记忆
   - SimHash 去重 + 主题切换检测

---

## 💡 关键决策记录

| 决策 | 选择 | 原因 |
|------|------|------|
| 思考链分离格式 | `<INTERNAL>` / `<EXTERNAL>` 硬标签 | 系统层正则直接截断，100% 防泄露 |
| 前缀 token | `answer.` | 用户原始设计保留，简单不易误触 |
| 模式 B `{` 限制 | 只禁 `{"tool"` 子串 | 防止误伤中文花括号和表情 |
| 权限裁决方 | 执行层（沙盒） | 模型禁止预判权限，避免自我审查 |
| PDF OCR 策略 | 先文本提取，再启发式判断扫描件 | 节省算力，避免无脑 OCR |
| 大文件处理 | MAX_TEXT_LENGTH=15000 自动截断 | 防止 token 爆炸 |
| 依赖管理 | 懒加载 `_lazy_import` | 缺库不阻塞启动，CLI 友好 |
| 文档解析器接入方式 | 执行层直接调用，不通过代码执行 | 安全 + 稳定 |

---

## 📚 参考来源

- **Claude Code** (Anthropic) —— 500+ 条件性提示词片段、Focus Mode、Plan Mode、Hooks、Memory
- **Anthropic 多代理研究** —— 工具描述质量决定 40% 任务完成时间
- **Devin** (Cognition) —— 证据驱动、引用驱动
- **Manus** —— 事件驱动、权限申请标准化
- **OpenAI Computer Use** —— 原生工具调用机制

---

## 🚀 下一步建议

1. **用户贴出 5 个核心代码文件** → 我提取设计模式融入提示词
2. **生成最终 v7.0 提示词** —— 融合用户仓库的 gateway/work/guardian/bank 设计
3. **生成配套执行层伪代码** —— 展示如何解析 `<INTERNAL>`/`<EXTERNAL>`、调用解析器、处理权限
4. **可选：生成 MCP Server 封装** —— 让 parse_document 成为标准化工具

---

*本上下文包由 Kimi Chat 自动生成，用于对话续接或团队同步。*
