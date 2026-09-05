# 待办事项(BACKLOG)

> 由 2026-09-05 四视角体检(安全复核 / 架构 / 测试与 CI / 文档产品化)+ 实测复现整理。
> 约定:编号 `SEC-`(安全)、`Q-`(快速赢项/质量)、`R-`(结构重构)、`REL-`(发布)。
> 已完成项进 `CHANGELOG.md`;领取后在此勾选。工作量:S/M/L;来源列 = 审查视角。

## P0 — 安全(全部经真实复现验证,建议最先做)

| ID | 事项 | 证据/说明 | 建议 | 工作量 |
|---|---|---|---|---|
| ✅ SEC-01 | **code_execute 沙箱可绕过 → RCE/任意写** | `code_tools.py:80-91` 只拦 Call.func 精确名;实测 `f=open;f(..)('a','w')`、`(lambda:open)()(...)` 成功落盘、`(lambda:exec)()('print(1)')` 成功执行 | Name/引用级白名单或去 builtins;叠 Go 执行器/job 边界;补 6 条回归测试 | M |
| ✅ SEC-02 | **parse_document 只读越界读** | `parse_tools.py:22-29` 不过 confine/sensitive;readonly 下读项目外 README/execution_layer.py 实测 SUCCESS(file_read 同路径 403) | 与 file_read 同口径路径判定+敏感目标+回归测试 | S |
| ◐ SEC-03 | **默认权限矛盾 + 外发零确认** | `agent_runner.py:668` 默认 write,与“默认 readonly”矛盾;api_post/api_get 无确认、egress_allowlist 默认关 → 注入可外带 .env | 三入口(ai_code/agent_runner/执行层)默认 readonly 对齐;外发写工具默认确认或默认开白名单 | S-M |
| ✅ SEC-04 | 快照 HMAC 默认关 + 敏感文件明文入 `.guardian` | `guardian.py:142/60`;signing_key 不配即无签名;.env/.pem 无排除 | 默认生成项目外密钥;敏感文件只记哈希;补测试 | M |
| ✅ SEC-05 | `browser_screenshot` 属只读且无确认 | `registry.py:117-119` | 归 WRITE + 逐次确认 | S |
| ✅ SEC-06 | execpolicy allow 档小洞 | `ace_execpolicy.py:314` 跳过 `-` 开头 token 可越区;`git config` 被当只读可 `--global` 写 | 选项值含路径不跳过;config 限 `--get/--list` | S |

## P1 — 快速赢项(低风险,按序做)

| ID | 事项 | 说明 | 工作量 |
|---|---|---|---|
| ✅ Q-01 | ruff 扩选 F401/F841/E711/F811 | 实测 F401=42 死导入全可 autofix(execution_layer.py:27-31 os/ast/html) | S |
| ✅ Q-02 | bench 功能 check 失败应 exit≠0;`benchmarks/results/` 入 .gitignore | 现在退出码恒 0、结果入库致本机跑即脏树 | S |
| ◐ Q-03 | test_all 环境敏感自识别(SKIPPED 通道 + `--strict`) | Go Job Object 附加失败/缺 requests/禁联网/系统 temp 只读应跳过并如实标注,不许假绿/整脚本 traceback;9 处裸 mkdtemp 统一走 `.test_tmp` | M |
| Q-04 | README/CI 手抄数字单一来源 | “40 工具”实为 41 声明/39 暴露;“readonly 16”实为 25;agent_runner 注释“24”;“10 家提供商”实为 9 家 10 端点;断言数“238/950/955”互斥 → 一律以源码/测试输出为准或 CI 生成 | S |
| ✅ Q-05 | `ace.cmd` 硬编码 `C:\aider_env\...` | 第 10 行,换机器必炸;改 PATH 探测 python/py | S |
| Q-06 | CI 结构一致性校验 | README 结构树漏 ace_cards/ace_selector/ace_theme/skill_tools/result;ci.yml compileall 漏 ace_http 等 7 根模块;补“树↔文件存在性”job | S |
| Q-07 | prompts 工具清单 ↔ registry 差集 | tools 版提示词手写 26 漏 12(kb_/skill_/goal_/subagent 等);双份 v7(14KB/21KB)漂移 | 由 TOOL_SPECS 生成 + CI diff;docs 版标 archive 或同步 | S-M |
| Q-08 | e2e smoke 抗抖动 | 240s 单次硬超时 → 2-3 次浅提问重试 | S |
| ✅ Q-09 | 死代码清理（BehaviorConstraint 已移除） | `work.py:326 BehaviorConstraint` 仅测试引用、AST 规则无人用;执行层死 import | S |
| Q-10 | 错误语义与文案解耦 | 靠 message 中文子串判 403;`error_code` 自由字符串散落 ~30 处;状态码无集中常量 | error_code/status 枚举化,文案走 i18n | M |
| Q-11 | CONTRIBUTING 更新 + demo --check 入 CI + Docker run 示例补 `--project-root` | CONTRIBUTING:16“238 项”等全过期;章节号混乱 | S |
| Q-12 | 版本单源 `__version__` + v3.1 git tag/Release | 徽章/CHANGELOG/版本表手动三份 | S-M |
| Q-13 | `pyproject.toml`(console_scripts ace=…)或明示“源码运行” | 根目录无打包 | M |
| Q-14 | locales 补齐 + 研究文档卫生 | ja.json 缺 2 键;codex/dsh/security 调研文档补上游 URL/许可证、脱敏本机路径 | S |
| Q-15 | 模块 docstring 检索词/命名说明 | Archive(记忆)/Nuwa(报告)/work(诱饵+AST)名称无信息量;不强行改名,补 docstring | S |

## P2 — 结构级(择机)

| ID | 事项 | 说明 | 工作量 |
|---|---|---|---|
| R-01 | `process_agent_output` 288 行拆状态机 | execution_layer.py:560-849 + 5 个临时标志 | L |
| R-02 | FileTools 1237 行拆 FileOps/TerminalView/TerminalExec | 三条执行路径并存(file_tools.py) | M-L |
| R-03 | 双前端对话引擎合并 | ai_code.ModelClient ↔ agent_runner.ModelProvider 统一 | M |
| R-04 | ai_code.py 2871 行:slash 表驱动 + 会话状态对象 | run_command 111 行 if/elif | M |
| R-05 | test_all.py 4400 行拆 [N] 文件 + runner(--only/--skip) | 现无法单段跑 | M |
| R-06 | 全仓命名风格收敛策略 | 新模块统一 ace_ 前缀;旧模块补导流 docstring | S |

## REL — 对外发布前

- REL-01 建 `SECURITY.md` + Issue/PR 模板;补 GitHub topics/主页(仓库公开,description 已有)
- REL-02 README 顶部“生产级”表述与现状对齐;关键数字动态化(Q-04)
- REL-03 一次真实 Windows 冒烟(ace.cmd → 真机对话)→ Q-05 完成后
- REL-04 在 GitHub 配置 `ACE_E2E_*` secrets 后,把 e2e-real-model 从“跳过”跑成真实绿(可选)

## 建议顺序

1. **P0 全批**(SEC-01→SEC-02→SEC-03→SEC-04→SEC-05→SEC-06)+ 各自回归测试
2. P1 快速项:Q-01 → Q-02 → Q-03 → Q-04 → Q-05 → Q-06/Q-07
3. P2/R-* 与 REL-* 按迭代安排
