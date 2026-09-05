# Codex CLI 源码调研：ACE 可借鉴设计清单（草稿，待补全）

> 调研对象：C:\Users\<用户名>\Desktop\AI_Project\_reference\codex（OpenAI Codex CLI，bazel monorepo）
> 说明：本仓库中 codex-cli/ 仅是 npm 启动器（spawn 预编译 Rust 二进制），真正的交互 CLI 全部在 codex-rs/tui（Rust）。

## 一、Sandbox 隔离（Windows 强隔离）【已定稿】

1. 【专用沙箱账户】windows-sandbox-rs/src/setup.rs、identity.rs — 提权 setup 创建 CodexSandboxOffline/Online 两账户，密码 DPAPI 加密存 codex_home；所有沙箱进程以该身份运行。【解决】进程身份级隔离。【价值】高（Windows 裸机）【成本】大
2. 【Capability SID + CreateRestrictedToken 受限令牌】token.rs、cap.rs — 每个写根生成随机 SID，WRITE_RESTRICTED 受限令牌，仅保留 SeChangeNotifyPrivilege。【价值】高【成本】中
3. 【路径级 ACL（deny/allow ACE + glob 展开 + 失败回滚）】acl.rs、deny_read_acl.rs、deny_read_resolver.rs — 按路径打 ACE，glob 先展开，不存在的路径先物化再打 ACE，失败撤销。【价值】高【成本】中
4. 【WFP 按账户断网】wfp.rs、wfp/filter_specs.rs — 持久化 provider/sublayer，ALE_USER_ID 匹配沙箱账户 SID，BLOCK ICMP/DNS 53/853/SMB 139/445。【价值】条件高（仅 Windows 裸机原生断网）【成本】大
5. 【私有桌面隔离】desktop.rs — CreateDesktopW 随机名，隔离 GUI/剪贴板/按键注入。【价值】中【成本】小
6. 【句柄白名单继承】process.rs PROC_THREAD_ATTRIBUTE_HANDLE_LIST — 只传 stdin/stdout/stderr 句柄。【价值】中【成本】小
7. 【沙箱失败判定（violation 结构化事件）】sandboxing/src/violation.rs、denial.rs — 退出码（2/126/127 排除、128+SIGSYS）+ 输出关键词启发式判断沙箱拒绝 vs 命令失败。【价值】高【成本】小
8. 【无法强制则拒绝运行（不静默降级）】sandboxing/src/windows.rs — 策略超出后端能力时 refusing to run unsandboxed。【价值】高【成本】小
9. 【elevated/legacy 双后端 + 统一会话 API】unified_exec/、backends/{elevated,legacy}.rs — 按 WindowsSandboxLevel 选后端，提权 runner + 命名管道 framed IPC。【价值】中【成本】大
10. 【环境消毒】env.rs — NUL 设备、PAGER 强制非交互、PATH 规范化。【价值】中【成本】小
11. 【WritableRoot 例外子路径】protocol/src/protocol.rs WritableRoot — 可写根内保留只读子路径（.git/.git/hooks/.codex），防提权文件被改。【价值】高【成本】小（ACE 在 docker 挂载层可表达）

ACE 差距总结：docker 容器用户覆盖了"身份/令牌环"大半；缺的是 ①沙箱失败判定+拒绝运行（小成本、平台无关，最值得补）②路径级 deny/allow 策略建模层 ③Windows 裸机才需要的沙箱账户+受限令牌+WFP 整链。

## 二、AGENTS.md 项目记忆 / skills / MCP【已定稿】

1. 【AGENTS.md 层级发现+拼接】core/src/agents_md.rs — cwd 向上找项目根（.git 标记）→ 根→cwd 每层取一个（AGENTS.override.md > AGENTS.md > fallback）→ 根到叶拼接。【价值】高【成本】小
2. 【project_doc_max_bytes 预算】config/mod.rs L224 默认 32 KiB 硬截断。【价值】高【成本】小
3. 【会话内缓存】agents_md_manager.rs refresh()，以(环境,信任级别,沙箱级别)为 key。【价值】高【成本】小
4. 【不信任项目跳过】agents_md.rs — untrusted 只注入用户指令，防恶意仓库投毒。【价值】中【成本】小
5. 【world_state 差分注入】context/world_state/agents_md.rs — AGENTS.md 是 WorldStateSection，仅变化才发替换片段；压缩后重建注入不丢失。【价值】高【成本】中
6. 【skills 目录 + $提及按需注入】codex-rs/skills/{loading,selection,mentions,parser}.rs、session/turn.rs L730-841 — SKILL.md frontmatter（name/description/dependencies），消息中 $skill 触发按需注入。【价值】高（与 SimHash 记忆互补）【成本】中
7. 【MCP 工具三态裁剪】mcp_tool_exposure.rs — ToolExposure::Direct/Deferred/Hidden，插件 MCP 单工具 8KB/总 64KB 上限。【价值】高【成本】中
8. 【MCP 审批模板】mcp_tool_approval_templates.rs + consequential_tool_message_templates.json — 按(server,connector,tool)渲染人话审批问句。【价值】中【成本】中
9. 【Memories 双阶段管线】memories/README.md — Phase1 后台提炼历史 rollout 为 raw_memory；Phase2 合并为 ~/.codex/memories/ 并 git 基线 diff。【价值】高（SimHash 升级蓝图）【成本】大
10. 【技能声明 MCP 依赖并自动安装】mcp_skill_dependencies.rs — SKILL.md dependencies.tools 缺则询问安装+OAuth。【价值】中【成本】大

## 三、Approval 审批 UX【已定稿】

1. 【命令三级决策矩阵】core/src/exec_policy.rs + codex-rs/execpolicy（Starlark 规则语言）— ①前缀规则匹配（显式 allow/deny 规则）②未匹配则危险启发式分类 ③approval_policy 兜底。规则优先于启发式。【价值】高【成本】中
2. 【前缀白名单"同前缀不再问"】exec_policy.rs — 批准时附带"以后同前缀命令自动批准"选项，落盘 default.rules；含 BANNED 前缀列表（防 bash -c/python -c 这类危险包装）。【价值】高【成本】小
3. 【三档批准作用域 + 单键快捷键】tui/src/bottom_pane/approval_overlay.rs、tui/src/keymap.rs — y/a/p（本次/本会话/永久前缀），d/n/Esc 拒绝/中断。【价值】高【成本】小
4. 【Granular 类目开关（关=静默拒绝）】protocol/src/protocol.rs GranularApprovalConfig — sandbox_approval/rules/skill_approval/request_permissions/mcp_elicitations 五类，false 时不弹窗直接拒绝。【价值】高【成本】小
5. 【审批预设档位】utils/approval-presets — ReadOnly/Default/FullAccess 一键打包切换（对应 sandbox 策略+approval 策略组合）。【价值】中【成本】小
6. 【auto-review 子代理代批】core/src/guardian/ — LLM 审查 on-request 审批，fail-closed，连续拒绝 3 次/轮上限，克隆父配置+只读权限+禁记忆/MCP。【价值】高【成本】大
7. 【补丁可写根自动批准】core/src/safety.rs — 对 workspace 内文件修改类操作自动批准（低风险类别免确认）。【价值】中【成本】小
8. 【命令规范化缓存去重】command_canonicalization.rs — 规范化 argv 缓存审批结果，同命令只问一次。【价值】中【成本】小
9. 【审批弹窗信息密度】approval_overlay.rs — Thread/Env/Reason/命中的权限规则/高亮命令 + 快捷键选项；大 payload 全屏展示。【价值】中【成本】小

## 四、Session/Config/Rollout/Compaction【已定稿】

1. 【13 层 TOML 配置栈深度合并】config/src/state.rs、loader/mod.rs、config_layer_source.rs、merge.rs — packaged(-10)<system(10)<cloud(15)<user(20)<profile(21)<project(25)<session flags(30)<legacy managed(40/50)；env 仅 CODEX_HOME/SQLITE_HOME/密钥，不参与通用合并；requirements.toml 独立强制约束层；线程级配置插层（ThreadConfigLoader）。【价值】高【成本】中
2. 【Session = Op 队列 + 事件流 + 状态 watch】core/src/session/mod.rs、handlers.rs — 所有用户/系统操作入队串行，事件流广播（TUI/日志/回放共用）。【价值】高（ACE 的 NDJSON IPC 可对齐）【成本】中
3. 【RecoverTurn 同 turn 续跑】protocol.rs、session/turn.rs — turn 失败可恢复重入，不丢中间状态。【价值】高【成本】中
4. 【Rollout：append-only JSONL 事件日志 + 后台 writer + flush 屏障】rollout/src/recorder.rs、compression.rs — 会话全量事件持久化，resume=重放 JSONL 重建 history（rollout_reconstruction.rs）。【价值】高（ACE 断点续跑/审计）【成本】大
5. 【rollout 压缩 worker】rollout/src/compression.rs — 后台周期压缩旧 rollout 文件，session_index.rs 建索引加速 resume 搜索。【价值】中【成本】中
6. 【compaction 触发与预算】core/src/compact.rs、compact_token_budget.rs — scope token ≥ auto_compact_token_limit + fallback buffer 触发；预算分 Total/BodyAfterPrefix；触发分 Manual/Auto；pre/post compact hooks 生命周期。【价值】高【成本】中
7. 【token 预算压缩（跳过总结换新窗口）】compact_token_budget.rs — 直接开新 context window 不调模型总结，仍发 ContextCompaction turn item 让模型感知。【价值】中【成本】小
8. 【模型降级 fallback】compact_model_fallback.rs — 旧模型压缩失败用当前模型重试。【价值】高【成本】小
9. 【流式重试三层】responses_retry.rs — 流退避/传输降级 → RecoverTurn → 模型 fallback。【价值】中【成本】中
10. 【Rollout token 预算】session/rollout_budget.rs + rollout/src/policy.rs — 接近限额注入剩余 token 提醒片段，超限 SessionBudgetExceeded。【价值】中【成本】小

## 五、CLI 交互细节【已定稿】

1. 【Feature 门控命令目录】tui/src/slash_command.rs、bottom_pane/slash_commands.rs — 50+ 命令+别名，按 feature 标志/侧会话过滤可见性，fuzzy 前缀匹配。【价值】高【成本】小
2. 【/ 弹层实时过滤】bottom_pane/command_popup.rs — 输入即过滤（前缀+子串）、↑↓+Enter、Esc 关闭、精确匹配自动选中。【价值】高【成本】小
3. 【/model 热切换】chatwidget/model_popups.rs、app/event_dispatch.rs — 弹层列 preset → UpdateModel+UpdateReasoningEffort+PersistModelSelection 三事件 → 改内存 config → 下一轮生效 → 写 config.toml 持久化默认；不打断进行中 turn。【价值】高【成本】小-中
4. 【双区流式渲染】streaming/controller.rs、markdown_stream.rs — 稳定区（已提交）+ tail 区（可变）；换行提交、未完成行不回显；表格 holdback 防列宽重排。【价值】高【成本】中
5. 【自适应提交节拍】streaming/chunking.rs、commit_tick.rs — 积压时 Smooth→CatchUp 批量 drain。【价值】中【成本】小
6. 【增量 markdown 渲染】streaming/render.rs — 已完成块缓存，只重渲最后一块；resize 全量重渲。【价值】高【成本】中
7. 【diff 渲染】diff_render.rs、history_cell/patches.rs — unified diff 行号/+/−/语法高亮/主题感知（暗亮、真彩/256/16 色三档）；/diff 含未跟踪文件。【价值】高【成本】中
8. 【Esc 中断 + 回溯编辑】keymap.rs、app_backtrack.rs — Esc 中断当前轮；Esc×2 transcript overlay，Enter 在选中消息前 fork 并恢复草稿（重写对话）。【价值】高【成本】中
9. 【配置化键位 + 两击 chord + Vim 模式】keymap/bindings.rs、chords.rs — tui.keymap.<context>.<action>、/keymap 可视重绑、chord 1s 超时。【价值】中【成本】中
10. 【@ 提及统一弹层】bottom_pane/mentions_v2/、mention_codec.rs — @ 触发文件/skill/插件统一搜索、fuzzy 排序；$=skill 提及、@=插件提及。【价值】高【成本】中
11. 【shell 环境快照（保真交互 shell 环境）】core/src/shell_snapshot.rs、shell-command/src/shell_snapshot.rs — 会话启动抓别名/函数/setopts/导出变量（10s 超时、3 天保留、source 验证）；执行命令时包裹 source 快照。与 ACE 的 Guardian 文件快照互补（这是环境保真，不是文件撤销；Codex 的 ThreadRollback 明确不恢复磁盘改动）。【价值】中【成本】小-中
12. 【有界实时命令输出】exec_cell/live_output.rs — 1MB 上限、保留首尾各 50 行+进行中行，防无换行输出无限增长。【价值】中【成本】小
13. 【终端探测】terminal_probe.rs、terminal-detection/ — 100ms 预算探测光标/OSC10-11 默认色/键盘增强，失败回退保守默认。【价值】低【成本】小

## 七、其他一手事实（正文不赘述）
- 旧 --dangerously-bypass-approvals-and-sandbox 已移除（approval 子代理确认）。
- execpolicy 是独立 Starlark 规则语言（codex-rs/execpolicy crate），命令级 allow/deny 规则与指令分离，docs/execpolicy.md 只是外链。

## TOP 5 最值得借鉴（综合价值×成本×与 ACE 架构契合度）

1. **沙箱失败判定 + 无法强制则拒绝运行**（sandboxing/src/violation.rs、denial.rs、windows.rs）—— 高价值/小成本/平台无关。ACE 用 docker+Job Object，正缺"沙箱拒绝 vs 命令自身失败"的归因与结构化事件回馈模型；"策略超出后端能力就拒绝运行、绝不静默降级"直接提升安全可信度。
2. **审批疲劳缓解组合：Granular 类目静默拒绝 + 前缀白名单"同前缀不再问"（带 BANNED 列表）+ 三档作用域单键快捷键**（protocol.rs AskForApproval/GranularApprovalConfig、exec_policy.rs、approval_overlay.rs、keymap.rs）—— 小成本，直接补 ACE（已有 plan_propose/request_permission）最缺的"减少确认疲劳"UX。
3. **AGENTS.md 层级项目记忆（发现+拼接+32KiB 预算+会话缓存+world_state 差分注入）**（agents_md.rs、agents_md_manager.rs、context/world_state/agents_md.rs）—— 小成本，Python 零依赖可抄；与 ACE 的 SimHash 会话内动态记忆互补（静态项目指令 vs 动态经验）。
4. **Rollout：append-only JSONL 事件日志 + 后台 writer + resume 重放重建 + RecoverTurn 同 turn 续跑**（rollout/src/recorder.rs、core/src/session/rollout_reconstruction.rs、session_index.rs）—— 大成本但根基性：断点续跑/审计/可恢复性是 ACE 长期必补项，ACE 已有 NDJSON IPC，演进路径清晰。
5. **Guardian LLM 代批（auto-review 子代理）**（core/src/guardian/）—— 高辨识度"AI 审 AI"：用另一个模型会话 fail-closed 审查审批请求、连续拒绝限流、克隆父配置+只读权限。成本大（额外模型调用+提示工程），但这是 Codex 审批体系里最有辨识度的一环；注意与 ACE 的"Guardian 快照回滚"同名异义。

紧随其后（备选）：skills $提及按需注入（与 AGENTS.md 互补，中成本）、MCP 工具三态裁剪（mcp_tool_exposure.rs，中成本）、双区流式渲染（观感提升，中成本）、/model 热切换（小-中成本）、WritableRoot 例外子路径（小成本）。

## 六、一手补充（主代理自己读到的）
- AskForApproval 四级：UnlessTrusted / OnRequest（默认，模型决定何时问）/ Granular（分类自动拒绝）/ Never（protocol/src/protocol.rs L906-986）——GranularApprovalConfig 分 sandbox_approval/rules/skill_approval/request_permissions/mcp_elicitations 五类，false 则自动拒绝不打扰用户。
- Guardian（core/src/guardian/mod.rs）= 用另一个模型会话审查 on-request 审批请求，fail-closed，连续拒绝上限（3 次/轮），克隆父配置、只读权限、AskForApproval::Never、禁 MCP/记忆。与 ACE 的 Guardian 快照回滚是不同概念，值得 ACE 借鉴为"审批疲劳缓解"。
- compaction 生命周期：compact_token_budget.rs — Manual/Auto 两种触发，pre/post compact hooks，token 预算版跳过总结直接开新 context window，仍发 ContextCompaction turn item 让模型感知。
- rollout 预算：session/rollout_budget.rs — 接近限额时向上下文注入"剩余 token 提醒"片段，超限 SessionBudgetExceeded。
- 时间提醒：session/time_reminder.rs — 按间隔或在用户/工具输出边界注入当前时间。
- Slash 命令：tui/src/slash_command.rs — /model /permissions /compact /undo? /diff /mention /skills /mcp /resume /fork 等 60+；枚举顺序=展示顺序（高频在前）；支持别名（stop/clean、pet/pets、pwd/cwd）；feature 门控可见性（slash_commands.rs builtins_for_input）。
- Shell 快照：core/src/shell_snapshot.rs — /undo 恢复的是 shell 状态（env/history/cwd），10s 超时、3 天保留、存 codex_home/shell_snapshots；与 ACE 的 Guardian 文件快照互补。
- user_shell_command.rs — 用户自己跑命令、结果以 UserShellCommand fragment 注入上下文（观察者模式：用户执行+模型读取结果）。
- SandboxPolicy：DangerFullAccess / ReadOnly / ExternalSandbox / WorkspaceWrite（protocol.rs L1010-1057）。
- SandboxType：LinuxSeccomp(bwrap)/MacosSeatbelt/WindowsRestrictedToken；violation 分类回馈模型（sandboxing/src/violation.rs）。
- codex-cli/bin/codex.js = npm 启动器，平台包 @openai/codex-*-{x64,arm64}，spawn 预编译二进制。
