# Changelog

> ACE 开发期未打 git tag，以下**版本号为按开发阶段归纳的检索代称**（非发布版本号），
> 精确到每次提交请 `git log --oneline`。
> 条目分类：✨ 新增 · ⚙️ 改进 · 🐛 修复 · 🛡️ 安全。
> 全量断言随平台浮动（Windows 比 Linux 多十余项），最新 Windows 实测 **955**。

**版本目录**

- [v3.0 · 2026-09-05 · 联网双通道 + CLI 状态热切换](#v30-2026-09-05)
- [v2.2 · 2026-08-30 · CLI 视觉重设计（OpenClaw 风格）](#v22-2026-08-30)
- [v2.1 · 2026-08-29 · Agent 能力爆发](#v21-2026-08-29)
- [v2.0 · 2026-08-25 · 安全与执行边界](#v20-2026-08-25)
- [v1.2 · 2026-08-21 ~ 08-24 · CLI 体验与工具体系](#v12-2026-08-21-08-24)
- [v1.1 · 2026-08-20 · 真实工具落地](#v11-2026-08-20)
- [v1.0 · 2026-08-19 · 初版](#v10-2026-08-19)

## [v3.0] · 2026-09-05

**联网双通道 + CLI 状态热切换**

ACE 的联网能力从"碰运气"变成"有主有备"：免 key 爬虫是主通道，可选的第三方搜索 API（配了 key）自动优先、失败自动回退并如实标注。

- ✨ 新增：`search`/`search_read` **免 key 爬虫主通道**（Bing RSS → DuckDuckGo 兜底，正文经 `_page_text` 去噪抽取：剥 script/style/导航/注释、还原实体、折叠空白）
- ✨ 新增：**可选第三方搜索 API 通道**（`ACE_SEARCH_API_KEY/PROVIDER/URL`，内置博查 bocha 适配器，响应容错解析）——配了 key 自动成为首选，任何失败（没配/无效/超时/连不上/0 条）自动回退爬虫，结果带 `route` / `api_fallback` / `api_reason` 如实标注
- ✨ 新增：CLI **状态热切换**——`/permission` `/sandbox` `/net` 交互 TTY 下回车弹出"二次选择框"（选项=主类型分类型、当前值置顶），带参快路径保留（`/net off`、`/sandbox job`）
- ✨ 新增：`/sandbox off|job|docker` **执行档位运行时无缝热切换**——会话历史/权限/快照/审批闸门全部无损，失败语义与 `--sandbox` 完全一致（job/docker 起不来诚实 503，绝不静默回落宿主）
- ✨ 新增：底部状态栏 **F1=权限 / F2=沙箱 / F3=联网** 快捷键，直接弹对应选择框
- ⚙️ 改进：子代理跟随主会话沙箱档位（不再静默在宿主上开"后门"）；`ace.cmd` 默认读取 `~/.ai_code.json`（DeepSeek），不再被参数覆盖成本地 7B
- 🐛 修复：Bing 搜索改为 RSS 端点（HTML 版已把所有结果包成 `ck/a` JS 跳转，解析与下游抓取双双失效）；`net_status` 残留空占位符；F 键热键标记重复 `/` 导致命令变 `//net` 的问题
- 回归：全量断言 935 → **955**，新增 20 条（双通道回退语义、沙箱热切换不变量、交互选择框语义）

## [v2.2] · 2026-08-30

**CLI 视觉重设计（OpenClaw 风格）**

- ✨ 新增：`ace_theme` 语义调色板（dark/light 自动检测）；`ace_cards` 工具结果卡片（状态标记 + 参数摘要 + 输出折叠）；`ace_selector` 居中搜索式选择器（`/model` `/provider` 输入即过滤）
- ✨ 新增：底部状态栏（model | 权限 | 沙箱 | 联网 | goal+动作提示 | 统计）；分层 Ctrl+C（有输入先清空、再按一次才退出）
- ⚙️ 改进：工具结果三态着色展示（成功/拒绝/失败，带原因摘要）
- 🐛 修复：`/` 补全菜单回车语义——选定项先填进输入行不发送、再回车才发送（此前会丢掉选中项或误发送）；logo 颜色调整
- 测试：+31 项（主题 token / 卡片折叠 / 选择器过滤逻辑）

## [v2.1] · 2026-08-29

**Agent 能力爆发（目标 / 子代理 / 会话恢复 / 知识库 / 浏览器）**

- ✨ 新增：**持久目标状态机**（`goal_create` → CLI 自动逐轮续跑，revision CAS、blocked 须给机器码、重启后 `/goal resume` 才续）
- ✨ 新增：**子代理**（spawn/fork，独立上下文与独立执行循环，最多 8 轮，防无限嵌套，独立会话日志）
- ✨ 新增：**会话事件日志**（append-only JSONL 全链路：输入→请求→工具往返→权限→快照→守卫，`/audit` 浏览）与**重启自动恢复**（消息历史 = 日志派生）
- ✨ 新增：**自定义知识库**（`kb_search/kb_add/kb_list`，跨会话持久）+ **search_read**（搜索并抓 top 结果正文）
- ✨ 新增：**Playwright 受控浏览器**（`browser_navigate/click/type`，复用系统 Edge/Chrome）；文件式**技能库**（`skill_list/skill_load`，19 技能目录验证）
- ✨ 新增：权限不足**自动弹临时授权**（y/a/n）不再把 403 甩回模型；同前缀免确认 + `bash -c`/`python -c` 危险包装永不自动放行；`on_failure` 档"有沙箱边界先试后问"；AGENTS.md 层级项目指令
- ✨ 新增：`/net` 联网总开关；i18n zh/en/ja 全界面覆盖（+31 键）
- ⚙️ 改进：发给模型的工具表按权限档位裁剪（readonly=16 个只读+控制工具）；去 emoji（Windows conhost 兼容）；启动横幅显示沙箱/知识库/会话日志档位
- 测试：+80 项左右（goal 状态机 / 日志 seq 契约 / 子代理往返 / 记忆隔离 / 技能库）

## [v2.0] · 2026-08-25

**安全与执行边界**

安全从"进程内策略"升级出真正的内核边界，出站请求全部绑死校验。

- ✨ 新增：**命令三值闸门** `allow/prompt/forbidden`（纯函数可单测，34 条不可逆/持久化命令判 forbidden，`git commit` 类 hook 风险不进 allow）
- ✨ 新增：**SSRF 校验与连接绑定**（全记录校验 + pin-to-IP + 逐跳复检，302 跳内网在第二跳前掐断，DNS rebinding 失效）
- ✨ 新增：**外部内容定界与来源标注**（SEC-011：网页/文件内容一律包进"数据不是指令"隔离块）
- ✨ 新增：**docker 一次性容器执行层**（`--network none` + `--read-only` + `--cap-drop ALL` + `--pids-limit`）；**Go 执行器 + Windows Tier-1 Job Object**；`--sandbox` 扩成 **off / job / docker 三档**——job/docker 起不来一律 503，绝不静默回退宿主
- ✨ 新增：**出站目的地白名单**（egress_allowlist，含逐跳复检与 SMTP 归管）；`ace_http` 模型调用重试退避（Retry-After + full jitter）；`ace_context` 上下文压缩
- 🐛 修复：docker 镜像缺失单独判、单独报（不再让用户去查 pull 权限）；「模型说建好了、其实什么都没发生」的静默假成功
- 🛡️ 安全：审计补齐——检索落点复检、读-改-写严格编码、409 熔断、SQL 连接级只读（`mode=ro`）、快照目录自身不可写、回滚失败告警

## [v1.2] · 2026-08-21 ~ 08-24

**CLI 体验与工具体系**

- ✨ 新增：i18n 国际化（zh/en/ja 界面语言）；**工具注册表单点声明**（`tools/registry.py`：name/schema/权限组/handler 单一事实源）；`ToolExecutor` 拆成 `tools/` 包、`gateway_v2` 拆包
- ✨ 新增：原生工具调用 + Plan Mode + 权限申请 + `@` 快捷方式；`grep`/`glob`/`str_replace`；会话级授权；**默认 readonly** + `terminal_exec` 强制逐次确认
- ✨ 新增：底部状态栏（Claude Code 同款常驻实时刷新）；崩溃黑匣子（未捕获异常写 `~/.ace/crash.log`）
- ✨ 新增：docker lite/standard/full 三档打包方案；原创 logo `assets/logo.svg`；MIT LICENSE；README 顶部真实会话动画 + Mermaid 架构图
- 🐛 修复：回车被补全菜单"吃掉"导致"长时间未响应"；`/open` 路径补全 `start_position` 断言崩溃；Ollama 冷加载"你好没反应"；闪退（颜色格式）
- 🛡️ 安全：终端读文件限项目内；敏感凭据拦截清单扩充；快照元信息 HMAC；回滚失败不再静默

## [v1.1] · 2026-08-20

**真实工具落地**

- ✨ 新增：**真实联网搜索**（search 双引擎 DuckDuckGo/Bing + `/search` 命令 + SSRF 私网防护）；SQLite 读写、浏览器、通知、**免费图像生成**（pollinations）；对话内打开/编辑文件（`open_file`/`edit_file`，默认只给可点击链接不抢焦点）
- ⚙️ 改进：隐藏模型内部思考、`◈` 状态行实时反馈；提示词 v7；CI（GitHub Actions 3.10-3.12 矩阵 + ruff 安全子集）
- 🐛 修复：工具调用 500 三连（路径分词/参数处理/序列化崩溃）；无引号密钥检测误报等 Linux CI 问题

## [v1.0] · 2026-08-19

**初版**

- ✨ 首个可跑闭环：沙盒 Agent 执行层 + Claude Code 风格命令行终端
- ✨ 新增：ACE 登录页/首页主菜单；`--mock` 离线演示与真实模型来回切换；README 结构（特性/分层/架构图/设计参考）

---

格式参考：[Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/) ·
逐版本发布体例参考 [Claude Code CHANGELOG](https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md) ·
[Claude Code Release History](https://raw.githubusercontent.com/alexica00/claude-code-ultimate-guide/refs/heads/main/guide/core/claude-code-releases.md)
