# Changelog

> ACE 开发期未打 git tag，以下**版本号为按开发阶段归纳的检索代称**（非发布版本号），
> 精确到每次提交请 `git log --oneline`。
> 条目分类：✨ 新增 · ⚙️ 改进 · 🐛 修复 · 🛡️ 安全。
> 全量断言随平台浮动（Windows 比 Linux 多十余项），最新 Windows 实测 **955**。

**版本目录**

- [v3.5 · 2026-09-05 · Q-10 错误码目录 + P2/REL 收尾（开发中）](#v35-2026-09-05)
- [v3.4 · 2026-09-05 · test_all SKIPPED 通道(Q-03)](#v34-2026-09-05)
- [v3.3 · 2026-09-05 · 工程化质量收尾（P1 快速项 + 发布件）](#v33-2026-09-05)
- [v3.2 · 2026-09-05 · P0 安全加固：沙箱引用级拦截 + parse_document 越界 + 默认只读](#v32-2026-09-05)
- [v3.1 · 2026-09-05 · 仓库统一 + 实测基准 + 真实模型 e2e](#v31-2026-09-05)
- [v3.0 · 2026-09-05 · 联网双通道 + CLI 状态热切换](#v30-2026-09-05)
- [v2.2 · 2026-08-30 · CLI 视觉重设计（OpenClaw 风格）](#v22-2026-08-30)
- [v2.1 · 2026-08-29 · Agent 能力爆发](#v21-2026-08-29)
- [v2.0 · 2026-08-25 · 安全与执行边界](#v20-2026-08-25)
- [v1.2 · 2026-08-21 ~ 08-24 · CLI 体验与工具体系](#v12-2026-08-21-08-24)
- [v1.1 · 2026-08-20 · 真实工具落地](#v11-2026-08-20)
- [v1.0 · 2026-08-19 · 初版](#v10-2026-08-19)

## [v3.5] · 2026-09-05（开发中）

**Q-10 错误码唯一目录 + 403 语义集中判定**

- ✨ 新增 `tools/status.py`：错误码唯一目录（400/403/404/409/500/501/503/504，8 个规范码）
- ⚙️ 403“安全限制”语义在 `tools/base.execute` **集中判定一次**并写入 `metadata.security_denied`，执行层不再用中文 message 子串各自猜测
- 🛡️ 新增 test_all [36] AST 守卫：代码库中散落的 `error_code` 字面量必须已登记，否则测试红
- 📦 Q-13 打包结论:维持源码运行;扁平模块+__file__ 相对资源(带无 wheel 意义),待 P2 布局重构(ace/ 包 + importlib.resources)后给 console 入口;详见 docs/PACKAGING.md
- 回归：本机 945/945 · 跳过 8（受限环境 0 失败）

## [v3.4] · 2026-09-05

**test_all SKIPPED 通道(Q-03)**

- ⚙️ `test_all.py` 能力探测(requests)+ 独立 `⏭` 跳过计数:`--strict` 时把跳过当失败;
  8 处 requests/联网用例缺能力即跳过而非误红;`elapsed` 断言改为“键存在”防计时抖动误报
- ✅ 效果:本机受限环境首次**全绿** `通过 942/942 · 跳过 8`;CI(装 requests、有联网)跳过为 0,覆盖不丢

## [v3.3] · 2026-09-05

**工程化质量收尾：P1 快速项 + 发布件**

- ⚙️ 测试健壮性：`test_all.py` 临时目录统一走 `.test_tmp/`（消除受限环境系统临时区只读导致的整脚本崩溃）
- ⚙️ ruff 扩选 `F401/F841/E711/F811` 并清理 43 处死导入/未用变量（16 文件）
- ⚙️ `bench` 正确性失败即红（CI 健康门）；`benchmarks/results/` 入库 → 不入库（本机跑不再脏树）
- ⚙️ `ace.cmd` 改为 PATH 探测 python（不再硬编码单机路径）
- 📚 数字去硬编码：README/CONTRIBUTING 工具数/只读数/提供商数改为“以 registry 为准”或“9 家厂商·10 入口”；结构树与 ci compileall 清单补全遗漏模块
- ⚙️ e2e 冒烟改为最多 3 次浅调用重试（抗 API 抖动）；移除 `BehaviorConstraint` 死代码（Q-09）
- 📦 发布件：`version.py` 版本单源；新增 `SECURITY.md` 与 PR 模板；CONTRIBUTING 重写指向 docs/DEVELOPMENT+INTERFACES
- 回归：全量 941/950（本机受限环境 9 项为缺 requests/禁联网等，ubuntu CI 全绿）

## [v3.2] · 2026-09-05（安全加固，未打 tag）

**P0 安全批（BACKLOG SEC-01~06，来自四视角体检 + 实测复现）**

- 🛡️ 修复（SEC-01，高危）：`code_execute` 沙箱只拦“调用点精确名”，`f=open`、`(lambda: exec)('…')`、`().__getattribute__('__class__')` 等别名/lambda/字符串脱壳可绕过 → 改为**危险内建引用级拦截**（`open/exec/eval/compile/__import__/input/breakpoint/globals/locals/vars/getattr/setattr/delattr` 的 Load 引用一律 403）+ 逃逸属性补 `__getattribute__`/`__getattr__`；新增 6 条绕过 payload 回归断言（含“无文件落地”“良性代码仍放行”）
- 🛡️ 修复（SEC-02，高危）：`parse_document` 不过路径闸门，readonly 下可读项目外任意文件 → 与 `file_read` 同口径（存在文件越界/敏感目标 `.key`/`.pem` 等一律 403；不存在仍 404；项目内正常解析）；新增 4 条回归断言
- 🛡️ 修复（SEC-03，部分）：`agent_runner --permission` 默认 `write` 与“默认 readonly”矛盾 → 默认改 `readonly`（对外发写工具的人工确认与 egress 白名单默认策略仍在 BACKLOG 跟进）
- 🛡️ 修复（SEC-04，中）：快照 HMAC 默认关闭 + `.env/*.pem` 明文进 `.guardian` → 签名**默认开启**（无配置时用/建本项目持久密钥 `.guardian/signing_key`，/undo 与重启后回滚仍可验签）；敏感凭据/密钥文件（`.env*`、`*.pem/.key/.p12/…`、`id_rsa` 等）不再拷进快照；新增 5 条回归断言
- 🛡️ 修复（SEC-05，中）：`browser_screenshot` 误归只读且无确认（截图可 OCR 外带）→ 降为写权限；readonly 下自动授权请求；新增 2 条回归断言
- 🛡️ 修复（SEC-06，低-中）：execpolicy 两处小洞 → `git config` 移出免审批白名单（防 `--global` 写 `~/.gitconfig`/注入 hook）；`--opt=路径`（如 `cp a --target-directory=/tmp`）单 token 内嵌越界路径不再被整体跳过，选项值单独过路径校验；新增 4 条回归断言
- 回归：全量断言 942/951（本机受限环境 9 项失败均为缺 requests/禁联网/计时抖动等环境项，ubuntu CI 应全绿）

## [v3.1] · 2026-09-05

**仓库结构统一 + 实测基准 + 真实模型 E2E**

- ⚙️ 改进：仓库结构统一——ACE 成为单一 git 仓库（目录 `ai angent` → `ace`）；提示词工程迭代文档归档进 `docs/prompt-engineering/`（含版本演进表与上下文包）；第三方参考源码（`_reference` 的 cline/codex clone）移出版本控制仅留本地；清理 `.guardian` / `.test_tmp` / `__pycache__` 等快照与缓存（均已 gitignore）
- ✨ 新增：`benchmarks/bench_core.py` 实测基准（纯 stdlib、不联网、一键复现 `python benchmarks/bench_core.py`）——正确性检查 **24/24**，输出 `benchmarks/results/bench_report.{md,json}`；文档中不可复现的预估百分比（如 +200%）已由实测数字替换
- ✨ 新增：`e2e/real_model_smoke.py` 真实模型端到端冒烟（OpenAI 兼容端点，env：`ACE_E2E_BASE_URL/API_KEY/MODEL`）——本机已用 **Ollama + Qwen2.5-coder:7b** 实测通过（提问→执行层裁决→作答，exit 0）
- ⚙️ 改进：CI 新增两个 job——`bench`（基准健康检查，`--quick`）与 `e2e-real-model`（配齐 `ACE_E2E_*` secrets 才执行，未配则跳过、不红）
- 🐛 修复：CI `e2e-real-model` 的 job 级 `if` 引用 `secrets`（GitHub 不允许，会导致整个 workflow 秒失败）→ 改为 step 内 env 传值 + shell 空值自检
- 🐛 修复：`tools/skill_tools.py` docstring 无效转义 `\A`（Python 3.12 SyntaxWarning）

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
