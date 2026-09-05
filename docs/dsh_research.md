# DSH（DeepSeek Harness）源码调研：ACE 可借鉴设计清单

- 调研对象：`C:\Users\<用户名>\Desktop\deepseek-harness`（TypeScript monorepo，docs/subsystems/* 设计文档 + 关键包源码）
- 调研方式：直读 docs 与源码（行号经 read/grep 核实）+ 4 个并行子代理分域深挖（沙箱/审批、会话/压缩、skill/subagent/workflow/goal、循环/错误/流式/UI）
- ACE 现状（用于排除"已有"）：Python 实现；五层网关、Guardian 快照回滚、SimHash 记忆、Go 执行器（Job Object+受限令牌）、docker 沙箱、NDJSON IPC、工具按权限裁剪、提示注入隔离（ACE_EXTERNAL_DATA）、上下文压缩、i18n 三语
- 行号基准：仓库相对路径（相对 `deepseek-harness/`），均已核实

---

## 主题 A：沙箱 / 权限 / 审批（ACE 缺什么）

### A1. 三态文件效应模式 + per-call 完整策略载体
- **源码位置**：`packages/sandbox/sandbox/src/index.ts:29`（SandboxMode = read-only|workspace-write|danger-full-access）、`:39-52`（SandboxExecutionPolicy：mode+workspaceRoot+sessionId 每次调用携带）、`:69-72`（SandboxPolicy 只允许受限模式）
- **解决什么问题**：把权限从"全局开/关"变成每次 capability 调用显式携带的完整策略（含会话标识、工作区根）；同一时刻 bash 可 read-only、子代理可 workspace-write；一次批准过的加宽重试是"新调用带新 mode"，不污染会话
- **ACE 借鉴价值**：高
- **大致实现成本**：中

### A2. per-call 解析优先级：显式授权 > 会话事件 > 部署默认
- **源码位置**：`packages/sandbox/sandbox-policy/src/index.ts:135-142`（resolve 优先级）、`:149-151`（overrideOf 纯折叠）；`session-mode.ts:33-38`（`sandbox/mode` 会话事件声明）、`:52-58`（effectiveSandboxMode 反向扫描）、`:69-70`（setSandboxMode 单写路径）
- **解决什么问题**：模式覆盖存放在会话日志里（replay 即状态，无需独立配置存储）；delegation 标记区分"子代理继承种入"与"人类切换"
- **ACE 借鉴价值**：高
- **大致实现成本**：中

### A3. enforcement 完整性报告（full/partial）——诚实降级
- **源码位置**：`packages/sandbox/sandbox/src/index.ts:59`（SandboxEnforcement）；`packages/sandbox/sandbox-local/src/index.ts:177-187`（windows-acl 恒 partial）、`:492-510`（selectRunner/chainVerdict）
- **解决什么问题**：老内核 Landlock ABI、Windows Everyone/hard-link 边界无法覆盖全部承诺文件效应时显式报 partial，要求绝对边界的消费方不得当作 full。ACE 在 macOS/WSL 用 docker 映射卷同样存在半强制场景
- **ACE 借鉴价值**：高
- **大致实现成本**：小

### A4. 多后端探测链 + fail-closed
- **源码位置**：`packages/sandbox/sandbox-local/src/index.ts:68-112`（defaultProbeBwrap/Seatbelt/WindowsAcl 真实跑 `true` 探测）、`:159-166`（PLATFORM_CHAINS）、`:316-333`（confine 失败抛 SandboxUnavailableError，绝不无限制放行）、`:499-510`（唯一候选免探测）
- **解决什么问题**：Linux 优先 bwrap→Landlock、macOS Seatbelt、Windows ACL；不可用即拒绝而非裸跑
- **ACE 借鉴价值**：高（Go 执行器可加"本地受限令牌 → docker → 拒绝执行"探测链）
- **大致实现成本**：中

### A5. stderr 双正交分类器：denialSignatures vs RunnerFailureRule
- **源码位置**：`packages/sandbox/sandbox/src/index.ts:81-94`（RunnerFailureRule：allowedExitCodes+fatalSignatures+informationalLines）、`:95-116`（ConfinedArgv 携带两套正交分类器）、`:108`（denialSignatures）
- **解决什么问题**：两种失败语义必须区分——沙箱基础设施坏了（命令从未运行）vs 策略正确拒绝了命令（限制生效）；后者不应被模型当作"命令失败"重试；退出码单独永远不能证明 runner 失败
- **ACE 借鉴价值**：高（Go 执行器+docker 当前最缺：把 docker daemon 故障/镜像拉取失败与策略拒绝分开）
- **大致实现成本**：中

### A6. 每后端拒绝方言表（不跨后端取并集）
- **源码位置**：`packages/sandbox/sandbox-local/src/index.ts:205-213`（DENIAL_SIGNATURES：bwrap=`read-only file system`、landlock=`permission denied`、seatbelt=`operation not permitted`、windows-acl 三词）；`packages/shell/bash-sandbox/src/helpers.ts:67-69`（classifyDenial）、`:112-116`（matchesSignature）
- **解决什么问题**：跨后端方言并集会"声称某后端从不产生的拒绝"误导分类；每个 wrap 携带自己后端的精确方言
- **ACE 借鉴价值**：高
- **大致实现成本**：小

### A7. 审批闭式 outcome + fail-closed
- **源码位置**：`packages/interaction/user-approval/src/types.ts:29`（ApprovalOutcome = allowed-once|rejected|cancelled|unavailable）；`index.ts:257-276`（request：先审计后取结果，缺答/乱答归一为 unavailable）
- **解决什么问题**：allowed-once 只授予"被问的那个动作"，无会话级宽放；不可用即拒绝——审批的第一原则
- **ACE 借鉴价值**：高
- **大致实现成本**：中

### A8. 会话级 ask/never 策略 + 服务内强制执行
- **源码位置**：`packages/interaction/user-approval/src/index.ts:94-97`（ApprovalPolicy = 'ask'|'never'）、`:112-118`（effectiveApprovalPolicy 折叠会话日志）、`:142-147`（setApprovalPolicy 单写路径）、`:304-329`（decide：'never' 在派发前返回 rejected——即使后注册的 prepend 监听器也无法绕过）
- **解决什么问题**：headless/CI 确定性拒绝；策略由服务自己执行而非"门卫监听器"（注册顺序不可绕过）
- **ACE 借鉴价值**：高
- **大致实现成本**：中

### A9. 审批审计对 + 开回合前置 + 可撤销
- **源码位置**：`packages/interaction/user-approval/src/index.ts:44-58`（approval/asked + approval/decided 配对审计事件）、`:127-134`（hasOpenTurn：审计对必须被 turn 包裹）、`:331-343`（abort 竞速胜出→cancelled，迟到答案丢弃）
- **解决什么问题**：每次询问都有可回放审计；审计失败则拒绝返回未记录的决策
- **ACE 借鉴价值**：高（与 ACE 的 Guardian 回滚体系天然结合）
- **大致实现成本**：中

### A10. 严格加宽阶梯 + 一次性授权
- **源码位置**：`packages/sandbox/sandbox/src/escalation.ts:28-31`（WIDER_MODES：read-only→workspace-write/danger-full-access）、`:41`（ESCALATION_TARGETS）、`:51-61`（sandbox_permissions 与 justification 必须配对且非空句）、`:157-188`（approveEscalation：先验严格加宽→解析通道→授权 mode 只盖这一个调用）
- **解决什么问题**：模型被拒后可"同回合一次重试"，但必须先过用户审批、必须是严格加宽、审批失败即终局
- **ACE 借鉴价值**：高（ACE 缺失的细粒度审批流最小可用形态）
- **大致实现成本**：中

### A11. 权限预设组合（sandbox+approval 捆绑）
- **源码位置**：`packages/interaction/permission-presets/src/index.ts:167-176`（默认表：workspace-write+ask / danger-full-access+never）、`:304-321`（current 派生：先认"仍匹配的已选预设"，否则声明序首个匹配，否则 derived-only 的 custom）、`:375-392`（set：先记 permission/preset 事件，再分别经两个 knob setter 写穿）
- **解决什么问题**：两个独立旋钮包装成单一用户选择器；preset 事件是 log-only 用户意图，保留共享 bundle 时用户选了哪一个
- **ACE 借鉴价值**：中高
- **大致实现成本**：小-中

### A12. fs 观察→写入分级（read-before-write + 版本 CAS）
- **源码位置**：`packages/fs/fs-observation-policy/src/index.ts:65-71`（writeIntent：未见→createIfAbsent；确认存在→replaceIfVersion）、`:78-88`（editIntent：未见→FS_NOT_OBSERVED；存在→版本 CAS）、`:91-94`（observe 记录 present@version/absent）；错误码分离见 `docs/subsystems/filesystem.md:254-268`（FS_STALE_VERSION/FS_NOT_OBSERVED/FS_SANDBOX_DENIED 与内核 FS_PERMISSION_DENIED 分立）；fs 工具发事件点：`packages/fs/tool-fs/src/write.ts:111`、`edit.ts:126`、`read.ts:162`
- **解决什么问题**：未经先读的文件禁止改；版本令牌防覆盖外部并发修改；策略通过事件注入不改工具
- **ACE 借鉴价值**：高（ACE 的 write/edit 目前是无条件覆盖，最值得抄的一条）
- **大致实现成本**：中

### A13. 模型可见的策略上下文渲染
- **源码位置**：`packages/sandbox/sandbox-policy/src/index.ts:38-52`（renderPolicyContext："Current DSH file policy: …"）、`:112-123`（注入 systemPrompt context）
- **解决什么问题**：模型每次请求可见当前策略文本，且由日志快照重建，不重写稳定系统提示词前缀（KV 缓存友好）
- **ACE 借鉴价值**：中
- **大致实现成本**：小

### A14. Windows ACL 受限令牌沙箱（对 Go 执行器直接相关）
- **源码位置**：`packages/sandbox/sandbox-windows-acl/README.md:7`（WRITE_RESTRICTED 令牌+限制 SID 交集放行；workspace SID 确定性、temp SID 每会话随机）、`:41`（每个 Win32 调用查错，fail-closed）；`src/runner.ts:54-55`（`windows-acl-run:` 签名+exit 127）、`:115-205`（受限令牌→重写 TMP/TEMP 到私有目录→KILL_ON_JOB_CLOSE job→镜像退出码→撤销 temp 授权）；`packages/sandbox/sandbox-local/src/index.ts:358-443`（standing ACE 复用缓存+幂等 re-grant 跳过全树重播）
- **解决什么问题**：Windows 无 docker 时的进程级文件写限制；跨会话 temp 权限不互渗；崩溃残留因新随机路径而惰性
- **ACE 借鉴价值**：高（Go 执行器已有 Job Object+受限令牌基础，补 WRITE_RESTRICTED+限制 SID 是自然延伸）
- **大致实现成本**：大

---

## 主题 B：会话 / 记忆 / 压缩（ACE 缺什么）

### B1. 事件溯源 session 日志 + seq 连续契约 + 深冻结
- **源码位置**：`packages/core/session/src/types.ts:27-128`（SessionEventMap 全事件词汇：turn/start、step/start、user/message、assistant/chunk、assistant/message、tool/call、tool/result、request/header、todo/write…）、`:216-249`（SessionEvent 判别联合：seq/time/ignorable/sourceEventSeqs/surfaceOp）；`packages/core/session/src/index.ts:604-655`（append：JSON 可序列化校验+深冻结+同步发布）、`:512-527`（seed seq 从 0 连续）
- **解决什么问题**：LLM 消息历史永远从日志派生，永不单独存储；坏事件在追加点失败而非落盘时失败；任何时刻可重放重建
- **ACE 借鉴价值**：高（ACE 的记忆/压缩目前不可审计、不可重放）
- **大致实现成本**：大（根基，可分期）

### B2. 「模型可见 ⟺ 可记录」可重建性原则
- **源码位置**：`packages/core/session/src/types.ts:57`（assistant/chunk 原始流入日志）、`:74`（tool/call 保留原始 arguments JSON 字符串）、`:99`（request/header 全量快照——每次请求的 envelope 是日志的纯函数）；仓库根 `AGENTS.md`（"anything that reaches a model request must be reconstructable from the session log"）
- **解决什么问题**：任何到达模型的输入都能从日志+代码重建——压缩、回滚、审计、调试都能精确复现当时请求
- **ACE 借鉴价值**：高（这是 ACE 上下文压缩无法回滚到任意时刻的根因）
- **大致实现成本**：中

### B3. surface 投影层 + replace 无损压缩
- **源码位置**：`packages/core/session/src/surface.ts:387-395`（foldSurface 完整重放）、`:398-459`（SurfaceManager 增量投影）、`:83-114`（deriveEventMessage 每节点纯投影——live 缓存与外部重建用同一函数）、`:246-266`（replacementRange 按 surface 位置而非 seq 区间）、`:210-243`（替换必须引用全部被影藏节点）；`packages/core/session/src/index.ts:701-747`（deriveMessages 增量缓存，replace 时整表重建）
- **解决什么问题**：模型历史=对 surface 节点的投影；DSH 的压缩 replace 是无损的（原始事件仍在日志，仅 surface 隐藏，可追溯 shadowedSeqs）
- **ACE 借鉴价值**：高
- **大致实现成本**：大（需先有 B1）

### B4. compaction 三事件锁协议 + 孤儿锁检测
- **源码位置**：`packages/compaction/compaction/src/types.ts:23`（compaction/start）、`:33-66`（compaction/summary 含 shadowedRange/shadowedSeqs/shadowedTokenCount/provider/model）、`:71`（compaction/end）；`packages/compaction/compaction-basic/src/region.ts:189`（start 同步先追加）、`:215`（end 最后追加——崩溃即产生可检测孤儿锁而非"假装完成"）、`:517-549`（inspectCompactionEntryState：从尾部扫描 unmatched start）、`:286-298`（assertCompactionInactive：unmatched start 在 session/end-seed 之前⇒属上一生命周期忽略；之后⇒busy）
- **解决什么问题**：锁以持久化事件形式存在；崩溃/重启后正确区分"已死进程的锁"与"正在压缩的锁"
- **ACE 借鉴价值**：高（ACE 的上下文压缩无锁协议，并发/崩溃下不安全）
- **大致实现成本**：小-中

### B5. 预期失败分类 ManualCompactionErrorCode
- **源码位置**：`packages/compaction/compaction/src/index.ts:28-34`（busy|cancelled|changed|summary|commit|persistence）；`region.ts:257-277`（throwManualFailure）
- **解决什么问题**：手动压缩的每个失败阶段有稳定机器可路由错误码；changed/summary 失败也留痕于日志
- **ACE 借鉴价值**：中
- **大致实现成本**：小

### B6. 保留尾部 + 平衡切分（不拆 tool-call/result 配对）
- **源码位置**：`packages/compaction/compaction-basic/src/region.ts:98-134`（selectCompactableRange：从尾部累计保留预算，再向前找平衡边界）；`packages/compaction/compaction/src/index.ts:17`（toolPairingBalancedBefore/After）
- **解决什么问题**：只压缩最旧有用范围、保留最近 verbatim 尾部、绝不拆散工具调用与其结果
- **ACE 借鉴价值**：高
- **大致实现成本**：小-中

### B7. token 计量驱动自动压缩（pressure / context-overflow 双触发点）
- **源码位置**：`packages/compaction/compaction-basic/src/index.ts:147-165`（agent/pre-step 串行压力检查，请求派生前）、`:179-223`（agent/request-error——仅当 surface.replaceGeneration 前进才授权重试）、`:258-332`（compactIfNeeded：先裁剪后选段再摘要）；`config.ts:20-23`（thresholdRatio 0.8、retainRatio 0.16）、`:133-167`（按模型 contextWindow 缩放预算）；`packages/llm/token-meter/src/index.ts:74-84`（measure：复用提供方 usage 锚点，否则启发式重定价）
- **解决什么问题**：压缩触发基于可重放 token 计量+提供方确认的溢出信号，而非启发式拍脑袋；"免费裁剪先落地、摘要失败不丢已取得的缩减"
- **ACE 借鉴价值**：高（ACE 无自动压缩策略）
- **大致实现成本**：大

### B8. tool-result 确定性头/中/尾裁剪 + 影子价格事件
- **源码位置**：`packages/compaction/compaction-tool-result-pruner/src/index.ts:83-122`（pruneContent：保留 headChars/tailChars，中间替换标记，保留富块顺序）、`:68-74`（measureContent）、`:162-166`（先追加 compaction/prune 定价事件）、`:167-173`（紧随追加 tool/result 替换事件 surfaceOp: replace）；`config.ts:7,10-14,27-29`（Unicode 码点计数不切破代理对）；`packages/compaction/compaction/src/types.ts:81-88`（compaction/prune 事件声明）
- **解决什么问题**：超大工具结果确定性瘦身（同输入必同输出，可重放验证），无模型调用；纯消费者无需逐节点保留价格即可做 token 记账——"替换的代价"是日志事件
- **ACE 借鉴价值**：高
- **大致实现成本**：小

### B9. spill 溢出落盘 + 头尾预览替换
- **源码位置**：`packages/spill/spill/src/types.ts:56-66`（SaveTextSpill）、`:69-73`（SpillRef：locator+bytes+retrievalHint）；`packages/spill/spill-policy/src/index.ts:190-209`（tools/post-execute 挂载点）、`:171-187`（预览预算预扣提示行字节，替换结果永不超过 maxInlineBytes）、`:195-197`（read 工具豁免防死循环）；`packages/spill/spill-local/src/store.ts:107-120`（open 'wx' 0o600 独占写防 symlink 劫持）
- **解决什么问题**：超大工具输出不截断不丢失——全文落盘，模型拿"定位符+用什么工具读回"的指引；存储故障是降级不是失败（`index.ts:153-161`）
- **ACE 借鉴价值**：高
- **大致实现成本**：小-中

### B10. 注册式投影单元（session-projection）
- **源码位置**：`packages/session/session-projection/src/index.ts:42`（ProjectionDefinition：init/apply/view 三个纯同步函数+stateVersion）、`:194`（register）、`:248`（snapshot 同步一致读）、`:271`（checkpoint）、`:355`（restore）；`packages/session/session-projection-cache/src/index.ts:119`（cachedSnapshot 零 I/O 冷读：缓存行→readFrom 尾部→restore→写回，"可能陈旧但永不错"）
- **解决什么问题**：任何"会话派生状态"（统计、token 压力、标题）用同一机制声明式派生：框架订阅 session/event 一次、逐事件 fold；状态引用不变（Object.is）则零下游工作
- **ACE 借鉴价值**：中高（SimHash 记忆/统计可做成事件派生单元）
- **大致实现成本**：中

### B11. LLM 会话标题（latest-wins + 用户重命名 pin）
- **源码位置**：`packages/session/session-title/src/index.ts:100`（session/title 事件）、`:192`（折叠取最新）、`:363-374`（rename：用户标题 pin 住，自动生成停排）、`:465-535`（first-prompt/all-prompts 节奏）；`packages/session/session-title-llm/src/index.ts:262-269`（辅助请求派发前先入日志——辅助调用也遵守"模型可见⟺可记录"）
- **解决什么问题**：标题是日志派生状态，可跨进程重建；用户显式改名是持久化决定
- **ACE 借鉴价值**：中（低成本高感知收益）
- **大致实现成本**：小

### B12. session-query：SQL 检索历史 + surface 三态 + 事件溯源链
- **源码位置**：`packages/session-query/session-query/src/extraction.ts:13-42`（语义文本提取：消息/推理/工具调用/结果/失败原因/todo；结构事件与 chunk 不提取）、`documents.ts:56-74`（classifySurface：与模型历史派生同一 foldSurface，标 current|shadowed|log-only）；`packages/session-query/session-query-sqlite/src/schema.ts:8`（SCHEMA_VERSION 8）、`:127-137`（FTS5 持久表）、`:141-169`（temp.live_docs 临时表）；`packages/session-query/tool-session-query/src/index.ts:52-120`（模型可见工具 session_search/session_event_search/session_trace/…）、`operations.ts:60-113`（cwd 工作区授权）、`:127-136`（当前会话检索自动排除当前 step 之前）；`packages/session-query/session-query/src/types.ts:105-121`（SessionEventTrace：replacedBy/replacementChain/sourceEventSeqs/derivedEventSeqs）
- **解决什么问题**：把"检索历史"变成模型可用工具（非仅 UI），检索边界=工作区授权边界；可回答"这个事件被谁替换/谁由它派生"
- **ACE 借鉴价值**：高（SimHash 记忆是无定位的，这是结构化检索）
- **大致实现成本**：中

### B13. 跨会话引用（session-reference）
- **源码位置**：`packages/context/session-reference/src/index.ts:75`（prepare：被引用会话投影为聚合的不可信上下文）、`:147`（listCandidates）；`docs/subsystems/session-reference.md`（canonical `@[label](dsh-session:…)` mention）
- **解决什么问题**：检索到的历史可直接以结构化引用注入当前提示（带预算/自引用/超量错误码）
- **ACE 借鉴价值**：中
- **大致实现成本**：中

### B14. 崩溃恢复：合成 interrupted turn/end（不截断）
- **源码位置**：`packages/core/session/src/repair.ts:85-131`（从 last.seq+1 补 step/end 与 turn/end reason interrupted）
- **解决什么问题**：崩溃后不丢事件、只补平衡边界；interrupted 是唯一非循环产出的 TurnEndReason，消费者可区分干净停止与截断
- **ACE 借鉴价值**：中
- **大致实现成本**：中

### B15. write-behind 批处理 + flush 屏障
- **源码位置**：`packages/session/session-persistence/src/write-behind.ts:45-56`（enqueue）、`:63-72`（flush）、`:139-158`（失败保留重试）；`packages/session/session-persistence/src/coordinator.ts:13,77-80`（SESSION_FORMAT_VERSION 拒绝文本——新旧格式互斥）
- **解决什么问题**：append 热路径永不阻塞 I/O；flush 是循环确认持久化的唯一屏障
- **ACE 借鉴价值**：中
- **大致实现成本**：中

---

## 主题 C：skill / subagent / workflow / goal / todo / jobs / plan / schedule

### C1. 技能目录"加载即注入"为持久 system-reminder，正文按需加载
- **源码位置**：`packages/skill/tool-skill/src/index.ts:213-251`（agent/pre-step 目录注入）、`:254-311`（renderCatalogMessage 全量替换）、`:328-335`（目录 digest 比较）、`:361-377`（catalogHistory 可见性判定）；`packages/skill/skill-filesystem/src/index.ts:241-260`（六层根：project-dsh→project-agents→custom→user-dsh→user-agents→bundled）、`:793-835`（parseSkillFile）、`:996-1000`（disable-model-invocation / user-invocable frontmatter）
- **解决什么问题**：模型知道"有哪些技能可用"但不把正文塞进系统提示；目录消息带 durable skill-catalog source；技能全文只在调用 skill 工具时加载
- **ACE 借鉴价值**：高
- **大致实现成本**：中

### C2. 按需加载 skill 工具 + 规范渲染 + 执行层二次校验
- **源码位置**：`packages/skill/tool-skill/src/index.ts:81-160`（skill 工具）；`packages/skill/skill/src/index.ts:171-184`（renderSkillContent：`<skill_content name>`/`<skill_resources>`/`<skill_instructions>`，escapeText 防标签逃逸）、`:127-138`（isModelInvocable）
- **解决什么问题**：加载时机由模型决定；执行时先查摘要再查全文并两次校验策略，防目录过滤被绕过
- **ACE 借鉴价值**：高
- **大致实现成本**：小-中

### C3. subagent：spawn vs fork 上下文继承/隔离
- **源码位置**：`packages/subagent/subagent-fork-in-process/src/index.ts:41-64`（completedTurnPrefix：截到最后一个 turn/end 的平衡前缀 seed，进行中回合排除）；`packages/subagent/tool-subagent/src/index.ts:220-245`（按 inheritsParentContext 动态措辞工具描述）
- **解决什么问题**：fork 继承父会话已完成回合前缀（seq 0 连续、平衡、可重放），spawn 全新开始
- **ACE 借鉴价值**：高（NDJSON IPC 已有会话概念，加"平衡前缀 seed"即得 fork 语义）
- **大致实现成本**：中

### C4. 可延续子代理：持久 Session + Activation + followup/interrupt + 冷恢复
- **源码位置**：`packages/subagent/subagent/src/continuation.ts:355-409`（startContinuable）、`:502-522`（followup 按 running/waiting/无 Activation 三分支）、`:554-590`（interrupt 授权：user 父地址或 exact 活祖先）、`:932-935`（stateOf 由 Agent 静默+ownedChildren 推导）、`:945-993`（coldResume 经 ctx.agents.resume）、`:1343-1434`（child-first 有界处置）
- **解决什么问题**：后台子代理是持久 child Session，进程内最多一个 Activation 驻留纪元；父代理 inbox 是唯一 FIFO 队列；无 Activation 时从持久日志冷恢复——"后台代理可继续对话、可中断、可恢复"
- **ACE 借鉴价值**：高（完全缺失子代理体系）
- **大致实现成本**：大

### C5. report 回传通道 + 结算通知
- **源码位置**：`packages/subagent/tool-subagent-report/src/index.ts:49-129`（installReportTool 装入子代理 scope）；`packages/subagent/subagent/src/continuation.ts:609-618`（reportFrom）、`:657-698`（deliverReport：agent.inject 静默 / agent.steer 唤醒）、`:82-88,1462-1507`（subagent-settled 结算通知，父代理必达一次）
- **解决什么问题**：子代理向直接父代理回传结果而不结束自己的回合；结算通知保证父代理知道子代理如何结束
- **ACE 借鉴价值**：高
- **大致实现成本**：中

### C6. 持久 descriptor + 不加载 Agent 的枚举
- **源码位置**：`packages/subagent/subagent/src/descriptor.ts:49-88`（one-shot/continuable 判别+冷恢复所需字段快照）；`packages/subagent/subagent/src/index.ts:355-374`（listChildren/listDescendants）
- **解决什么问题**：子代理身份是持久化会话事件；枚举直接从 session store 折叠，不 load/resume Agent
- **ACE 借鉴价值**：中
- **大致实现成本**：中

### C7. goal 持久状态机 + 修订号 CAS 并发控制
- **源码位置**：`packages/goal/goal/src/types.ts:19`（GoalRef：id+revision）、`:44-55`（GoalPhase = active|paused|blocked|complete）、`:51-55`（GoalBlockReason：机器 code+人类 message）；`packages/goal/goal/src/index.ts:401-411`（expectCurrent：stale 即 GOAL_STALE_REVISION）、`:542-558`（commit：append goal/change 全量快照事件）；`packages/goal/goal/src/fold.ts:313-330`（严格重放：轮次必须=roundsStarted+1，拒绝 gap/stale/超 cap）
- **解决什么问题**：所有变更要求携带期望 revision，重放严格校验过渡合法性——防"模型重试/并发时旧状态覆盖新状态"
- **ACE 借鉴价值**：高
- **大致实现成本**：中

### C8. 轮次驱动（round driver）：空闲自动续跑 + 一轮一消息
- **源码位置**：`packages/goal/goal-round-driver/src/index.ts:138-205`（drive：静默检查→checkpoint→保留下一轮→followup）、`:103-109`（readyToDrive：agent idle 且无竞争输入）、`:349-414`（pre-step 校验队列消息仍持有 exact revision，无效则 reject）；`prompt.ts:12-24`（`<goal_round>` 提示模板：Round N/M）
- **解决什么问题**：目标 armed 后 agent 空闲即自动发起下一轮，每轮恰好一条 goal-source 消息；人类输入/reject/max-tokens 都有明确处置
- **ACE 借鉴价值**：高（完全无 goal 循环）
- **大致实现成本**：大

### C9. blocked 三轮判定 + armed/disarmed 分离
- **源码位置**：`packages/goal/tool-goal/src/index.ts:295-306`（blocked 前 roundsStarted ≥ blockedAfterConsecutiveRounds 默认 3，否则 GOAL_TOOL_BLOCK_THRESHOLD）、`:309-312`（code 'model-reported'）；`packages/goal/goal/src/index.ts:236-242`（disarm 不动持久 phase）、`:198-200`（session-start 自动 disarmed，须人类 resume 才重新武装）、`:310-328`（resume 校验轮次预算）
- **解决什么问题**：同一阻塞条件持续至少 3 轮才可自报 blocked，须给出机器 code+人类 message；difficulty/uncertainty 不算；重启后不会无授权自动续跑
- **ACE 借鉴价值**：高
- **大致实现成本**：小-中

### C10. todo_write 全量替换协议
- **源码位置**：`packages/todo/tool-todo/src/index.ts:91-111`（toTodoList：空/重复 content 拒绝，single-active 可配）、`:149-225`（工具定义/execute：每次发送整单，todo/write 事件全量快照）；`packages/core/session/src/types.ts:148-154`（TodoItem 极简：content+三态 status，无 id——整单替换所以无需身份）
- **解决什么问题**：模型不维护增量编辑；allowParallelInProgress 决定并发语义并反映在工具描述；UI 从日志渲染
- **ACE 借鉴价值**：高
- **大致实现成本**：小

### C11. 后台作业注册表（jobs）
- **源码位置**：`packages/jobs/jobs/src/index.ts:62-177`（JobRegistry：start/list/get/read/kill/wait/onJobDone/onJobsChanged）；`packages/jobs/jobs/src/types.ts`（JobStart/JobHooks/JobOutcome/JobSnapshot：status running|stopping|completed|killed|failed）；`packages/jobs/tool-jobs/src/index.ts:279-300`（onJobDone 通知）、`:302-340`（job_output：wait 有界/增量）、`:362-401`（job_kill）
- **解决什么问题**：长任务统一抽象——start 原子注册、按 owner session 鉴权（id 可预测，鉴权而非保密）、read 分流式增量/终态幂等、kill 幂等、完成注入忙 owner 或唤醒空闲 owner
- **ACE 借鉴价值**：高
- **大致实现成本**：中

### C12. 完成通知纪律：reported 单次 + wake 预算 + 字节裁剪
- **源码位置**：`packages/jobs/tool-jobs/src/index.ts:45-53`（maxConsecutiveWakes 默认 3）、`:293-300`（预算耗尽降级 inject）、`:146-167`（有界字节裁剪）；`packages/jobs/jobs-local/src/index.ts:416-440`（first-wins settle：一个终态记录、一次通知）
- **解决什么问题**：一个 job 终态只通知一次，避免"唤醒回合又启动新 job 再唤醒"的自我激励链
- **ACE 借鉴价值**：中
- **大致实现成本**：小

### C13. plan mode 作为持久化日志状态 + exit_plan_mode 审批闭环
- **源码位置**：`packages/plan/plan-mode/src/index.ts:130-139`（foldPlanMode：plan/mode 最后值胜出）、`:445-465`（set：committed/queued/cancelled/noop）、`:468-480`（onBoundary：turn 内选择 pending 到下一个接受 pre-step 才追加）、`:229-237`（plan:policy 系统提示段）；`exit_plan_mode` 工具 `:325-413`（校验 `#` 开头完整 markdown → 经 userQuestions 审批 → 批准则退出，Keep planning 反馈回模型）
- **解决什么问题**：计划模式是 log-only 会话事件，重放/分叉/压缩自动恢复，无内存镜像；退出必须呈交完整计划审批
- **ACE 借鉴价值**：高
- **大致实现成本**：中

### C14. workflow 编排脚本 + fatal 错误纪律
- **源码位置**：`packages/workflow/workflow/src/index.ts:130-148`（WorkflowError.fatal：钩子误用必须杀死脚本，绝不溶解成普通子代理失败）；`packages/workflow/tool-workflow/src/index.ts:138-150`（agent/pipeline/parallel/phase/log 钩子契约）；`packages/workflow/workflow-worker-thread/src/index.ts:57-70`（启动前预解析，SCRIPT_PARSE 同步抛）、`:91-99`（maxTotalAgents 上限）；`docs/subsystems/workflow.md`（phases 只是进度词汇不构成执行结构）
- **解决什么问题**：模型写脚本扇出子代理；fatal 错误 vs 普通子代理失败（落 null）严格区分
- **ACE 借鉴价值**：中（需先有子代理体系）
- **大致实现成本**：大

### C15. schedule：持久会话内提醒
- **源码位置**：`packages/schedule/schedule/src/types.ts`（After/At/Every 记录）；`packages/schedule/schedule/src/runtime.ts:231-318`（driveOnce：等 agent 完全 idle → followup 一回合）；`packages/schedule/schedule/src/tools.ts:318-372`（schedule_create 三种互斥选择器）
- **解决什么问题**：代理安排"稍后/定时/每 N 分钟"回访自身会话；错过窗口的 Every 只补最新一次（锚定对齐）；投递是普通对话回合
- **ACE 借鉴价值**：中
- **大致实现成本**：中

### C16. 斜杠命令注册表（不经模型执行）
- **源码位置**：`packages/interaction/commands/src/index.ts:116-123`（parseCommand）、`:145-160`（执行路径：command/run 先写日志再调 handler，command/done 收尾）；`docs/subsystems/commands.md`
- **解决什么问题**：人类 UI 直接执行插件命令（如切权限预设）不消耗模型轮次，生命周期可审计
- **ACE 借鉴价值**：中
- **大致实现成本**：小-中

### C17. user-questions seam（稳定 id 回显 + 批量提问 + intent）
- **源码位置**：`packages/interaction/user-questions/src/index.ts`（AskUserQuestionItem：id 回显、multiSelect、custom 自由文本；intent 只改呈现不改协议，approve 按名不按位）；`index.ts:51`（ask：仅精确活跃的运行时根可问人，DELEGATED_CALLER 拒绝被拥有子代理提问）
- **解决什么问题**：工具/权限插件需要人类回答时经统一 seam 问 UI
- **ACE 借鉴价值**：中
- **大致实现成本**：小

---

## 主题 D：循环 / 错误处理 / 重试 / 流式协议 / UI

### D1. agent 生命周期事件钩子（pre-step / request / request-error / turn-stopping）
- **源码位置**：`packages/core/agent/src/runtime-types.ts:231`（agent/pre-step waterfall）、`:244`（agent/request）、`:260`（agent/request-error）、`:278`（agent/turn-stopping serial）；`packages/core/agent-loop/src/agent.ts:235`（pre-step 派发）、`:375`（request-error 派发）、`:458`（request 派发）、`:195`（whenIdle）；完整序列见 `docs/agent-lifecycle.md`
- **解决什么问题**：turn→claim→pre-step（可权威拒绝/enter）→step→assistant→tool 循环→turn/end；插件挂在离散钩子上，不改循环本体；request-error 返回 { kind: 'retry' } 或保留原错误
- **ACE 借鉴价值**：高（五层网关可对齐为离散钩子）
- **大致实现成本**：中

### D2. 工具执行管线：pre → guards → execute → post 四段瀑布 + 结果事件
- **源码位置**：`packages/core/tools/src/index.ts:152`（tools/pre-execute）、`:163`（tools/execute，around 包装：超时/重试/指标）、`:175`（tools/post-execute：accept/block/replace/add context）、`:197`（tools/result 同步通知）；monotonic guards `:1101-1124`（守卫可 deny 不可 force-allow，按注册序，被拒调用的结果仍走 post）；`docs/tool-execution-pipeline.md` 全流程图
- **解决什么问题**：策略（审批/沙箱/超时/裁剪）全部挂在瀑布上，工具本体不耦合策略；guard 是同步断言，先于 execute 执行
- **ACE 借鉴价值**：高
- **大致实现成本**：中

### D3. 持久化重试调度（llm-retry）
- **源码位置**：`packages/llm/llm-retry/src/index.ts:210-219`（agent/request-error 瀑布挂载）、`:150-153`（每次重试调度先入日志 llm/retry + llm/retry-started，再可取消等待）、`:182-190`（从日志 findLast 推导 previousRetry——回放安全、崩溃安全）、`:177`（retryableCodes 门控）、`:194-205`（providerRetryAfterMs 优先）、`:58-63`（指数退避+jitter 封顶 maxDelayMs）；`packages/llm/llm/src/retry-policy.ts:14-24`（默认可重试码 EMPTY_RESPONSE/RATE_LIMIT/SERVER/TIMEOUT/TRANSPORT；500ms 起、10s 上限、0.1 抖动）；`packages/llm/llm-deepseek/src/adapter.ts:129-137`（解析 retry-after 头）、`:150-162`（HTTP 状态→稳定错误码：429→RATE_LIMIT、400 上下文溢出→CONTEXT_WINDOW_EXCEEDED、≥500→SERVER）
- **解决什么问题**：重试策略由 provider 注册时解析为不可变策略；每次调度持久化后才等待——重启不丢重试进度；空响应视为可重试错误（EMPTY_RESPONSE）
- **ACE 借鉴价值**：高
- **大致实现成本**：小-中

### D4. LlmFailure 归一化 + 规范化错误码
- **源码位置**：`packages/llm/llm/src/types.ts`（LlmFailure：message+code+status+providerRetryAfterMs+requestId——序列化、provider 中立）；`docs/subsystems/llm-streaming.md:236`（CONTEXT_WINDOW_EXCEEDED 唯一规范码，消费方按码路由而非按文本）
- **解决什么问题**：所有失败归一为一个可序列化 payload；策略决定是否可重试
- **ACE 借鉴价值**：高
- **大致实现成本**：小

### D5. StreamChunk 流式协议 + BlockAssembler + 原始 chunk 入日志
- **源码位置**：`packages/llm/llm/src/types.ts:312-324`（StreamChunk 闭式联合：block-start/text-delta/reasoning-delta/tool-call-delta/block-end/usage/finish，index 关联交错块；usage 必须出现在 finish 前）、`:116-125`（FinishReasonMap：stop/tool-calls/max-tokens/aborted/error）；`packages/llm/llm/src/assembler.ts`（BlockAssembler：增量折叠+interruptedBlocks() 安全终稿中断前缀+max-tokens 时丢弃未完成 tool call）；`packages/core/agent-loop/src/agent.ts:348-352`（原始 chunk 逐条入日志保真，重放可逐 token 重建）、`:354-371`（中断时落 interrupted:true 部分消息，保留已产出的 text/reasoning，丢弃 tool-call）、`:400-409`（assistant/message 用 sourceEventSeqs 引用 chunk 事件）
- **解决什么问题**：流式协议与组装器共享一套实现；中断/截断有安全终稿；日志保真重放
- **ACE 借鉴价值**：中（NDJSON IPC 可对齐：增量块+终块事件+usage 纪律）
- **大致实现成本**：中

### D6. 工具超时守卫：TOOL_TIMEOUT 结构化错误
- **源码位置**：`packages/guard/timeout-policy/src/index.ts:25`（TOOL_TIMEOUT 兼作 deadline 分类码与结果错误码）、`:41-48`（toolTimeoutResult：替换为 isError 结构化结果）、`:55-80`（tools/execute 包装：deadline 换入 exec.signal，派发后恢复上游信号，仅当自己的计时器触发才替换结果——用 code 区分嵌套外层 deadline 防误判）
- **解决什么问题**：工具声明的 timeoutMs 被可靠映射为可路由/可重放的结构化错误；超时=替换结果而非抛异常中断
- **ACE 借鉴价值**：中
- **大致实现成本**：小

### D7. 重复工具调用提醒（repeat-tool-reminder）
- **源码位置**：`packages/guard/repeat-tool-reminder/src/index.ts:103-105`（canonicalize：深层 key 排序后 stringify）、`:189-207`（post-execute 计数——被 pre-execute 拒绝的调用同样计数，因为"锤被拒调用"正是要打断的循环）、`:209-224`（只注入提醒上下文，绝不 veto）、`:229-232`（agent/pre-step 出现用户消息即重置该 agent 链；WeakMap 按 agent 分键）；阈值可配 [3,5,8] 分级（gentle→detailed）
- **解决什么问题**：防模型死循环重试同一调用；只提醒不否决
- **ACE 借鉴价值**：中高（网关层低成本高收益）
- **大致实现成本**：小

### D8. 正交结果报告（timedOut/aborted/signal/exitCode 各自独立）
- **源码位置**：`packages/shell/shell/src/types.ts:111-136`（ShellRunResult 四个正交字段）；`docs/defensive-patterns.md`（"Report orthogonal outcomes independently"——进程可以同时超时 AND exit 0（捕获了信号），绝不把一个标志的报道嵌套在另一个分支里）
- **解决什么问题**：调用方不会把截断的运行读成干净成功
- **ACE 借鉴价值**：中
- **大致实现成本**：小

### D9. 事件模式语义：emit / waterfall / parallel / serial
- **源码位置**：`docs/event-producer-consumer.md`（全事件矩阵：谁派发、谁监听、什么模式）；waterfall 监听器必须调 next() 否则短路（`docs/cordis-primer.md`）；`packages/core/session/src/index.ts:85`（session/flush parallel：每个监听器都跑且都 await，无 veto）
- **解决什么问题**：四类事件语义覆盖全部协作场景——fire-and-forget 通知、可 veto 的决策链、并行屏障、串行检查点；监听器异常被包含（一个坏订阅者不破坏核心生命周期，`docs/defensive-patterns.md`）
- **ACE 借鉴价值**：中
- **大致实现成本**：中

### D10. 运行时不变量 companion（每包 invariant）
- **源码位置**：仓库约定（`packages/AGENTS.md`：每个包拥有 ./invariant，断言拥有关系而非服务/方法存在性）；例：`packages/compaction/compaction/src/invariant.ts:155-215`（compaction/start/summary/end 关系校验）、`packages/todo/tool-todo/src/invariant.ts:25-44`（todo 内容非空/唯一/状态合法）、`packages/goal/goal-round-driver/src/invariant.ts:33-56`（轮次可从日志重建）、`packages/llm/llm-retry/src/invariant.ts:44-124`（llm/retry 事件必须落在 open turn/step 内、retryId 链一致、计数连续）、`packages/llm/llm/src/invariant.ts:36-84`（validateStream：delta 必须对应 open block、block-end 类型匹配、usage 仅一次、finish 后无 chunk）
- **解决什么问题**：关键关系在提交点由权威事件流校验，坏事件在源头拒绝而非静默腐坏；流协议违规在消费点即时暴露
- **ACE 借鉴价值**：中
- **大致实现成本**：中

### D11. 工具调用调度：barrier + 有界并行池 + 模型序提交
- **源码位置**：`packages/core/agent-loop/src/tool-calls.ts:82-101`（executionMode 分组：独占调用成 barrier，可并行调用成组）、`:121-246`（runGroup：maxParallelToolCalls 有界滚动池、commitReady 只按模型序连续提交、abort 排水）、`:104-110`（parseArguments：坏 JSON 保留原文、空串→{}）、`:249-259`（appendSkippedToolCall：取消时未启动调用补合成错误结果 TOOL_ABORTED_BEFORE_DISPATCH，保证重放有效）
- **解决什么问题**：独占/并行语义明确、并发有上限、结果严格按模型顺序落盘、abort 不产生悬空调用
- **ACE 借鉴价值**：高（NDJSON IPC 已有多工具，缺"有界并行池+模型序提交+取消补结果"的正确性骨架）
- **大致实现成本**：中

### D12. 失败分类系统：稳定 code + cause 链 + UNKNOWN 兜底
- **源码位置**：`packages/llm/llm/src/error.ts:13-22`（HarnessError 带稳定机器可路由 code）、`:114-154`（errorChain 渲染完整 cause 链供诊断）、`:161-162`（isHarnessError）；`packages/core/agent-loop/src/agent.ts:302-315`（turnEnds 分类：LlmError 保留 failure 事实，其它一律扁平为 errorChain 文本+UNKNOWN code）
- **解决什么问题**：机器按 code 路由而非解析 message 文本；跨进程/重放保留失败类别；未知错误有确定兜底不崩循环
- **ACE 借鉴价值**：高（给 Python 侧所有异常加稳定 code 字段+归一化函数，是重试/守卫/UI 分类的地基）
- **大致实现成本**：小

### D13. 互斥 TokenUsage 计量 + token-meter 两级定价
- **源码位置**：`packages/llm/llm/src/types.ts:135-141`（inputTokens 为未缓存输入，cacheRead/cacheWrite 单列，计费=三者之和，reasoningTokens 含于 outputTokens）；`packages/llm/llm-deepseek/src/translate.ts:53-62`（mapUsage：DeepSeek prompt_tokens 含缓存命中，减回为互斥计数）；`packages/llm/token-meter/src/measure.ts`、`estimate.ts`、`usage-projection.ts`（baseline 二选一：最近成功调用 envelope 匹配且 total 不低于启发式 anchor 时复用实际 usage，否则纯函数启发式定价）
- **解决什么问题**：不同 provider 计数口径不一时计费/展示无歧义；请求压力/上下文定价不依赖每次真实调用
- **ACE 借鉴价值**：中
- **大致实现成本**：中

### D14. 客户端订阅 + lastSeq 基线回放
- **源码位置**：`packages/client/connection`（session/subscribed 带 lastSeq 基线重放 + 后续 session/event 帧流，断线按 lastSeq 补齐）；`docs/subsystems/jobs.md:253-275`（onJobsChanged 在可见集每次提交后触发，观察者重读而非累积增量）；`packages/session/session-projection/src/index.ts:81-87`（ProjectionChangeListener：unit 值变化即推送，带 seq 水位）；`docs/cookbook/adding-a-conversation-node.md`（同一业务 id 贯穿 start/update/result 事件族，客户端按 id 分组而非猜邻接）
- **解决什么问题**：单一权威事件流供 UI 增量消费，断线重连不丢事件；UI 只收"整值+水位"，不自己 fold 域事件
- **ACE 借鉴价值**：中（NDJSON IPC 之外补"订阅+序号基线回放"，或加投影推送帧）
- **大致实现成本**：中

### D15. postmortem 复盘文化
- **源码位置**：`docs/postmortem/README.md`（满足 subtle+systemic+costly-to-rediscover 才写；编号 0001-0004 kebab-case，含 Executive summary/Timeline/Root cause/Guardrails）；`0001`（教训：namespace 与 export default 互斥、可选服务用 ctx.get、至少一个测试走真实 Loader）；`0004`（进程归因需独立证据合取、未知致命行 fail-closed）
- **解决什么问题**：流程缺口复盘而非追责；教训固化为 guardrails 与测试防再犯
- **ACE 借鉴价值**：低（流程/文化）
- **大致实现成本**：小

### D16. 防御性模式七条铁律
- **源码位置**：`docs/defensive-patterns.md`（正交结果独立报告 / 公共契约两侧归一 / 异步状态≠同步状态 / dispose 必须到达 quiescence（先关监听器再 kill）/ 回调异常在派发器包含 / 不可信输出不给环境与可预测路径（scrub `*KEY*`/`*TOKEN*` 环境变量、temp 0700+随机名+'wx' 0o600 独占写）/ 链接形路径用 unlink 而非递归删除）
- **解决什么问题**：每一条都是真实上过的 bug 类；Python asyncio 下子进程超时上报与任务收尾最值得抄
- **ACE 借鉴价值**：中
- **大致实现成本**：小

---

## TOP 5 最值得借鉴项

**1. 事件溯源会话日志 + surface 投影 + 「模型可见⟺可记录」**（B1/B2/B3，成本大）
ACE 现有"上下文压缩+Guardian 快照回滚"是破坏性/点状的；DSH 的日志是唯一事实源，历史永远从日志派生、压缩是带 shadowedSeqs 溯源链的无损 replace、任何时刻可重放重建。这是把 ACE 的记忆/回滚/审计统一起来的根基，可分期落地（先加 append-only 事件流+每次请求头/工具参数入日志，再做 surface 投影）。

**2. 沙箱 per-call 化 + enforcement 完整性报告 + stderr 双正交分类**（A1-A6，成本中）
直接叠加在 ACE 的 Go 执行器/docker 上：三态模式随每次调用显式携带、解析优先级（显式授权>会话>默认）、full/partial 诚实上报、多后端探测链 fail-closed、以及最重要的——把"策略拒绝（denial 方言）"与"执行器/runner 故障"分开分类，模型不会把沙箱坏了误当命令失败反复重试。

**3. 细粒度审批流：闭式 outcome + 会话级 ask/never + 严格加宽一次性授权**（A7-A10，成本中）
ACE 有"工具按权限裁剪"但没有审批。这套最小可用形态：只有 allowed-once 放行其余全 fail-closed、'never' 在服务内强制执行（监听器注册顺序不可绕过）、audit 配对可回放、被拒后可"同回合一次加宽重试"（必须先过审批、必须严格加宽、justification 配对）。

**4. compaction 三事件锁 + tool-result 确定性裁剪 + 影子价格事件**（B4/B8，成本小-中）
ACE 已有上下文压缩，缺的是：以持久化事件形式存在的锁（崩溃即孤儿锁可检测）、tool-result 的确定性头尾裁剪（同输入必同输出、可重放验证、无模型调用）、以及"裁剪代价"作为相邻日志事件（纯消费者无需逐节点状态即可做 token 记账）。

**5. goal 持久状态机 + 轮次驱动 + blocked 三轮判定**（C7-C9，成本中）
对单代理编码 agent 提升长任务可靠性最直接：目标持久化（revision CAS 防旧状态覆盖新状态）、空闲自动续跑下一轮、同一阻塞条件持续 3 轮才可自报 blocked（须给机器 code+人类 message）、重启后自动 disarmed 须人类 resume。todo_write 全量替换（C10，成本小）可同步顺手加上。

（备选第 5：continuable 子代理体系 C4/C5——体系性最强但成本大，建议在 goal 之后做。）

---

## 实现优先级建议

1. **先小成本高收益**：D12 错误码归一化、D10 流语法校验、B4/B8 压缩锁与确定性裁剪、D3 持久化重试、A6 拒绝方言表、D7 重复调用提醒、D6 工具超时
2. **再中成本体系**：A1-A5 沙箱 per-call、A7-A10 审批流、B1-B3 事件溯源日志、C7-C9 goal、C10 todo、C11 jobs
3. **最后大成本**：C4-C5 continuable 子代理体系、A14 Windows ACL 原生沙箱、B7 token 计量自动压缩

## 已核实的负向结论（避免走弯路）

- `docs/subsystems/guard.md` 不存在（guard 机制只在 `packages/guard/*` 源码与 AGENTS.md 中）
- `DENIED_BY_PERMISSION` 常量、工具参数裁剪/截断、"工具错误可重试分类"在 DSH 中均不存在（已 grep 核实），ACE 无需对照实现

## 调研方法与局限

- 信息来源：docs/subsystems/* 设计文档（英文版）+ 关键包源码直读（行号经 read/grep 核实）；4 个并行子代理分域深挖后并入本清单
- 未覆盖：apps/web 前端 React 细节、native/ Rust 源码、vendor/ Cordis 框架内部（事件模式语义仅在文档层面引用）、lsp/mcp/terminal 等与 ACE 相关性低的子系统
- 成本评估为相对 ACE 现有架构（Python + NDJSON IPC + Go 执行器）的粗略量级

---
> **来源与许可**：调研对象为 DeepSeek Harness（本地克隆 `deepseek-harness/`，仅作只读参考）；
> 公开设计解析入口见仓库根 README「设计参考」。本文件是 ACE 内部设计笔记，不含上游代码。