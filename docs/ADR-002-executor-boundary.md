# ADR-002：执行器进程边界、IPC 协议契约与 Windows 沙箱选型

- **状态**：Accepted，阶段 1–4 已落地（含流式增量输出与宿主侧聚合），阶段 5 的 Tier-2（Docker）未实现。详见文末「实施后记」。
- **日期**：2026-08-22（原始决策）／2026-08-22（实施后记）
- **决策范围**：`terminal_exec` / `code_execute` 的执行边界、宿主与执行器之间的 IPC 契约、审批与沙箱的职责切分
- **编号说明**：`docs/ADR.md:11` 已存在一条内联条目「ADR-002：为什么诱饵验证频率默认 0」。本文件是**独立编号序列**（`docs/ADR-NNN-*.md`）中的 002，与 `docs/ADR.md` 内的内联序列不共享编号空间。建议后续把内联条目迁成独立文件以消除歧义，本 ADR 不做此改动。

---

## Context

### 现状：三条执行路径，三种完全不同的安全等级

ACE 的工具执行统一经 `tools/base.py:134` 的 `execute()` 分发，权限裁决在 `execution_layer.py:553`，写操作前后由 guardian 做快照/回滚（`execution_layer.py:571`、`execution_layer.py:850`）。但真正落到 OS 的三条路径强度差异极大：

1. **`terminal_view`（只读）**：`tools/file_tools.py:230` 用 `subprocess.run(parts, ..., shell=False)`，前置 argv 白名单校验（`tools/file_tools.py:216-227`，白名单常量来自 `tools/base.py`，在 `tools/file_tools.py:13-15` 导入）。这是三条中最健康的一条。

2. **`code_execute`**：`tools/code_tools.py:127` 用 `subprocess.run([sys.executable, tmp_file], shell=False, cwd=sandbox_dir, env=minimal_env)`，叠加了 AST 黑名单（`tools/code_tools.py:21-36` 的 `DANGEROUS_CALLS/MODULES/FUNCS/NAMES/ATTRS`，扫描入口 `tools/code_tools.py:94-97`）、最小环境变量（`tools/code_tools.py:115-125`）、独立临时目录（`tools/code_tools.py:101-104`）、30 秒超时（`tools/code_tools.py:129`、超时映射见 `tools/code_tools.py:139-140`）、执行后清理（`tools/code_tools.py:149-152`）。执行层还额外套了诱饵 + AST 闸门（`execution_layer.py:563-569`、`execution_layer.py:858`）。

3. **`terminal_exec`（本 ADR 的核心风险点）**：`tools/file_tools.py:274` 是 `subprocess.run(cmd, shell=True, ...)`，直接把模型生成的字符串交给 `cmd.exe`。它与 `code_execute` 的不对称有三处，且每一处都是单向劣化：
   - **无 argv 白名单**：`terminal_view` 有（`tools/file_tools.py:216-227`），`terminal_exec` 没有。唯一的前置检查是长度（`tools/file_tools.py:248`）与一个 `mkdir` 内建旁路（`tools/file_tools.py:252-266`）。
   - **无环境变量清洗**：`code_execute` 剥离到 9 个变量（`tools/code_tools.py:115-125`），`terminal_exec` 完整继承宿主环境，包括所有 API Key 与代理配置。
   - **`shell=True`**：任何 `&&`、`|`、`>`、`%VAR%`、`^` 转义都由 shell 解释，字符串级的黑名单在这一层没有可靠语义。

   `tools/file_tools.py:268-270` 还对命令做了 `~/Desktop` → 绝对路径的字符串替换，这意味着命令文本在进入 shell 前被改写过——审计日志里记录的 `command` 字段（`tools/file_tools.py:281`）是改写后的值，与模型原始意图不完全一致。

`math_calc` 曾在用 `eval`（当时的 `tools/code_tools.py:162`），虽然前置了白名单 AST 校验，风险等级远低于上述三条，但它是同一类"在解释器内执行不可信输入"的模式，本 ADR 一并归入迁移范围末尾。**该项已完成**（见"阶段 5"）：现在由自实现的 `eval_math_ast()` 求值，`tools/` 内不再出现 `eval` 调用，因此这条不再依赖执行器进程边界。

### 结构性问题：安全边界与业务逻辑同处一个进程

当前所有防御（AST 扫描、诱饵、白名单、guard 输出检测 `execution_layer.py:584-598`）都运行在与 ACE 主逻辑**同一个 Python 进程**里。这带来三个架构层面的后果：

- **共享地址空间**：`code_execute` 的 AST 黑名单是**静态**防御。一旦被绕过（`getattr` 拼接、`__builtins__` 重获取路径未被 `DANGEROUS_ATTRS` 覆盖等），逃逸出来的代码虽然跑在子进程里，但 `terminal_exec` 的 `shell=True` 路径给了它一个不需要绕过任何 AST 的等价通道。
- **没有资源边界**：30 秒超时是**唯一**的资源限制。内存、子进程数、句柄、磁盘写入量都不受限；`subprocess.TimeoutExpired` 只杀直接子进程，`shell=True` 下 `cmd.exe` 派生的孙进程会成为孤儿继续运行。
- **无法换实现**：安全逻辑与 Python 的 `subprocess`、`ast` 模块深度绑定。想引入 OS 级隔离原语（受限令牌、seccomp、Job Object）就必须在同一个进程里写 ctypes，而想换成 Rust 实现则要重写全部调用点。

### 环境与设计约束（已核实，不再复议）

- 宿主 Windows 11 + PowerShell 5.1；Python 3.13.14；**Go 1.26.5 可用**（`D:\学习\go\go\bin\go.exe`，不在 PATH 上，需显式绝对路径调用）。本机无 rustc/cargo，且 `go test -race` 不可用（缺 C 编译器，`-race requires cgo`），Go 测试一律在 `CGO_ENABLED=0` 下跑、不带竞态检测。
  - 这一条曾写作"本机无 rustc/cargo/go"，是错的：只看 PATH 就下了结论。执行器最终用 Go 实现（`executor/`），而不是本 ADR 原先预期的"Python 执行器，将来可能换 Rust"。
- 零第三方依赖是项目原则（`docs/ADR.md:25-29` 的 ADR-004）：核心只用 stdlib，`requests`/`prompt_toolkit` 可选懒加载。
- 已有 `Dockerfile:1-11`（`python:3.12-slim` + `requests`）与 `docker-compose.yml:1-6`（ACE + Ollama）。注意：现有容器化的语义是**把整个 ACE 放进容器**（`CMD ["python", "ai_code.py", "--mock"]`，`Dockerfile:11`），不是"ACE 在宿主、执行器在容器"——后者是本 ADR 讨论的另一件事。
- `test_all.py` 1121 行纯 stdlib 自写断言，统一入口 `run_agent()`（`test_all.py:59`）与 `check()`（`test_all.py:50`）；`guardian.py` 提供 `snapshot`（`guardian.py:79`）/`verify_snapshot`（`guardian.py:128`）/`rollback`（`guardian.py:162`）/`prune`（`guardian.py:218`）。

### 参考实现的事实（本地副本，已核对）

- codex 把审批与沙箱做成**两个正交枚举**：`AskForApproval`（`_reference/codex/codex-rs/protocol/src/protocol.rs:924`，变体 `UnlessTrusted`/`OnRequest`/`Granular`/`Never`）与 `SandboxPolicy`（`protocol.rs:1010`，变体 `DangerFullAccess`/`ReadOnly`/`ExternalSandbox`/`WorkspaceWrite`）。值得注意：`on-failure` 现已退化为 `OnRequest` 的 serde alias（`protocol.rs:932`），说明这个枚举在真实演进中是**收敛**的。
- 沙箱后端是**运行时枚举**而非编译期选型：`SandboxType { None, MacosSeatbelt, LinuxSeccomp, ... }`（`_reference/codex/codex-rs/sandboxing/src/manager.rs:37`）。
- 命令安全性判定被抽成**独立 crate**：`execpolicy`，规则是数据（`prefix_rule(pattern, decision, justification, match, not_match)`），决策是三值 `allow`/`prompt`/`forbidden`，冲突时取最严（`_reference/codex/codex-rs/execpolicy/README.md:5-10`、`README.md:95`），输出是 JSON（`README.md:76-90`）。
- 执行器是**独立进程 + JSON-RPC over stdio**：`JSONRPCMessage`（`_reference/codex/codex-rs/exec-server-protocol/src/rpc.rs:54`）、`InitializeParams`（`exec-server-protocol/src/protocol.rs:76`）、`ExecParams`（`protocol.rs:221`）、`ExecResponse`（`protocol.rs:280`）、`SignalParams`（`protocol.rs:360`）、`TerminateParams`（`protocol.rs:371`）、`ExecOutputStream{Stdout,Stderr}`（`protocol.rs:778-780`）、`ExecOutputDeltaNotification`（`protocol.rs:786`）、`ExecExitedNotification`（`protocol.rs:795`）。字节数据用 base64 包装（`ByteChunk`，`protocol.rs:60`）。
- **Windows 强隔离需要一次性管理员安装**：codex 的 Windows 路径基于 `CreateRestrictedToken`（`_reference/codex/codex-rs/windows-sandbox-rs/src/token.rs:481`）+ 路径 ACL + WFP 网络过滤（`windows-sandbox-rs/src/wfp.rs:77` 注明"intended to run from the already-elevated setup helper"）+ 独立沙箱用户账户（`windows-sandbox-rs/src/bin/setup_main/win/sandbox_users.rs`、`firewall.rs`），并区分 `WindowsSandboxLevel::Elevated` 与非提权后端，托管网络能力**只在提权后端可用**（`windows-sandbox-rs/src/unified_exec/mod.rs:75-78`）。在本地副本中**未检索到 AppContainer 的使用**。

---

## Decision Drivers

1. **消除 `shell=True`**（`tools/file_tools.py:274`）是本 ADR 的首要目标，其余都是为了让这件事做得彻底且不可回退。
2. **零第三方依赖不可破**（`docs/ADR.md:25-29`）：所有必需路径只能用 stdlib（含 `ctypes`）；需要外部运行时的方案只能是**可选档位**。
3. **实现语言可替换**：契约必须语言无关，替换实现时宿主侧零改动。（实施结果：执行器直接用 Go 写成，跳过了"先 Python 再换掉"的中间态；这条驱动力因此从"将来可能"变成了"当下就是"。）
4. **既有测试与 guardian 不能被破坏**：`test_all.py` 全部断言（除下文明确点名的一条）与 `guardian.py` 的快照/回滚语义必须保持。
5. **可分阶段、每阶段可独立验证与回滚**：不接受"大爆炸式"重写。
6. **诚实的隔离声明**：每个档位必须写清"防住什么、防不住什么"。声称的隔离强度高于实际，比没有隔离更危险。

---

## Considered Options

### 决策一：执行边界的位置

- **A1 进程内加固**（继续在 ACE 进程里做 argv 白名单 + env 清洗，不引入新进程）
- **A2 独立执行器子进程 + NDJSON over stdin/stdout**（采纳）
- **A3 本地 TCP/命名管道 RPC 服务**
- **A4 直接引入 MCP / JSON-RPC 完整实现**

### 决策二：Windows 沙箱原语

见下文「决策二」的逐项隔离边界分析（a–e）。

### 决策三：审批与沙箱的职责切分

- **C1 单一 `permission_level` 继续承载全部语义**（现状，`execution_layer.py:290-296`）
- **C2 双正交枚举 ApprovalPolicy × SandboxPolicy + 独立 execpolicy 模块**（采纳）

---

## Decision

### 决策一：把危险工具委派给独立执行器子进程，契约为 NDJSON over stdin/stdout

**采纳 A2。**

宿主侧新增 `executor_client.py`（NDJSON 客户端），执行器侧新增 `executor/`（子进程入口 `python -m executor`）。`ExecutionLayer` 通过配置 `executor.mode = inproc | subprocess` 选路，`terminal_exec` 与 `code_execute` 是首批迁移的两个工具。

> **实施后更正（与 `exec_protocol.py` 那条同类）**：宿主侧客户端最终落在 `ace_executor.py`（`ExecutorClient`），没有 `executor_client.py`；`executor/` 是 **Go 模块**（`go.mod` + `main.go` / `protocol.go` / `run.go` / `sandbox*.go`），不是 Python 包，`python -m executor` 跑不起来。选路开关也不叫 `executor.mode` —— 实际是 `config["use_go_executor"]` 加环境变量 `ACE_USE_GO_EXECUTOR`，三态优先级为「显式参数 > 环境变量 > 默认开」。下文凡出现 `executor.mode` 的地方按这一条读。

**为什么不是 A1**：进程内加固能解决 `shell=True`，但解决不了资源边界与进程树回收——没有独立进程就没有可以整体 kill 的对象，也没有可以整体替换成 Rust 二进制的对象。做完 A1 之后仍然要做 A2，而 A1 的代码会成为需要二次迁移的中间态。

**为什么不是 A3**：TCP 引入端口占用、绑定地址与本机其他进程可连接的攻击面（必须再做认证）；命名管道在 Windows 与 POSIX 上的 API 与权限模型不一致，跨平台成本高于 stdio。stdio 的父子关系天然是最小权限：管道句柄只有父子两端持有，进程死亡即连接终止，无需额外认证层。

**为什么不是 A4**：MCP/JSON-RPC 的完整实现（批量请求、双向请求、通知路由、错误对象规范）远超本场景所需，且 stdlib 里没有现成实现，自己写等于把 A2 的成本乘以二。本协议**借用** JSON-RPC 的 `id` 相关性与 `method` 分发思想（对齐 `exec-server-protocol/src/rpc.rs:54`），但不声称兼容 JSON-RPC 2.0，避免"看起来兼容实际不兼容"的更坏结果。

**换成备选的代价**：选 A1 省下约一半的初期工作量，但把"资源限制"和"实现语言可替换"两个目标永久搁置，且未来迁移时所有加固代码要重写一遍。选 A3 增加认证层与端口管理，换来的唯一好处（执行器可跨机器）在当前需求里不存在。选 A4 把协议成本从"一个文件"放大到"一个子系统"，且仍需自己实现传输层。

---

### 协议契约 v1（语言无关）

#### 传输与分帧

- **通道**：执行器进程的 stdin（宿主 → 执行器）与 stdout（执行器 → 宿主）。执行器**自身**的 stderr 是诊断日志，**不属于协议**，宿主可采集但不得解析为消息。
- **编码**：UTF-8，每行一个 JSON 对象，以 `\n` 结束（NDJSON）。JSON 内部不得出现裸换行（必须转义）。
- **行长上限**：1 MiB。任何超限的载荷必须由发送方切块（见 `output` 事件的 `seq`）。
- **stdout 纯净性硬约束**：执行器的 stdout **只能**出现协议行。这对 Python 实现是真实风险——一次 `print()` 调试就会污染协议流。实现要求：进程启动时立即 `os.dup()` 保留协议 fd，然后把 `sys.stdout` 重定向到 stderr；子进程的输出**只经 `output` 事件转发，绝不直通**。
- **单位与表示约定**（为 Rust 实现消除歧义）：所有时长以毫秒整数表示，字段名以 `_ms` 结尾；所有路径为绝对路径字符串；所有字节数据以 base64 编码（对齐 `exec-server-protocol/src/protocol.rs:60` 的 `ByteChunk`），不传递已解码文本，解码是宿主的职责。

#### 消息信封

三种 `type`：

- `req`（宿主 → 执行器）：`{"v", "type":"req", "id", "method", "params"}`
- `resp`（执行器 → 宿主）：`{"v", "type":"resp", "id", "result"}` 或 `{"v", "type":"resp", "id", "error"}`
- `event`（执行器 → 宿主）：`{"v", "type":"event", "id", "event", "seq", "data"}`

不变量（Rust 实现必须满足同样的不变量）：

- 每个 `req.id` **恰好**对应一个 `resp`。`resp` 是该 `id` 的终态，其后不得再出现该 `id` 的任何 `event`。
- 同一 `id` 的 `event.seq` 从 0 单调递增，无空洞。宿主据此检测丢帧。
- `id` 由宿主生成，会话内唯一（推荐 `uuid4().hex`）。
- **未知字段必须忽略**（前向兼容）；未知 `method` 或未知 `type` 返回错误但**不终止会话**。

#### 方法集

| 方法 | 语义 |
| --- | --- |
| `initialize` | 版本与能力协商。必须是会话首条 `req`，其他方法在此之前一律返回 `E_NOT_INITIALIZED` |
| `exec.command` | 执行外部命令（`terminal_exec` 的替代） |
| `exec.python` | 执行 Python 源码（`code_execute` 的替代） |
| `cancel` | 取消一个进行中的 `id` |
| `shutdown` | 优雅关闭：拒绝新请求，等待在途请求终结，然后退出 |

（上表是方法清单而非配置矩阵，故保留表格形式。）

#### 版本协商

`v` 字段是**主版本号整数**。主版本变更 = 破坏性变更。次要能力通过 `initialize` 的 `features` 字符串数组协商（如 `"exec.python"`、`"stream.stdout"`、`"sandbox.job_object"`、`"cancel.graceful"`）。宿主发送 `protocol_versions: [1]`，执行器在支持集合中选最高者回传 `protocol_version`；无交集则回 `E_PROTOCOL_VERSION` 并退出。协商完成后所有消息的 `v` 必须等于协商结果，不符者按 `E_MALFORMED_MESSAGE` 处理。

#### 错误码

字符串枚举（稳定标识），同时携带 `http_like` 字段以便映射到现有 `ExecutionResult.error_code`（`tools/result.py:14`），保证工具层返回形状不变：

- `E_NOT_INITIALIZED` → 400
- `E_MALFORMED_MESSAGE` → 400
- `E_UNKNOWN_METHOD` → 400
- `E_INVALID_PARAMS` → 400
- `E_PROTOCOL_VERSION` → 500
- `E_POLICY_DENIED` → 403（execpolicy 判定为 `forbidden`，或 argv 未命中白名单）
- `E_APPROVAL_REQUIRED` → 403（判定为 `prompt` 且请求未携带有效审批凭据）
- `E_SANDBOX_UNAVAILABLE` → 501（请求的沙箱档位在本机不可用）
- `E_SANDBOX_VIOLATION` → 403（子进程被沙箱阻断）
- `E_SPAWN_FAILED` → 500
- `E_TIMEOUT` → 504
- `E_CANCELED` → 499
- `E_INTERNAL` → 500
- `E_EXECUTOR_CRASHED` → 500（**由宿主合成**，非执行器发出：管道断裂、进程死亡、看门狗超时）

输出被截断**不是错误**，而是 `result.truncated: true` 标记，`exit_code` 照常返回。

#### 超时与取消语义

- `timeout_ms` 由宿主在 `params` 中传入，**执行器是计时的唯一真相源**。
- 宿主额外维护看门狗：`timeout_ms + grace_ms`（默认 grace 2000ms）内未收到 `resp` → 视为执行器失联 → kill 执行器进程树 → 合成 `E_EXECUTOR_CRASHED`，并重启执行器。这条兜底是必需的：如果只信任执行器计时，执行器自身挂死就没人兜底。
- `cancel` 的双 `resp` 语义（容易实现错，明确写下）：
  1. `cancel` 请求自身得到一个 `resp`，`result` 为 `{"accepted": true|false, "target_id", "reason"?}`。目标已终结时 `accepted: false, reason: "already_finished"`。重复取消同一 `id` 幂等，第二次 `accepted: false`。
  2. **被取消的原请求**得到它自己的 `resp`，`error.code = "E_CANCELED"`，并携带已产出的部分输出统计。
- 终止顺序：`mode: "graceful"` 时先向子进程树发送终止信号（POSIX：向进程组发 `SIGTERM`，`grace_ms` 后 `SIGKILL`；Windows：优先 `TerminateJobObject`，无 Job 时退化为 `taskkill /T /F`），`mode: "kill"` 时跳过 grace 直接强杀。
- 超时的处理路径与 `cancel` **完全相同**，只是触发者是执行器自己的计时器，最终 `error.code = "E_TIMEOUT"`。这样"超时"和"取消"共用一条终止代码路径，减少一类只在超时才出现的资源泄漏 bug。

#### JSON 示例

**请求 1：initialize**

```json
{"v":1,"type":"req","id":"a1b2c3","method":"initialize","params":{"client":{"name":"ace","version":"7.0"},"protocol_versions":[1],"features_requested":["exec.command","exec.python","stream.stdout","cancel.graceful"],"host":{"os":"windows","os_version":"11","cwd":"C:\\Users\\69215\\Desktop\\AI_Project\\ai angent"}}}
```

**响应 1：initialize 结果（声明本机可用沙箱档位）**

```json
{"v":1,"type":"resp","id":"a1b2c3","result":{"server":{"name":"ace-executor","version":"0.1.0","language":"go","language_version":"go1.26.5"},"protocol_version":1,"features":["exec.command","exec.python","stream.stdout","cancel.graceful","sandbox.job_object"],"sandbox":{"available":["tier0_process","tier1_job_object"],"unavailable":{"tier2_docker":"docker CLI not found on PATH"}},"limits":{"max_line_bytes":1048576,"max_chunk_bytes":65536,"max_output_bytes":5242880,"max_timeout_ms":600000}}}
```

**请求 2：exec.command（无 shell，argv 数组 + 显式 env 策略 + 沙箱档位）**

```json
{"v":1,"type":"req","id":"d4e5f6","method":"exec.command","params":{"argv":["git","status","--porcelain"],"cwd":"C:\\Users\\69215\\Desktop\\AI_Project\\ai angent","timeout_ms":30000,"stdin":null,"stream":true,"env_policy":{"mode":"allowlist","allow":["PATH","SystemRoot","WINDIR","COMSPEC","TEMP","TMP","PYTHONIOENCODING"],"set":{"PYTHONDONTWRITEBYTECODE":"1"}},"sandbox":{"tier":"tier1_job_object","allow_weaker_tier":false},"limits":{"max_output_bytes":1048576,"max_memory_bytes":536870912,"max_child_processes":32},"policy_decision":{"decision":"allow","rule_id":"git-readonly","evaluated_by":"host"},"approval":null}}
```

原始设计里这个 `sandbox` 块还带 `policy:"workspace_write"`、`writable_roots`、`network_access:false`、`scratch_dir`。**实现后这四个字段一旦出现就报 `E_SANDBOX_UNAVAILABLE`**，因为 Tier-0/Tier-1 都不提供文件系统与网络边界（Job Object 限的是资源与进程树，受限令牌刻意不加 restricting SID），它们要等 Tier-2。这里的判断是：静默忽略这类字段比不实现它们更危险 —— 调用方写下 `network_access:false` 之后会以为子进程断了网，然后在这个前提上做别的放行决定。`network_access` 因此在 Go 侧是 `*bool` 而不是 `bool`：值类型的零值就是 `false`，会把"没传"和"显式要求断网"判成同一件事，于是每个不关心网络的请求都会被拒。


**事件流（同一 id 的增量输出，base64 原始字节）**

```json
{"v":1,"type":"event","id":"d4e5f6","event":"started","seq":0,"data":{"pid":24188,"sandbox_applied":{"tier":"tier1_job_object","job_object":true,"restricted_token":false,"integrity_level":"medium (S-1-16-8192)","restricted_token_reason":"受限令牌下进程无法启动，已放弃令牌重试（Job Object 边界仍生效）: fork/exec ...python.exe: The file cannot be accessed by the system."}}}
{"v":1,"type":"event","id":"d4e5f6","event":"output","seq":1,"data":{"stream":"stdout","offset":0,"data_b64":"IE0gdG9vbHMvZmlsZV90b29scy5weQo="}}
{"v":1,"type":"event","id":"d4e5f6","event":"output","seq":2,"data":{"stream":"stdout","offset":28,"data_b64":"","capped":true}}
```

`offset` 是该 stream 内本帧首字节的字节偏移，宿主用它检测丢帧（与 `seq` 互补：`seq` 覆盖全部帧的全局顺序，`offset` 覆盖单条流的连续性）。截断发生在推送之前，因此帧里的字节数总和恒等于最终 `bytes.stdout`；恰好越过 `max_output_bytes` 时额外发一帧 `"capped":true` 的标记帧（只发一次，`data_b64` 可为空）。`resp` 里的 `digest` 是同一份字节的 sha256，宿主拼装完后校验，不一致即 `E_TRANSPORT`——这条保证了"流式聚合"与"一次性返回"在字节层面等价，而不是看起来等价。


**响应 2：exec.command 正常终结**

```json
{"v":1,"type":"resp","id":"d4e5f6","result":{"exit_code":0,"signal":null,"duration_ms":412,"truncated":false,"bytes":{"stdout":28,"stderr":0},"captured_bytes":{"stdout":28,"stderr":0},"digest":{"stdout":"9f2c...","stderr":"e3b0..."},"sandbox_applied":{"tier":"tier1_job_object","job_object":true,"restricted_token":false,"integrity_level":"medium (S-1-16-8192)","restricted_token_reason":"受限令牌下进程无法启动，已放弃令牌重试（Job Object 边界仍生效）: ...","degraded":false}}}
```

注意 `degraded` 与 `restricted_token` 是**两件事**：前者表示"请求的资源/进程树边界没有全部生效"，后者表示"身份边界是否建立"。丢掉受限令牌时 Job Object 请求的限制一项没少，所以 `degraded` 仍为 `false`，原因写在专门的 `restricted_token_reason` 里。把两者混在一个 `degraded_reason` 中会让 SRE 的告警规则（`degraded == true` 即告警）在最常见的情形下天天误报。

`integrity_level` 是第三件事，也是**实测**而非配置回显：`restricted_token=true` 只说明令牌派生成功，不说明降到了哪一档。实测值是 `medium (S-1-16-8192)` —— LUA_TOKEN 给到的是 Medium，**不是 Low**，所以子进程仍然能写用户 profile 下的绝大多数位置。这也解释了为什么"待实测假设第 1 项"（Low IL 下 python/git/pip 还能不能干活）至今没被触发：当前实现根本没走到 Low。把等级如实报出来，是为了防止后来者从 `restricted_token=true` 推出一个比事实更强的结论，然后据此省掉别的防护。


**请求 3：exec.python（替代 code_execute）**

```json
{"v":1,"type":"req","id":"g7h8i9","method":"exec.python","params":{"source":"import time\nwhile True:\n    time.sleep(1)\n","filename":"snippet.py","cwd":null,"timeout_ms":30000,"stream":true,"env_policy":{"mode":"allowlist","allow":["PATH","SystemRoot","WINDIR","COMSPEC"],"set":{"PYTHONIOENCODING":"utf-8","PYTHONDONTWRITEBYTECODE":"1","PYTHONPATH":""}},"sandbox":{"tier":"tier1_job_object","allow_weaker_tier":false},"limits":{"max_output_bytes":1048576,"max_memory_bytes":268435456,"max_child_processes":1}}}
```

**响应 3：超时终结（注意 partial 统计与 kill 结果都在 error.data 里）**

```json
{"v":1,"type":"resp","id":"g7h8i9","error":{"code":"E_TIMEOUT","http_like":"504","message":"execution exceeded timeout_ms=30000","data":{"duration_ms":30014,"killed":true,"kill_method":"TerminateJobObject","orphans_remaining":0,"bytes":{"stdout":0,"stderr":0},"truncated":false}}}
```

**请求 4 与响应 4：cancel（双 resp 语义示例）**

```json
{"v":1,"type":"req","id":"j0k1l2","method":"cancel","params":{"target_id":"g7h8i9","mode":"graceful","grace_ms":2000}}
{"v":1,"type":"resp","id":"j0k1l2","result":{"accepted":true,"target_id":"g7h8i9"}}
{"v":1,"type":"resp","id":"g7h8i9","error":{"code":"E_CANCELED","http_like":"499","message":"canceled by host","data":{"duration_ms":1180,"killed":true,"kill_method":"TerminateJobObject","bytes":{"stdout":12,"stderr":0}}}}
```

**响应 5：策略拒绝（execpolicy `forbidden`，审批不可解除）**

```json
{"v":1,"type":"resp","id":"m3n4o5","error":{"code":"E_POLICY_DENIED","http_like":"403","message":"command matched a forbidden rule","data":{"rule_id":"no-recursive-force-delete","matched_prefix":["rm","-rf"],"decision":"forbidden","justification":"递归强删不可通过审批解除；请指定具体路径并使用 file_delete","approvable":false}}}
```

**响应 6：沙箱档位不可用（不静默降级）**

```json
{"v":1,"type":"resp","id":"p6q7r8","error":{"code":"E_SANDBOX_UNAVAILABLE","http_like":"501","message":"requested sandbox tier is not available","data":{"requested":"tier2_docker","available":["tier0_process","tier1_job_object"],"reason":"docker CLI not found on PATH","allow_weaker_tier":false}}}
```

---

### 决策二：Windows 沙箱原语选型

**采纳分档设计：Tier-0（纯进程级）恒定启用 + Tier-1（Job Object，Windows 默认）+ Tier-2（Docker，可选强隔离）。放弃 AppContainer 与 WSL2+bwrap。**

沙箱档位是**协议里的请求字段**、执行器在 `initialize` 中声明本机可用集合（对齐 `sandboxing/src/manager.rs:37` 的运行时枚举做法），而不是编译期选型。这样 Rust 执行器落地时可以直接新增 seccomp/seatbelt/受限令牌+WFP 档位，宿主代码零改动。

#### (a) Job Object + 受限令牌（ctypes）— 采纳为 Tier-1 默认

- **实际隔离边界**：进程级的**资源与身份**边界，不是文件系统边界。Job Object 通过 `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` 施加进程数、提交内存、用户态 CPU 时间上限，`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` 保证句柄关闭即整树回收，禁止 breakaway 保证子孙进程无法脱离。受限令牌（`CreateRestrictedToken` + `DISABLE_MAX_PRIVILEGE` + 限制 SID，参照 `windows-sandbox-rs/src/token.rs:481`）或降低完整性级别到 Low，收缩的是**写**权限与用户对象访问。
- **防住**：进程树逃逸与孤儿进程（当前 `shell=True` 下最现实的失控形态）、fork bomb、内存耗尽、无限运行、以 Medium 完整性写入需要更高 IL 的位置。
- **防不住**：文件系统**读取**——用户目录下的 `.ssh`、`.aws`、`.env`、浏览器数据在 Low IL 下大多仍可读；出站网络（Job Object 完全不涉及网络，WFP 过滤需要管理员，见 `windows-sandbox-rs/src/wfp.rs:77`）；注册表读取；写入那些 ACL 显式允许 Low IL 的位置；以及最重要的一条——**工作区内的破坏照旧生效**，这是设计上允许的，只能靠 guardian 回滚。
- **新工具链**：无（stdlib `ctypes`）。**管理员权限**：Job Object 与 `CreateRestrictedToken` 本身不需要；但 deny-ACL、独立沙箱用户、WFP 都需要。**跨平台一致性**：差，仅 Windows；Linux/macOS 需另写 `setsid` + `resource.setrlimit` 的等价档位。
- **成本**：中。ctypes 结构体布局（指针宽度、对齐）易错，且必须走 `CREATE_SUSPENDED` → `AssignProcessToJobObject` → `ResumeThread` 的正确顺序，否则子进程可能在入 Job 前就已派生孙进程。

#### (b) AppContainer — 不采纳

- **实际隔离边界**：内核强制的 capability 边界。文件系统**默认全部拒绝**，必须为每个需要访问的目录显式添加 AppContainer SID 的 ACE；网络需 `internetClient` capability，不授予则出站被内核直接阻断；命名对象进入独立命名空间。这是纯 Win32 方案里唯一能真正阻断**读**与**网络**的一档。
- **防住**：未授权目录的读与写、默认出站网络、大部分用户对象访问、命名对象污染。
- **防不住**：已显式授权目录内的破坏；CPU/内存耗尽（仍需叠加 Job Object）；以及一个实践问题——`python.exe` 要在 AppContainer 里运行，需要给 Python 安装目录与 stdlib 加 ACE，`pip`/`git`/`node` 各自还要一批，授权面会持续膨胀直到接近 Tier-1 的实际效果。
- **不采纳的理由**：ctypes 实现量是五个选项里最大的一档（`CreateAppContainerProfile` + `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES)` + `SetEntriesInAclW` 逐路径授权），而它能提供的"阻断读与网络"能力，Docker 档位用几乎零代码就能提供且跨平台一致。本地 codex 副本中未见 AppContainer 使用，其 Windows 强隔离走的是受限令牌 + ACL + WFP + 独立用户账户 + 一次性提权安装的组合——这一点强化了判断：**"不需要管理员的强 Windows 沙箱"这个东西很可能不存在**。
- **换成 (b) 的代价**：多出数百行高风险 ctypes 代码与一批"某工具在 AppContainer 里跑不起来"的长尾问题，换来的隔离强度仍低于 Tier-2，且完全无法复用到 Linux/macOS。

#### (c) Docker 容器 — 采纳为 Tier-2 可选档

- **实际隔离边界**：内核 namespace + cgroup；在 Windows 上是 Linux VM，因此边界是**不同的内核**。宿主文件系统仅通过显式挂载卷可见；`--network=none` 彻底断网；`--memory`/`--cpus`/`--pids-limit` 限资源；`--read-only` + `tmpfs` 限写。
- **防住**：宿主文件系统访问（未挂载即不可见——这是唯一能防住"读凭据文件"的档位）、出站网络、资源耗尽、宿主注册表与凭据存储。对"执行模型生成的任意命令"这个威胁模型，这是五个选项里最强的一档。
- **防不住**：挂载进去的工作区内的破坏（设计上允许）；Docker Desktop 未安装/未运行时**完全不可用**；若挂载 docker socket 则等价于宿主 root（因此绝对禁止）；容器内 Linux 语义 ≠ 宿主 Windows 语义——路径分隔符、行尾、可用命令都不同，因此"在桌面建个文件夹"这类**指向宿主的真实意图无法满足**。这条限制决定了 Tier-2 只能是可选档，不能是默认档。
- **新工具链**：需要 Docker Desktop（重量级、可选）。注意现有 `Dockerfile:1-11` 服务的是"整个 ACE 进容器"，Tier-2 需要的是一个**只含执行器**的最小镜像，两者不能复用同一个 Dockerfile 的 `CMD`（`Dockerfile:11`）。**管理员权限**：安装需要，日常运行不需要（docker-users 组）。**跨平台一致性**：最好。
- **成本**：中低——复用 `docker` CLI 加 stdio 转发，协议层零改动。新问题是容器生命周期与冷启动延迟。

#### (d) WSL2 + bwrap — 不采纳

- **实际隔离边界**：WSL2 的 VM 边界 + bwrap 的 namespace 边界，理论强度接近 (c)。
- **防住**：与 (c) 类似。
- **防不住**：宿主 Windows 文件系统默认通过 `/mnt/c` 可见（除非 bwrap 不绑定，那就等于 (c) 但更麻烦）；drvfs 跨界 I/O 性能极差；宿主 Windows 命令仍无法执行。
- **不采纳的理由**：在 Windows 宿主上这是两层间接（WSL2 + bwrap），得到的隔离不比 (c) 强，而依赖更多（WSL2 + 发行版 + bubblewrap + unprivileged userns 可用性需逐机验证），且 macOS 完全没有对应物。
- **换成 (d) 的代价**：多一层运行时与一套路径映射逻辑，跨平台一致性反而比 (c) 差。若未来要做 Linux 原生强隔离，正确的方向是 seccomp + landlock（参照 `_reference/codex/codex-rs/linux-sandbox/`），而不是 bwrap 套在 WSL2 里。

#### (e) 纯进程级限制 — 采纳为 Tier-0 基线，但必须诚实标注它不是隔离

- **实际隔离边界**：**没有 OS 强制边界**。子进程以当前用户的完整令牌运行，唯一的约束是我们自己写的检查。
- **防住**：非对抗性的意外破坏（路径打错、误删）；环境变量中的凭据泄漏（allowlist，照 `tools/code_tools.py:115-125` 的做法）；挂死（超时）；shell 元字符注入（禁 `shell=True`，只传 argv 数组）；不在白名单里的可执行文件。
- **防不住**：白名单内任一程序的滥用——只要 `python`、`git`、`curl` 中任何一个在名单里，就等价于全权（`python -c`、`git clone` 到任意路径、`curl | sh`）；绝对路径写宿主任意位置；出站网络；读取 `%USERPROFILE%` 下的凭据文件；TOCTOU；白名单绕过（8.3 短名、UNC 路径、符号链接、`cmd.exe /c` 变体）。**argv 白名单是策略，不是隔离**——它约束的是"模型说了什么"，不是"进程能做什么"。
- **成本**：最低，纯 stdlib，零依赖原则不受影响。

#### 分档决策与默认值

- **Tier-0 恒定启用**，与任何上层档位叠加。它是唯一在所有环境下都可用的一档，也是唯一能防住"环境变量泄漏凭据"的一档（Tier-1/Tier-2 都不自动做 env 清洗）。
- **Tier-1 为 Windows 默认**：不引入新工具链、不需要管理员、能真正回收进程树。
- **Tier-2 为可选强隔离档**：`docker` 可用且用户显式开启时生效。
- **不静默降级**：请求的档位不可用时返回 `E_SANDBOX_UNAVAILABLE`（示例见响应 6），除非请求显式带 `allow_weaker_tier: true`；即便降级也必须在 `result.sandbox_applied.degraded_reason` 中标注（示例见响应 2）。静默降级会让日志声称的隔离强度高于实际，这比没有隔离更危险。

---

### 决策三：审批与沙箱双闸门，命令安全性判定独立成模块

**采纳 C2。**

#### 两套正交枚举

**`ApprovalPolicy`（何时问人）**：

- `never`：不询问，失败直接回模型
- `on_request`：模型可主动请求审批（默认）
- `untrusted`：除 execpolicy 明确 `allow` 的命令外一律需审批
- `on_failure`：**作为 `on_request` 的别名接受，不作为独立档位实现**。理由：codex 已经把 `on-failure` 退化成 `OnRequest` 的 serde alias（`protocol.rs:932`），说明这一档在真实演进中被证明是多余的。现在就按别名实现，避免将来再做一次破坏性收敛。

**`SandboxPolicy`（子进程能碰什么）**：

- `read_only`：不可写任何位置（默认）
- `workspace_write { writable_roots, network_access }`：可写指定根（默认 `[project_root]`，`network_access: false`）
- `danger_full_access`：无限制

#### 与现有 `PermissionManager` 的关系（三个维度，不是三种说法）

现有 `PermissionManager` 的 `readonly`/`write`/`full`（`execution_layer.py:290-296`）本质是**工具集白名单**——它裁决"`terminal_exec` 这个工具能不能被调用"（`execution_layer.py:553-561`），与"这条命令的子进程能碰什么"是不同的问题。因此：

- `PermissionManager` **保留不变**，继续负责**工具准入**。这也保证 `test_all.py:243-244`、`test_all.py:396-408` 的权限断言不受影响。
- `ApprovalPolicy` 负责**何时把决定权交还给人**。
- `SandboxPolicy` 负责**执行时的 OS 边界**，作为 `exec.*` 请求的字段下发给执行器。

单次调用的完整链路：工具准入（现有 `PermissionManager`）→ 命令安全性判定（新 execpolicy）→ 审批（如判定为 `prompt` 且策略允许问）→ 沙箱执行（执行器）→ guardian 回滚（现有，宿主侧）。

#### 默认值与组合

- 默认：`ApprovalPolicy = on_request`，`SandboxPolicy = read_only`。这与现有 `permission_level` 默认 `readonly`（`execution_layer.py:299`、CLI 默认见 `execution_layer.py:980`）一致。
- 用户把权限升到 `write` 时，`SandboxPolicy` 联动升到 `workspace_write{writable_roots:[project_root], network_access:false}`。
- `danger_full_access` 只能由显式 CLI flag + 一次性确认开启，永不作为任何路径的默认值。
- 有意义的组合：
  - `never` + `read_only`：全自动只读探索，失败直接回模型（CI / 评测场景）
  - `untrusted` + `read_only`：首次接触陌生仓库
  - `on_request` + `workspace_write`：升权后的日常默认
  - `never` + `danger_full_access`：**唯一必须硬拦的组合**，启动时直接拒绝。无人值守叠加无隔离等于完全没有边界，这个组合不存在合理用途。

#### 命令安全性判定放在哪一层：独立模块 `ace_execpolicy.py`

**不放执行器、不放执行层、不放工具，而是独立的纯函数模块 + 数据化规则**（对齐 codex 把它抽成独立 crate 的做法，规则形态与三值决策见 `execpolicy/README.md:5-10`）。四条理由：

1. **可无副作用单测**：判定是纯函数（argv → decision），`test_all.py` 可以直接断言 `decision`，**不需要真的执行任何命令**。当前 `terminal_exec` 的测试必须真实执行（`test_all.py:326`、`test_all.py:334-337`），这既慢又限制了能覆盖的危险用例数量。
2. **宿主与执行器都要用它**：宿主用于 pre-flight（决定是否需要审批、是否直接拒绝），执行器用于纵深防御的二次校验。同一份规则、两处执行——这要求它既不属于宿主也不属于执行器。
3. **规则是数据，因此语言无关**：argv 前缀 + `decision` 可以序列化成 JSON 随请求下发（示例见请求 2 的 `policy_decision` 字段），未来的 Rust 执行器读同一份规则文件即可，不需要移植判定逻辑。
4. **三值决策而非布尔**：`allow`/`prompt`/`forbidden`。`forbidden` 是**审批不可解除**的（`rm -rf /`、`format`、写 `C:\Windows`；见响应 5 的 `approvable: false`），`prompt` 是可由用户提升的。布尔判定无法表达"这条命令连问都不该问"。多规则命中时取最严（`forbidden` > `prompt` > `allow`，同 `execpolicy/README.md:95`），避免规则冲突时的歧义。

**换成 C1 的代价**：继续用单一 `permission_level` 承载三个维度，意味着"允许调用 `terminal_exec`"和"允许写宿主任意位置"永远无法分离——用户为了让 Agent 在项目内建个文件，必须同时授予它写 `C:\` 的能力。而把判定逻辑留在 `_exec_terminal_exec` 内部（现状）则意味着每个危险命令的测试都必须真实执行，覆盖率天花板很低。

---

## Consequences

### 正面

- `shell=True`（`tools/file_tools.py:274`）被彻底移除，命令注入面从"字符串黑名单"变成"argv 数组 + 数据化前缀规则"。
- `terminal_exec` 与 `code_execute` 的三项不对称（白名单、env 清洗、隔离）被拉平到同一条路径。
- 首次获得资源边界与可靠的进程树回收；孤儿进程从"必然发生"变成"可检测"（响应示例中的 `orphans_remaining`）。
- 命令安全性判定可在不执行命令的前提下被单测覆盖。
- 执行器可被 Rust 二进制原地替换，宿主零改动。

### 负面（必须接受的代价）

- **延迟与生命周期复杂度**：常驻执行器进程带来僵尸进程、管道半关闭、Windows 上 Ctrl-C 传播语义差异、执行器崩溃后的重启与在途请求补偿。这些是全新的一类故障模式。
- **协议成为新的公共契约**：需要版本化、需要契约测试。`stdout` 污染（一次 `print()` 即破坏协议流）是一整类新 bug，且它的表现形式是"JSON 解析失败"，排查方向容易被误导。
- **双份策略判定会漂移**：宿主与执行器各跑一次 execpolicy，若规则数据不同源就会出现"宿主放行、执行器拒绝"的困惑。缓解手段是单一规则文件 + 同一份单测，但这是需要持续维护的约束而非一次性工作。
- **系统调用代码的可维护性**：Tier-1 的 Job Object / 受限令牌代码是"看起来像 C 的 Go"（`syscall.NewLazyDLL` + `unsafe.Pointer` 手工布局），结构体布局错误的表现是静默失效而非报错——沙箱声称启用但实际没生效。因此 `sandbox_applied` 必须由执行器**实测回报**（如响应 2 所示），不能由配置推断；而"实测回报"本身也需要被测试证伪，见 `executor/token_probe_windows_test.go` 的特权计数探针。原文写的是 ctypes（当时预期 Python 执行器），换成 Go 之后风险性质不变，只是少了指针宽度这一类坑。
- **Tier-2 引入外部运行时依赖**：Docker 只能是可选档，不进核心，零依赖原则得以保住，但也意味着**最强的隔离档位在多数用户机器上不可用**。
- **必须修改一条既有测试断言**：`test_all.py:326` 使用 `command='echo x > created.txt && echo api_key="abcdef1234567890"'`，依赖 shell 的重定向与 `&&` 语义。阶段 1 之后这条命令会被 execpolicy 判为 `prompt` 或直接拒绝。这是本迁移对"不破坏现有测试"的**唯一例外**，需要在同一个提交里把断言改为"该命令需审批"，并另起一个用例继续覆盖原本要验证的 guard 行为（输出中的硬编码密钥检测，`execution_layer.py:584-598`）。
- **guardian 的保护范围不会因此变强**：沙箱阻止的是越界，guardian 回滚的是越界之内的破坏，两者不可互相替代。
- **一处容易被忽略的耦合**：guardian 快照采集的是 `project_root`（`guardian.py:60`）。`terminal_exec` 当前 `cwd` 就是 `project_root`（`tools/file_tools.py:275`），所以快照是有效保护；而 `code_execute` 的 `cwd` 是临时沙箱目录（`tools/code_tools.py:101-104`），与快照范围不重叠——也就是说 `code_execute` 的快照（`execution_layer.py:573-579` 对 `WRITE_TOOLS` 一律建快照，`code_execute` 在 `execution_layer.py:107` 的集合内）**本来就是空保护**。迁移中必须保持 `exec.command` 的 `cwd` 语义不变，否则 guardian 回滚会**静默失效**且没有任何测试能发现。

### 待实测假设（未验证，不得当作已知）

1. **Job Object + 低完整性级别下常用工具是否仍可用**：`python`、`git`、`pip` 对 `%TEMP%`、`AppData` 的写入在 Low IL 下的行为未实测。若大面积失败，Tier-1 需退化为"只用 Job Object 限资源，不降 IL"。
2. ~~**`CreateRestrictedToken` + 进程创建的特权要求**~~ —— **已实测，结论见下方"已验证的假设"第 1 条。** 不再是待实测项。
3. **Windows 上双管道非阻塞读取**：Python 在 Windows 无法对管道 `select()`，需要两个读线程或 asyncio proactor。这会向当前完全同步的 `ExecutionLayer` 引入线程，兼容性未验证。
4. **NDJSON 行长与 base64 膨胀**：base64 有 4/3 膨胀，64 KiB 分块对应约 87 KiB 行长，1 MiB 行限下的实际吞吐与内存占用需压测。
5. **进程树终止的覆盖面**：`taskkill /T /F` 对通过 `start` 启动的 detached 进程是否有效未验证；这也是优先用 `TerminateJobObject` 的原因。
6. **参考实现的适用性边界**：codex 的 Windows 强隔离依赖一次性管理员安装（独立沙箱用户 + ACL + WFP，见 `windows-sandbox-rs/src/wfp.rs:77`、`bin/setup_main/win/sandbox_users.rs`），ACE 若坚持"不需要管理员"，则**永远无法达到 codex Windows 档位的隔离强度**。这是一个已被接受的能力上限，不是待解决的问题。

### 已验证的假设（有实测数据，可当作已知）

1. **`CreateRestrictedToken` + 进程创建在普通用户下可行**（原待实测假设 #2，已实现于 `executor/sandbox_windows.go`）。
   - 不需要 `SE_ASSIGNPRIMARYTOKEN_NAME`：当传给 `CreateProcessAsUser` 的令牌是**调用者自身令牌的受限版本**时，Windows 免除该特权要求。Chromium 沙箱依赖的正是这条特例。因此既不需要提权，也不需要退化到 `CreateProcessWithTokenW`。
   - 落地方式：`OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE|TOKEN_QUERY|TOKEN_ASSIGN_PRIMARY)` → `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE|LUA_TOKEN)` → 写入 `syscall.SysProcAttr.Token`（Go 的 `os/exec` 见到非 0 的 `Token` 就改走 `CreateProcessAsUser`）。
   - **实测效果：子进程特权数 5 → 1**（`executor/executor_test.go:TestRestrictedTokenActuallyDropsPrivileges`，通过 `GetTokenInformation(TokenPrivileges)` 数 `PrivilegeCount`；剩下的 1 个是 `DISABLE_MAX_PRIVILEGE` 语义上保留的 `SeChangeNotifyPrivilege`）。也就是说 `SeDebugPrivilege`、`SeBackupPrivilege` 这类"绕过 ACL"的能力确实没了。
   - **刻意不用 `SidsToRestrict`**：限制性 SID 会让子进程访问任何文件都要通过两次 ACL 检查，工作目录立刻变成不可写——这个执行器要跑 pytest、要写编译产物，加上等于把功能砍掉。身份边界到"去特权 + 降完整性"为止；文件系统边界是 Tier-2 的职责。
   - **唯一实测到的失败模式：应用执行别名**。Microsoft Store 版 `python.exe` 是 reparse point，受限/LUA 令牌解析不了它，`CreateProcessAsUser` 返回 `ERROR_CANT_ACCESS_FILE`。处理方式是 `spawnRelaxer` 可选接口（`executor/sandbox.go`）：放弃令牌、重建一个全新的 `exec.Cmd`（`Start` 失败后的 `exec.Cmd` 已关掉自己的管道，不能重用）、重试一次，并把原因写进 `restricted_token_reason`。选择这条路而不是直接失败，是因为后者会让任何装了 Store Python 的机器上 `code_execute` 彻底不可用——拿"完全不能用"换"少一层纵深"不划算。
   - 未验证的边界：本机只有一个账户类型可测，域账户 / 组策略限制下的行为未知。`restricted_token_reason` 的存在就是为了让这类环境差异在运行时自己暴露出来，而不是靠文档猜。

---

## Migration Plan

每个阶段独立可验证、独立可回滚，验证命令统一为 `python test_all.py`（写这份 ADR 时 1121 行、纯 stdlib；实施完成后 5683 行 / 1428 条断言，依然纯 stdlib）。Go 侧另有 `go vet ./... && go build ./... && go test ./...`；`go test -race` 需要 cgo，本机无 C 编译器，由 CI 的 windows/ubuntu 两条 runner 覆盖。

### 阶段 0：引入策略与协议模块，只观测不拦截

- 新增 `ace_execpolicy.py`（纯函数 + 规则数据）与 `exec_protocol.py`（信封与错误码的序列化/校验，无副作用）。**实际落地时没有 `exec_protocol.py`**：宿主侧的信封与错误码收在 `ace_executor.py` 里，执行器侧收在 `executor/protocol.go` 里。两侧各写一份是刻意的——协议要是共享一份实现，"两个独立实现互相校验"这条性质就没了；见「实施后记」。

- 在 `tools/file_tools.py:243` 的 `_exec_terminal_exec` 入口 shadow 调用策略判定，把 `decision` 写入 `result.metadata`，**不改变任何行为**。
- 验证：`test_all.py` 全绿（行为未变）+ 新增策略纯函数断言（可覆盖数十条危险命令而无需执行）。
- 回滚：删两个新文件 + 一行调用。

### 阶段 1：消除 `shell=True` 与环境变量继承

- `tools/file_tools.py:274` 改为 argv 执行（复用 `tools/base.py:75` 的 `_split_cmd_windows`）。确实需要 shell 语义的命令（重定向、`&&`）走显式 `["cmd.exe","/c",...]`，且必须先通过 execpolicy（默认 `prompt`）。
- 补 env allowlist，直接照 `tools/code_tools.py:115-125` 的 `minimal_env`。
- **保持 `cwd=project_root` 不变**（`tools/file_tools.py:275`），否则 guardian 回滚静默失效。
- 已知破坏：`test_all.py:326` 的断言需同步更新（见 Consequences）。
- 验证：`test_all.py` + `test_terminal_exec.py`。
- 回滚：单文件 revert。

### 阶段 2：进程外执行器上线，进程内路径保留

- 新增 `executor_client.py`（宿主侧 NDJSON 客户端 + 看门狗）与 `executor/`（子进程入口）。
- `ExecutionLayer` 增加配置开关 `executor.mode`，**默认仍为 `inproc`**。
- 因为 `test_all.py` 的工具调用统一走 `run_agent()`（`test_all.py:59`），只需参数化 `ExecutionLayer` 的构造即可让**同一批断言在两种 mode 下各跑一遍**。这是本迁移能保持测试兼容的关键结构优势。
- 验证：两种 mode 下 `test_all.py` 均全绿。
- 回滚：配置改回 `inproc`。

### 阶段 3：沙箱档位（已落地；原前置条件"待实测假设 1、2 的 spike 通过"中的第 2 项已实测通过）

- 执行器内实现 Tier-0（阶段 1 已有）+ Tier-1（Job Object + 受限令牌，Go `syscall`）。`initialize` 声明可用档位。
- 档位不可用时返回 `E_SANDBOX_UNAVAILABLE`，默认不降级。
- 验证：新增断言——内存炸弹被 kill、子进程树被整体回收（`orphans_remaining == 0`）、超时走与 cancel 相同的终止路径、`sandbox_applied` 为实测回报而非配置回显。
- 回滚：把 sandbox 请求恒定为 `tier0_process`。

### 阶段 4：默认切换到子进程模式 + 流式输出（已落地）

- `executor.mode` 默认改 `subprocess`；启用 `output` 增量事件，宿主聚合回现有 `result.data["stdout"]` 形状，**保持 `ExecutionResult` 契约不变**（`tools/result.py:10-14`），下游 guard 检测（`execution_layer.py:584-598`）无需改动。
- 验证：`test_all.py` 全绿 + 流式聚合与一次性返回的字节级一致性断言。
- 回滚：配置改回 `inproc`。

### 阶段 5：可选强隔离档与实现替换

- 新增 Tier-2（Docker）作为可选档，需要一个**只含执行器**的最小镜像（不复用 `Dockerfile:11` 的 `CMD`）。
- **已完成**：`math_calc` 不再用 `eval`，改为自实现的 `eval_math_ast()`（`tools/code_tools.py`）。判据从"校验器有没有枚举到这个节点"变成"dispatch 表里有没有这个节点"——新节点类型的默认结局是 raise 而不是被执行。前置的 `_scan_math_expression()` 保留，但职责降为给出可读的 403 理由。顺带收紧两处：字符串字面量不再放行（`"a" * 10**8` 是内存 DoS），幂运算的底数改为在值层判上界（旧规则要求两边都是字面量，把 `(1+2)**3` 这种正常算式也拒了）。这一项与执行器无关，已独立完成。
- 只要 `initialize` 与方法集不变，Rust 执行器可原地替换二进制，宿主零改动。
- 回滚：档位下线 / 二进制回退。

---

## 与其他角色的交接

- **给代码审查师**：架构层坏味道对应的具体代码位置——`tools/file_tools.py:274`（`shell=True`）、`tools/file_tools.py:274-276`（无 env 清洗，与 `tools/code_tools.py:115-125` 不对称）、`tools/file_tools.py:268-270`（命令在执行前被字符串改写，审计字段 `tools/file_tools.py:281` 记录的是改写后的值）、`tools/code_tools.py:162`（`eval`）。
- **给测试专家**：架构风险区域需要提升覆盖率——execpolicy 三值判定（纯函数，可高密度覆盖）、cancel/timeout 的双 `resp` 语义与幂等性、执行器崩溃后的宿主补偿路径、`sandbox_applied` 是否为实测回报。另需一条**当前缺失**的断言：`code_execute` 的 guardian 快照因 cwd 不重叠而是空保护（`tools/code_tools.py:101-104` vs `guardian.py:60`），这个事实应当被测试固化，而不是靠注释。
- **给 SRE**：单点与瓶颈——执行器进程是新的单点（崩溃即所有危险工具不可用，需要重启策略与在途请求补偿）；看门狗超时阈值 `timeout_ms + grace_ms` 需要可配置；孤儿进程数（`orphans_remaining`）与执行器重启次数应作为监控指标；`sandbox_applied.degraded` 为 true 时应告警，因为它意味着实际隔离低于声称值。

---

## 结论

**有条件通过。** 条件有三：

1. 阶段 1（消除 `shell=True` + env allowlist）必须先落地并通过 `test_all.py`，它独立于协议工作即可交付大部分安全收益。
2. 待实测假设第 1 项（Low IL 下常用工具是否可用）仍需实测。第 2 项已完成实测，结论是**受限令牌路径在普通用户下可用**（特权数 5 → 1，见"已验证的假设"）；因此 Tier-1 **确实具备身份隔离**，只在少数可执行文件（应用执行别名）上会自动放弃令牌并退回"仅 Job Object 资源限制"，此时 `restricted_token=false` + `restricted_token_reason` 如实标注，不声称具备身份隔离。
3. `test_all.py:326` 的断言修改必须与阶段 1 同提交，且原本要验证的 guard 行为需由新用例继续覆盖。

---

## 实施后记（2026-08-22，实现完成后回填）

本 ADR 写在实现之前，下面记录**实际落地与原计划的差异**。差异本身比结论更有价值——它标出了哪些判断是纸上推演的产物。

### 与原计划一致的部分

- NDJSON over stdio、`initialize` 声明可用档位、`sandbox_applied` 实测回报、审批与沙箱两个正交闸门——全部照原样落地。
- 判定与执行分离：`ace_execpolicy.evaluate_command()` 是纯函数，不碰进程也不碰网络，因此几十条危险命令可以在单测里高密度覆盖。
- 主机侧客户端 `ace_executor.py` 与执行器 `executor/` 之间只有协议，没有共享代码。

### 与原计划不同的部分

- **实现语言是 Go，不是"先 Python 后 Rust"**。原因是环境判断错了（见"环境与设计约束"第一条的更正）。收益不只是省掉一次迁移：Job Object 与受限令牌在 Go 里是 `syscall` 调用而不是 ctypes 结构体手工布局，静默失效的风险面小了一圈。
- **`shell=True` 没有被完全删除，而是被收进了一条需要人点头的路径**（`tools/file_tools.py:398-399`）。原计划是"确实需要 shell 语义的命令走显式 `["cmd.exe","/c",...]`"；实际实现保留了 `shell=True`，但前置条件是 execpolicy 判为 `prompt` **且** `approval_hook` 返回同意。安全性上等价（都需要人类批准），代价是这行代码看起来仍然刺眼，容易在未来的审查里被误判为遗漏。
- **Go 执行器默认开启，但走的是"能用就用"而非"必须可用"**（`tools/base.py`：`ACE_USE_GO_EXECUTOR=0/false/no/off` 可强制关闭，显式构造参数优先级最高）。原计划的阶段 4 是"默认改 subprocess，档位不可用时返回 `E_SANDBOX_UNAVAILABLE`，默认不降级"；实际实现在**二进制缺失或起不来时静默降级回进程内实现**，因为默认值决定了沙箱是否真的被走到——默认关等于三个档位在真实使用中一次都不生效。硬性不降级留给显式请求某个 tier 的场景（`allow_weaker_tier=false`），而不是加在默认路径上。
- **Tier-2（Docker）未实现**，`initialize` 如实把它报为 unavailable，不做静默降级。

### 实施期补的边界问题（BT-02..BT-05）

原计划把"杀不掉的子进程"当成不会发生的情况；实测下来它是最贵的一类故障，因为代价不是一次失败而是永久泄漏。

- **杀完必须有界地收尸**（`executor/run.go` 的 `reapAfterKill`，宽限 5s ×2 档）。`waitDone` 由 `wg.Wait()` → `cmd.Wait()` 喂，而 pump 只有在**所有**继承了 stdout 句柄的进程都消失后才看到 EOF —— 含孙进程。`killTree` 在 Tier-0 只是尽力而为（整树保证要靠 Tier-1 的 Job Object），跑掉一个就让裸 `<-waitDone` 永久阻塞：goroutine + 句柄 + 管道全泄漏，请求也永远拿不到 `resp`（宿主会把它误报成传输超时）。放弃等待时**不能碰 `outS`/`errS`** —— pump 还在往里写，读 `total`/`buf` 就是 `-race` 抓得到的数据竞争，所以放弃路径如实回报"0 输出 + 原因"。不选"关管道逼退阻塞的 read"：`StdoutPipe` 用的是 `os.Pipe`，Windows 上是没注册到 poller 的同步匿名管道，并发 `Close`/`Read` 行为未定义。
- **Ctrl+C 必须发 `cancel`**（`ace_executor.py`）。`KeyboardInterrupt` 不是 `Exception`，原来的 `except Exception` 接不到它 —— 而那恰好是最该发 cancel 的时刻，否则执行器的子进程（一次构建、一次下载）会变成没人认领的后台任务继续烧 CPU 和磁盘，直到自己超时。同时给执行器进程加了 `CREATE_NEW_PROCESS_GROUP` / `start_new_session`，让它不被控制台信号连带打死。
- **超时只有一个来源**（`ACE_EXEC_TIMEOUT_MS` / `ACE_EXEC_RESP_GRACE_MS`，均带上下钳位），Go 路径与进程内回退共用，两条路径的超时语义不会分叉。钳位不是洁癖：`ACE_EXEC_TIMEOUT_MS=0` 这种手误会让每条命令瞬间超时，而症状（全是 `E_TIMEOUT`）指不到环境变量上。
- **进程内回退不再是"没有边界的那条路"**（`tools/file_tools.py` 的 `_run_capped`）。原来的 `subprocess.run(timeout=30)` 在 `shell=True` 下会**永久挂住**：它的超时处理是 `Popen.kill()`（只杀直接子进程，也就是 `cmd.exe /c`）后 `communicate()`，而后者要等活着的孙进程给出管道 EOF —— "30 秒超时"变成无限期阻塞。现在是两条 pump 线程 + 整树回收（`taskkill /T /F` / `killpg`）+ 1 MiB 输出上限，**到量后继续排空**（到量就停读会让子进程卡在 `write` 上，"大小限制"悄悄变成"时间限制"），超时按 504 返回并**带上已截获的输出**。
- **默认环境白名单补了 `SystemDrive` / `ProgramData` / `ALLUSERSPROFILE`**。少了它们，Windows shell 层里 `%SystemDrive%\ProgramData\...` 这类字面量路径展开不了、退化成相对路径，子进程会在自己的 cwd（正常就是用户的项目目录）里造出一棵叫 `%SystemDrive%` 的垃圾目录树 —— 这是在本仓库 `executor/` 下真实长出来过的。故意**不**放行 `APPDATA` / `LOCALAPPDATA`：那是用户可写的状态目录，等于白送一块持久化落脚点。
  - 这条修了两次，第一次没修在生效的那份上。清单有两份拷贝：`executor/run.go` 的 `defaultEnvAllow` 和宿主 `ace_executor.py` 的 `DEFAULT_ENV_ALLOW`。Go 那份只在 `len(allow) == 0` 时才被查到，而宿主**永远显式下发**自己那份 —— 所以只改 Go 侧等于没改，`%SystemDrive%` 目录树照旧长出来。两份现已一致，并有一条断言从 `run.go` 里正则解析出列表与 Python 侧逐项比对（含顺序）。教训是判据要盯**漂移本身**：一份清单存在两处，就一定会有一次只改了一处。

### 还没做的

- 阶段 4 的另一半已完成：流式增量输出（`output` 事件）与宿主侧聚合。落地时改掉了四处一开始写错的地方：截断必须发生在推送 `onChunk` **之前**（否则 `max_output_bytes` 只约束了缓冲区，事件流仍把子进程的全量输出推给宿主）；`seq` 必须在写锁内分配（否则 stdout/stderr 两个 pump 并发时帧的写出顺序与 seq 不一致，宿主的丢帧检测会误报协议损坏）；事件在读线程内**实时派发**而不是等 `resp` 之后回放（这让"resp 是同一 id 的最后一帧"成为单线程读取的性质，而不是时序上的巧合）；读侧套 `io.BufferedReader`（裸 FileIO 上按行迭代会退化成逐字节 syscall）。另外每帧单独 `base64.b64decode`、只在末尾做**一次** UTF-8 解码——帧长度不是 3 的倍数，base64 字符串不能拼接后再解；字节一致性由执行器回报的 sha256 `digest` 校验，不一致抛 `E_TRANSPORT`。
- 仍未接线的是 `code_execute`：它还没走执行器，`terminal_exec` 才是当前唯一使用流式路径的工具。

- Tier-2 Docker 档位。
- 待实测假设第 1 项（Low IL 下 `python`/`git`/`pip` 的写入行为）——当前 Tier-1 走的是 LUA_TOKEN 的 **Medium** 完整性级别，并没有降到 Low，所以这条假设的原始场景尚未被触发，也尚未被验证。这一点现在不再依赖读代码推断：`sandbox_applied.integrity_level` 是实测回报（`GetTokenInformation(TokenIntegrityLevel)`），本机值为 `medium (S-1-16-8192)`，并有一条断言盯着它 —— 如果哪天真降到了 Low，那条断言会先响，提醒重新评估这项假设。
- `policy` / `writable_roots` / `network_access` / `scratch_dir` 四个字段仍然没有实现（它们要等 Tier-2）。现在的行为是**收到即报 `E_SANDBOX_UNAVAILABLE`**，不再静默忽略。

