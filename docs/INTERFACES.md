# 接口与类型契约(INTERFACES)

> 本文件把 ace 的**对外/对内接口**钉死,供开发与 AI 助手遵守,防止“协议漂移”。
> 依据:当前源码(`tools/registry.py`、`tools/result.py`、`execution_layer.py`、`agent_runner.py`、`guardian.py`、`Archive.py` 等)。与代码冲突时**以代码为准并更新本文**。
> 未标准化的缺口统一见 [BACKLOG.md](BACKLOG.md)(错误码枚举、状态常量、双前端合并等)。

## 1. 分层与依赖方向(谁不能绕过谁)

```text
ai_code.py / agent_runner.py        # 前端(会话/流式/提供商)
   └── execution_layer.py           # 执行层主入口:解析 → 权限 → 守门 → 工具 → 回滚
         ├── tools/registry.py      #   工具唯一声明(TOOL_SPECS)── 只被派生,不被旁路
         ├── tools/<域>_tools.py    #   handler 实现(ToolExecutor)
         ├── gateway_v2/            #   L1/L2/L4/L5 网关(意图/技能/守门/飞轮)
         ├── ace_net.py             #   出站闸门(SSRF + 白名单)
         ├── ace_execpolicy.py      #   命令三值判定(allow/prompt/forbidden)
         └── guardian.py/Archive.py/Nuwa.py   # 快照/记忆/报告
```
铁律:模型只能与执行层对话;执行层是唯一会碰到文件系统/网络/进程的边界。

## 2. Agent ↔ 执行层:文本协议(默认通道)

模型每次输出为两段:
```text
<INTERNAL>
[INTERNAL_THINKING]
[ACT] <tool_name>            # 或 [PLAN]/[REASON] 状态标签
[/INTERNAL_THINKING]
</INTERNAL>
<EXTERNAL>
answer.
{"tool": "<tool_name>", ...参数...}      # 模式 A:工具调用
</EXTERNAL>
```
- 模式 B(最终回复):`answer.` 后跟**纯文本**,不带 `tool` 键 → 状态 `FINAL_REPLY`。
- 模式 A 的 JSON 以 `{"tool": ...}` 为根;无 `tool` 键的 JSON 一律按文本处理。
- Windows 路径反斜杠由 `tools/base.repair_backslash_json` 修复(进执行层前)。
- 状态标签(`[PLAN]/[REASON]/[ACT]/[ANALYZE]/...`)只作思考链标记,模型不得借此绕格式。

**原生工具调用通道(可选)**:OpenAI 兼容 `tools`/`tool_choice=auto`;
端点不支持时自动降级回文本协议。`agent_runner --tools` 打开,降级循环独立于 `ace_http` 重试。

## 3. 执行层公共 API

```python
ExecutionLayer(project_root: str | Path,
               permission_level: "readonly" | "write" | "full",
               config: dict)   # 键见下
result: dict = el.process_agent_output(agent_output_text: str, user_input: str)
ctx = el.prepare_context(user_input)          # 记忆预注入(可独立调用)
```

`config` 已知键(`benchmarks/bench_core.py`、`test_all.py` 在用):
`bait.enabled/frequency`、`sandbox_base`、`confine_files`、`signing_key`、`max_snapshots`、
`session_id`、`guard.rules`、`egress_allowlist`、`sandbox.mode`、`flywheel_path`、`email_smtp`。

`process_agent_output` 返回 dict(契约字段,测试依赖):
`status`(见 §4)、`data`、`message`、`tool`、`internal`、`instruction`(错误自动回喂)、
`memory_injected`、`snapshot_id`、`rule`(守门命中)、`intent`、`skills`、`ast_warnings`、`baited_code`。

## 4. 状态码契约(现状;集中常量化见 BACKLOG P1-Q10)

| 状态 | 含义 |
|---|---|
| `SUCCESS` | 工具执行成功,`data` 含结果 |
| `FINAL_REPLY` | 模式 B 最终回复放行,`message`=回复 |
| `PERMISSION_REQUEST` | 权限不足自动请求授权(工具名在 `tool`) |
| `GUARD_VIOLATION` | L4 守门/模式 B 命中,`rule` 点名规则 |
| `BAIT_TRIGGERED` | code_execute 诱饵注入待修复,`baited_code` |
| `AST_FAILED` | AST 安全规则熔断 |
| `403` | 权限/越界/敏感目标拦截(语义见 message,待枚举化) |
| `404` | 路径或目标不存在 |
| `409` | 歧义(如 str_replace 多匹配),指引补上下文重试 |
| `400` | 参数错误(附示例) |
| `500` | 内部失败 |
| `501` | 已登记未实现 / 缺渠道配置 |
| `503` | 沙箱档位不可用(不静默回退) |

## 5. 权限模型

- 档位:`readonly`(起步默认)/ `write` / `full`;**默认只读**是产品契约
  (⚠️ `agent_runner.py --permission` 目前默认 `write`,与本文矛盾,记 BACKLOG SEC-03)。
- 工具权限组:`PERM_READ` / `PERM_WRITE` / `PERM_HIGH_RISK`;另有 `CONTROL_TOOLS`
  (`plan_propose`/`request_permission`,任何档位都在)与 `CONFIRM_TOOLS`。
- 授权:单次(用后即焚)或会话级;`terminal_exec` 只接受逐次确认,永不会话级。
- 非 tty / 非交互:授权与计划审批一律 fail-close 拒绝。
- 写工具调用前自动快照;`.guardian/` 对 Agent 只读不可写删。

## 6. 工具结果与执行器接口

```python
@dataclass
class ExecutionResult:      # tools/result.py —— 对外边界的唯一结果类型
    status: str             # success | error | guard_violation | bait_triggered | permission_denied
    data: Any
    error_code: str         # 自由字符串(将枚举化)
    message: str            # 给人/模型看;不得承载语义判定
    metadata: dict
```
handler 统一收口到 `tools/base.execute` 分发;**不许**在 execution_layer 手写 if/elif 工具链。

## 7. 工具注册表契约(tools/registry.py)

```python
@dataclass(frozen=True)
class ToolSpec:
    name: str                       # 工具名(唯一)
    permission: str                 # PERM_READ / PERM_WRITE / PERM_HIGH_RISK
    description: str                # 模型可见,写清楚“何时用/别拿来做什么”
    handler: str = ""               # ToolExecutor 方法名;"" = 登记未实现(不暴露)
    parameters: dict = ...          # JSON Schema(object,properties[,required])
    example: str = ""               # {"tool":...,...} 示例
    pass_tool_name: bool = False    # True → handler(tool_name, params)
    control: bool = False           # True → 执行层直通(plan_propose/request_permission)
    expose: bool = True             # False → 不发给模型(占位/危险登记)
    confirm: bool = False           # True → 每次逐次确认(terminal_exec)
```
派生关系(禁止手写第二份):`READ/WRITE/HIGH_RISK_TOOLS` 与 function-calling schema、
`TOOL_EXAMPLES`、暴露清单全部由 `TOOL_SPECS` 派生;`agent_runner.TOOLS = openai_tools()`。

## 8. 网络与模型客户端

- 所有出站(api_get/api_post/browser_open/search 系)统一走 `safe_request`:
  `ace_net` SSRF 判定(pin-to-IP + 逐跳复检 + 全记录)+ 可选 `egress_allowlist`。
- 模型调用统一 OpenAI 兼容 `POST {base}/chat/completions`,`Authorization: Bearer <key>`;
  429/5xx/抖动由 `ace_http.urlopen_json_with_retry` 退避(认 `Retry-After`)。
- 已知缺口:双前端 `ai_code.ModelClient` 与 `agent_runner.ModelProvider` 重复实现 → BACKLOG R-03 合并。

## 9. 支撑模块最小接口

| 模块 | 契约方法 |
|---|---|
| `guardian.py` | `snapshot(reason) -> id|None`、`verify_snapshot(id) -> (ok,msg)`、`rollback(id) -> bool`、`backup_dir` |
| `Archive.py` | `add(text)->bool`(短输入拒)、`detect_topic_shift(text)`、`get_memory(top_k)`、`stats()` |
| `Nuwa.py` | `add_metric(...)`、`add_rollback(...)`、`generate_report() -> {html_path,json_path,summary}` |
| `universal_document_parser.py` | `parse_document(path) -> ParseResult(success, method, text, truncated, metadata, error)` |

## 10. 已知接口级待办(实现时引用 BACKLOG ID)

- 错误码/状态码集中常量 + 枚举化,文案与语义解耦 → BACKLOG Q-10
- 双 v7 提示词(运行时 `prompts/` vs 规范 `docs/prompt-engineering/`)同步/标注 → BACKLOG Q-07
- `parse_document` 未走文件路径闸门(只读越界)→ BACKLOG SEC-02
- `code_execute` AST 精确名拦截可被别名/lambda 绕过 → BACKLOG SEC-01
- 模块命名风格(旧 `Archive/Nuwa/work/guardian` vs 新 `ace_*`)→ BACKLOG R-06

## 11. 命名与检索索引(R-06)

历史命名无信息量,不强行改名(避免破坏引用),检索时用下列关键词:

| 模块 | 真实职责 | 检索词 |
|---|---|---|
| `Archive.py` | SimHash 记忆引擎 | memory / simhash / 记忆 / 主题切换 |
| `Nuwa.py` | POC 报告(HTML+JSON) | report / POC / 通过率 |
| `work.py` | 诱饵工厂 + AST 行为检测 | bait / ast / 诱饵 / 检测 |
| `guardian.py` | 物理快照回滚 | snapshot / rollback / undo / 快照 |
| `ace_*` | 执行层支撑(策略/网络/上下文/HTTP/日志/主题/选择器/卡片/隔离) | 直接以 ace_ 前缀检索 |

约定(见 `docs/DEVELOPMENT.md` §3):**新模块一律 `ace_` 前缀、小写下划线**;
新增导出/类请补 docstring 首行职责(检索词友好)。
