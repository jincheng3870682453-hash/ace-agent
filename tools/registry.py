#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools.registry —— 工具注册表：工具的唯一声明处

在此之前，新增一个工具需要同时改三处硬编码，漏一处就是静默失效：
  1. tools/base.py    execute() 的 if/elif 分发链
  2. agent_runner.py  TOOLS 字面量（function calling schema）
  3. execution_layer.py  READ_TOOLS / WRITE_TOOLS / HIGH_RISK_TOOLS / TOOL_EXAMPLES

现在这三处都从 TOOL_SPECS 派生。新增工具 = 在 TOOL_SPECS 里加一条 + 实现 handler 方法。
这也是 MCP 接入点：MCP 本质是"运行时注册外部工具"，即 register() 一个 ToolSpec。
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

# 权限组：与 execution_layer.PermissionManager 的分级一一对应
PERM_READ = "read"
PERM_WRITE = "write"
PERM_HIGH_RISK = "high_risk"


@dataclass(frozen=True)
class ToolSpec:
    """一个工具的完整声明。

    handler:        ToolExecutor 实例上的方法名；空串表示"已登记但未实现"
                    （terminal_dangerous / db_drop 这类占位项）。
    pass_tool_name: handler 签名为 (tool_name, params) 而非 (params)。
                    file_read/file_write/file_delete/file_move 共用 _exec_file_ops。
    control:        由执行层直接处理，不走真实工具执行（plan_propose / request_permission）。
    expose:         是否暴露给模型（function calling / 提示词清单）。
    confirm:        每次调用都必须由用户确认，权限等级放行也不例外。
                    用于 terminal_exec 这类"策略层拦不住"的工具：它的危险命令黑名单
                    可被引号/长选项/变量展开/解释器旁路绕过，所以最终防线交给人。
                    复用 PERMISSION_REQUEST 流程，临时授权用后即焚 → 天然逐次确认。
    """
    name: str
    permission: str
    description: str
    handler: str = ""
    parameters: Dict = field(default_factory=lambda: {"type": "object", "properties": {}})
    example: str = ""
    pass_tool_name: bool = False
    control: bool = False
    expose: bool = True
    confirm: bool = False


def _obj(properties: Dict, required: Optional[List[str]] = None) -> Dict:
    schema: Dict = {"type": "object", "properties": properties}
    if required:
        schema["required"] = required
    return schema


TOOL_SPECS: List[ToolSpec] = [
    # —— 只读 ——
    ToolSpec(
        name="terminal_view", permission=PERM_READ, handler="_exec_terminal_view",
        description="只读查看目录/文件/进程状态（白名单命令，无 shell 副作用）",
        parameters=_obj({"command": {"type": "string",
                                     "description": "只读命令，如 ls -la / pwd / cat file.py"}},
                        ["command"]),
        example='{"tool":"terminal_view","command":"ls -la"}',
    ),
    ToolSpec(
        name="file_read", permission=PERM_READ, handler="_exec_file_ops", pass_tool_name=True,
        description="读取文件内容；传 offset/limit 可分段读取并返回带行号的片段（大文件先分段读，不要整读）",
        parameters=_obj({"path": {"type": "string", "description": "文件路径"},
                         "offset": {"type": "integer",
                                    "description": "起始行号（从 1 开始），与 limit 配合分段读"},
                         "limit": {"type": "integer", "description": "读取行数"}},
                        ["path"]),
        example='{"tool":"file_read","path":"README.md"}',
    ),
    ToolSpec(
        name="grep", permission=PERM_READ, handler="_exec_grep",
        description="按正则在项目文件内容中检索，返回 文件:行号: 内容（原生实现，不经过 shell）",
        parameters=_obj({"pattern": {"type": "string", "description": "Python 正则表达式"},
                         "path": {"type": "string", "description": "检索起点，目录或文件，默认项目根"},
                         "glob": {"type": "string",
                                  "description": "文件名过滤，如 *.py；多个用逗号分隔"},
                         "case_sensitive": {"type": "boolean", "description": "区分大小写，默认 false"},
                         "max_results": {"type": "integer", "description": "最多返回匹配行数，默认 200"}},
                        ["pattern"]),
        example='{"tool":"grep","pattern":"def _exec_","glob":"*.py"}',
    ),
    ToolSpec(
        name="glob", permission=PERM_READ, handler="_exec_glob",
        description="按文件名通配符查找文件路径（如 **/*.py），用于定位文件而不是搜内容",
        parameters=_obj({"pattern": {"type": "string", "description": "通配符，如 **/*.py 或 tools/*.py"},
                         "path": {"type": "string", "description": "查找起点目录，默认项目根"},
                         "max_results": {"type": "integer", "description": "最多返回条数，默认 200"}},
                        ["pattern"]),
        example='{"tool":"glob","pattern":"**/*.py"}',
    ),
    ToolSpec(
        name="api_get", permission=PERM_READ, handler="_exec_api_get",
        description="GET 请求获取数据（自动拦截内网/SSRF）",
        parameters=_obj({"url": {"type": "string"}}, ["url"]),
        example='{"tool":"api_get","url":"https://example.com"}',
    ),
    ToolSpec(
        name="db_query", permission=PERM_READ, handler="_exec_db_query",
        description="SQLite 只读查询（仅 SELECT/WITH，最多 100 行）",
        parameters=_obj({"query": {"type": "string"}}, ["query"]),
        example='{"tool":"db_query","query":"SELECT * FROM t"}',
    ),
    ToolSpec(
        name="search", permission=PERM_READ, handler="_exec_search",
        description="联网搜索（DuckDuckGo/Bing，无需 API Key）。搜代码请用 grep，不要用这个",
        parameters=_obj({"query": {"type": "string"}, "top_k": {"type": "integer"}}, ["query"]),
        example='{"tool":"search","query":"Python 教程","top_k":5}',
    ),
    ToolSpec(
        name="browser_screenshot", permission=PERM_READ, handler="_exec_browser_screenshot",
        description="截取屏幕画面保存到 .ace_shots/（需 pillow，Windows 可免依赖）",
    ),
    ToolSpec(
        name="math_calc", permission=PERM_READ, handler="_exec_math_calc",
        description="纯算术表达式求值（白名单 AST，无副作用）",
        parameters=_obj({"expression": {"type": "string"}}, ["expression"]),
        example='{"tool":"math_calc","expression":"2+2*10"}',
    ),
    ToolSpec(
        name="datetime_now", permission=PERM_READ, handler="_exec_datetime_now",
        description="获取当前时间",
        parameters=_obj({"format": {"type": "string"}}),
        example='{"tool":"datetime_now","format":"YYYY-MM-DD HH:mm:ss"}',
    ),
    ToolSpec(
        name="browser_open", permission=PERM_READ, handler="_exec_browser_open",
        description="用系统默认浏览器打开 http/https 链接",
        parameters=_obj({"url": {"type": "string"}}, ["url"]),
        example='{"tool":"browser_open","url":"https://example.com"}',
    ),
    ToolSpec(
        name="parse_document", permission=PERM_READ, handler="_exec_parse_document",
        description="解析 Word/Excel/PPT/PDF/图片/文本并提取内容",
        parameters=_obj({"path": {"type": "string"}, "force_ocr": {"type": "boolean"}}, ["path"]),
        example='{"tool":"parse_document","path":"报告.docx"}',
    ),
    ToolSpec(
        name="open_file", permission=PERM_READ, handler="_exec_open_file",
        description="生成可点击文件链接（用户点击后打开）",
        parameters=_obj({"path": {"type": "string"}}, ["path"]),
        example='{"tool":"open_file","path":"README.md"}',
    ),
    ToolSpec(
        name="edit_file", permission=PERM_READ, handler="_exec_edit_file",
        description="用 VS Code 或系统默认编辑器打开文件给人看；不修改内容，改内容请用 file_write",
        parameters=_obj({"path": {"type": "string"}}, ["path"]),
        example='{"tool":"edit_file","path":"main.py"}',
    ),
    ToolSpec(
        name="plan_propose", permission=PERM_READ, control=True,
        description="复杂任务先输出分步计划，等待用户批准后再执行",
        parameters=_obj({"title": {"type": "string"},
                         "steps": {"type": "array", "items": {"type": "string"}}},
                        ["steps"]),
        example='{"tool":"plan_propose","title":"任务","steps":["步骤1","步骤2"]}',
    ),
    ToolSpec(
        name="request_permission", permission=PERM_READ, control=True,
        description="请求用户临时授权某个工具（如被 403 拦截的写入/高权限操作）",
        parameters=_obj({"target": {"type": "string"}, "reason": {"type": "string"}}, ["target"]),
        example='{"tool":"request_permission","target":"terminal_exec","reason":"原因"}',
    ),

    # —— 写入 ——
    ToolSpec(
        name="terminal_exec", permission=PERM_WRITE, handler="_exec_terminal_exec",
        description="执行修改性 shell 命令（写入权限，自动快照；每次执行都需用户确认）",
        parameters=_obj({"command": {"type": "string"}}, ["command"]),
        example='{"tool":"terminal_exec","command":"mkdir test"}',
        confirm=True,
    ),
    ToolSpec(
        name="str_replace", permission=PERM_WRITE, handler="_exec_str_replace",
        description="局部替换文件片段（首选的改代码方式，不要整文件覆盖）。old_string 必须唯一，"
                    "匹配到多处会报 409 且不写入——按提示补足上下文后重试，或传 replace_all=true",
        parameters=_obj({"path": {"type": "string"},
                         "old_string": {"type": "string",
                                        "description": "要被替换的原文片段，建议带前后 3-5 行上下文以保证唯一"},
                         "new_string": {"type": "string",
                                        "description": "替换后的内容；传空串或省略 = 删除该片段"},
                         "replace_all": {"type": "boolean",
                                         "description": "true 时替换全部匹配（默认 false，多匹配直接报错）"}},
                        ["path", "old_string", "new_string"]),
        example='{"tool":"str_replace","path":"a.py","old_string":"def old():\\n    pass",'
                '"new_string":"def new():\\n    return 1"}',
    ),
    ToolSpec(
        name="file_write", permission=PERM_WRITE, handler="_exec_file_ops", pass_tool_name=True,
        description="写入/覆盖整个文件（执行层自动快照）。新建文件用它；改已有文件请用 str_replace",
        parameters=_obj({"path": {"type": "string"}, "content": {"type": "string"}},
                        ["path", "content"]),
        example='{"tool":"file_write","path":"out.txt","content":"hello"}',
    ),

    ToolSpec(
        name="file_delete", permission=PERM_WRITE, handler="_exec_file_ops", pass_tool_name=True,
        description="删除文件（执行层自动快照）",
        parameters=_obj({"path": {"type": "string"}}, ["path"]),
        example='{"tool":"file_delete","path":"old.txt"}',
    ),
    ToolSpec(
        name="file_move", permission=PERM_WRITE, handler="_exec_file_ops", pass_tool_name=True,
        description="移动/重命名文件",
        parameters=_obj({"source": {"type": "string"}, "dest": {"type": "string"}},
                        ["source", "dest"]),
        example='{"tool":"file_move","source":"a.txt","dest":"b.txt"}',
    ),
    ToolSpec(
        name="api_post", permission=PERM_WRITE, handler="_exec_api_post",
        description="POST 请求提交数据",
        parameters=_obj({"url": {"type": "string"}, "data": {"type": "object"}}, ["url"]),
        example='{"tool":"api_post","url":"https://example.com","data":{"key":"value"}}',
    ),
    ToolSpec(
        name="code_execute", permission=PERM_WRITE, handler="_exec_code_execute",
        description="在受限沙盒中执行 Python 代码（禁止 os/subprocess/socket 等危险调用）",
        parameters=_obj({"language": {"type": "string"}, "code": {"type": "string"}},
                        ["language", "code"]),
        example='{"tool":"code_execute","language":"python","code":"print(1)"}',
    ),
    ToolSpec(
        name="browser_click", permission=PERM_WRITE, handler="_exec_browser_click",
        description="点击页面元素（未实现）", expose=False,
        parameters=_obj({"selector": {"type": "string"}}, ["selector"]),
    ),
    ToolSpec(
        name="browser_type", permission=PERM_WRITE, handler="_exec_browser_type",
        description="在页面元素中输入文本（未实现）", expose=False,
        parameters=_obj({"selector": {"type": "string"}, "text": {"type": "string"}},
                        ["selector", "text"]),
    ),
    ToolSpec(
        name="db_write", permission=PERM_WRITE, handler="_exec_db_write",
        description="SQLite 写入（INSERT/UPDATE/DELETE/CREATE/ALTER，拒绝 DROP 等）",
        parameters=_obj({"query": {"type": "string"}}, ["query"]),
        example='{"tool":"db_write","query":"INSERT INTO t (name) VALUES (\'x\')"}',
    ),
    ToolSpec(
        name="notify_send", permission=PERM_WRITE, handler="_exec_notify_send",
        description="发送通知（console/file/toast）",
        parameters=_obj({"channel": {"type": "string"}, "to": {"type": "string"},
                         "content": {"type": "string"}}, ["channel", "content"]),
        example='{"tool":"notify_send","channel":"console","content":"hello"}',
    ),
    ToolSpec(
        name="image_generate", permission=PERM_WRITE, handler="_exec_image_generate",
        description="生成图片保存到 .ace_images/（pollinations.ai 免费）",
        parameters=_obj({"prompt": {"type": "string"}, "size": {"type": "string"}}, ["prompt"]),
        example='{"tool":"image_generate","prompt":"a cat","size":"512x512"}',
    ),

    # —— 目标状态机（持久化长任务：goal_create / goal_update / goal_status） ——
    ToolSpec(
        name="goal_create", permission=PERM_READ, handler="_exec_goal_create",
        description="创建持久化目标：长任务自动逐轮续跑，直到完成/暂停/阻塞或轮次预算耗尽。"
                    "objective 写清最终交付物；max_rounds 默认 20",
        parameters=_obj({"objective": {"type": "string"},
                         "max_rounds": {"type": "integer"}}, ["objective"]),
        example='{"tool":"goal_create","objective":"实现登录模块并跑通测试","max_rounds":10}',
    ),
    ToolSpec(
        name="goal_update", permission=PERM_READ, handler="_exec_goal_update",
        description="更新目标状态（phase: active/paused/blocked/complete）。"
                    "必须携带当前 revision（用 goal_status 查）。"
                    "自报 blocked 必须给机器 code（missing_dependency/api_unavailable/"
                    "permission_blocked/invalid_input/environment_broken）与人类说明；"
                    "难度/不确定不算阻塞",
        parameters=_obj({"id": {"type": "string"}, "revision": {"type": "integer"},
                         "phase": {"type": "string"},
                         "reason_code": {"type": "string"},
                         "reason_message": {"type": "string"}},
                        ["id", "revision", "phase"]),
        example='{"tool":"goal_update","id":"...","revision":3,'
                '"phase":"blocked","reason_code":"api_unavailable",'
                '"reason_message":"DeepSeek API 401，等待用户换 key"}',
    ),
    ToolSpec(
        name="goal_status", permission=PERM_READ, handler="_exec_goal_status",
        description="查询当前目标状态（含 revision，更新前必查）",
        parameters=_obj({}),
        example='{"tool":"goal_status"}',
    ),

    # —— 高危：已登记但未实现，需 full 权限（占位，防止名字被误当未知工具而静默通过分级）——
    ToolSpec(name="terminal_dangerous", permission=PERM_HIGH_RISK,
             description="高危终端操作（未实现，需 full 权限）", expose=False),
    ToolSpec(name="db_drop", permission=PERM_HIGH_RISK,
             description="删除数据库表/库（未实现，需 full 权限）", expose=False),
]


# ============================================================
# 派生视图：三处硬编码统一从这里取
# ============================================================

SPEC_BY_NAME: Dict[str, ToolSpec] = {s.name: s for s in TOOL_SPECS}


def register(spec: ToolSpec, replace: bool = False) -> None:
    """运行时注册工具（MCP / 插件接入点）。

    注意：调用方需自行保证 handler 方法已挂到 ToolExecutor 上，
    并在注册后刷新 execution_layer 的权限集合（见 execution_layer.refresh_tool_sets）。
    """
    if spec.name in SPEC_BY_NAME and not replace:
        raise ValueError(f"工具已注册: {spec.name}（如需覆盖请传 replace=True）")
    if spec.name in SPEC_BY_NAME:
        TOOL_SPECS[:] = [s for s in TOOL_SPECS if s.name != spec.name]
    TOOL_SPECS.append(spec)
    SPEC_BY_NAME[spec.name] = spec


def names_with_permission(permission: str) -> set:
    return {s.name for s in TOOL_SPECS if s.permission == permission}


def control_tool_names() -> set:
    return {s.name for s in TOOL_SPECS if s.control}


def confirm_tool_names() -> set:
    """每次调用都需用户确认的工具（权限等级放行也不例外）"""
    return {s.name for s in TOOL_SPECS if s.confirm}


def tool_examples() -> Dict[str, str]:
    return {s.name: s.example for s in TOOL_SPECS if s.example}


def openai_tools() -> List[Dict]:
    """生成 OpenAI 兼容 function calling 的 tools 数组。

    `parameters` 深拷贝出去：ToolSpec 是 frozen dataclass，但 frozen 只冻住字段绑定，
    冻不住字段指向的那个 dict。不拷贝的话，调用方随手改一下返回的 schema
    （补个字段、删个 required）就改到了注册表本体，而且是全进程可见 —— 这种改动
    没有任何一处看起来像在改注册表。
    """
    from copy import deepcopy
    return [{"type": "function",
             "function": {"name": s.name,
                          "description": s.description,
                          "parameters": deepcopy(s.parameters)}}
            for s in TOOL_SPECS if s.expose]

