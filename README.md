# ai angent —— 沙盒 AI Agent 执行层

> 把 `agent_system_prompt_v7` 里承诺的系统全部落地实现。

## 模块清单

| 文件 | 职责 | 状态 |
|---|---|---|
| `gateway_v2.py` | L1-L5 五层网关：意图识别 / Skill 推荐 / 模型适配 / 本能守门(8 规则) / 反馈飞轮 | ✅ |
| `work.py` | 诱饵工厂 BaitFactory（5 种语义诱饵）+ ASTDetector（6 规则行为检测）+ BehaviorConstraint | ✅ |
| `guardian.py` | 物理快照回滚：写入前自动快照、完整性预检、备份→恢复→验证→清理 | ✅ |
| `Archive.py` | SimHash 记忆引擎：主题切换检测（阈值 0.25）、短输入保护、催促词加权、记忆注入 | ✅ |
| `Nuwa.py` | POC 报告生成：通过率/平均响应/回滚计数，HTML + JSON 双格式 | ✅ |
| `universal_document_parser.py` | N 合一文档解析（Word/Excel/PPT/PDF/OCR/纯文本），懒加载 + 截断 | ✅ |
| `execution_layer.py` | 主入口：解析 INTERNAL/EXTERNAL、权限裁决、工具执行、安全闸门串联 | ✅ |
| `agent_runner.py` | 交互循环：LLM ↔ 执行层多轮闭环，错误自动回喂模型修正 | ✅ |
| `ai_code.py` | AI Code 命令行：流式输出 / 斜杠命令 / 复用本机已有模型配置 | ✅ |
| `test_all.py` | 全模块端到端测试（148 项，纯 stdlib） | ✅ |

## 快速开始

```bash
# 跑全部测试
python test_all.py

# AI Code（ACE）命令行 —— cmd 里敲 ace 随时唤醒
ace                             # 默认进入登录页（首页菜单：logo + ❯ 光标，↑/↓ 选择 · 数字直选）
ace --mock                      # 离线演示直接进聊天，无需密钥
ace --input "现在几点了"         # 单次对话
python ai_code.py               # 或直接用 python 跑

# 首次使用：首页选 2「配置向导」（提供商 → API Key → 模型），之后选 1「进入聊天」
# 指定自己的模型
python ai_code.py --base-url https://api.deepseek.com/v1 --api-key sk-xxx --model deepseek-chat

# 查看执行层状态
python execution_layer.py --stats
```

CLI 斜杠命令（**按下 `/` 实时弹出菜单，边打字边过滤**；唯一匹配回车直接执行）：
`/help` `/clear` `/status` `/stats` `/memory` `/snapshots` `/undo` `/rollback <id>` `/report` `/permission [level]` `/model` `/provider` `/config` `/open <路径>` `/edit <路径>` `/exit`

**切换 API Key / AI 提供商（一键）**：
```
/provider                       # 列出 10 家提供商（当前标 ✓）
/provider zhipu                 # 一键切智谱（自动换到 glm-4.7-flash 并保存）
/provider 3 sk-你的key          # 按编号切 DeepSeek + 同时设置密钥
/provider deepseek sk-xxx       # 按 id 切换同理
/config                         # 三步向导：选提供商 → 隐藏输入 key → 选模型
```

内置提供商注册表（参考本机 `cli/AI-CLI-安装平台/lib/api.js`，模型名 2026-08 调研）：
智谱 GLM（Anthropic/OpenAI 双端点，含免费开源的 **glm-4.7-flash**）、DeepSeek、Kimi/Moonshot、OpenAI、Anthropic Claude、通义 Qwen、硅基流动、OpenRouter、Ollama 本地。

> 实时自动补全菜单需要 `pip install prompt_toolkit`（Claude Code 同款弹窗交互）；未安装时自动降级为"回车后提示"模式。`/open` `/edit` 后面还有文件路径补全。

**在终端里直接打开文件**（编辑器无关，任何裸终端可用）：
```
/open 报告.docx      # 用系统默认程序打开（Word/记事本/看图器…）
/edit main.py        # 优先用 VS Code 打开（找不到 code 命令则回退默认程序）
/edit 新文件.txt     # 文件不存在时自动创建再打开
```

**自定义模型**（都会保存到 `~/.ai_code.json`，下次启动自动生效）：
```
/model                        # 查看当前配置
/model deepseek-chat          # 切换模型名
/model base-url https://...    # 设置 API 地址（自动识别 OpenAI/Anthropic 格式）
/model api-key sk-xxx         # 设置密钥（显示时自动打码）
/config                       # 交互式配置向导
```

**无感安全体验**：写入操作前自动快照（上限 20 自动清理）、结果行显示耗时与"已自动快照，/undo 一键回滚"、`/undo` 无需记快照 id 一键回到最近状态、主题切换时自动注入相关记忆。

配置优先级：命令行参数 > `~/.ai_code.json` > `~/.claude/settings.json`（本机已有模型配置）> 环境变量。API 格式自动识别：`/anthropic` 端点走 Anthropic Messages 格式，其余走 OpenAI 兼容格式。

## 安全设计（多轮审查后加固）

- `terminal_view` 白名单只读命令（内建实现 + 元字符拦截 + 版本参数严格校验），readonly 不再能执行任意 shell
- `code_execute` 策略层沙箱：AST 拦截危险模块（os/subprocess/socket/pickle/importlib...）、内建逃逸（`__builtins__`/`__class__` 链）、open 全禁 → 环境变量清洗 → 临时目录 + 30s 超时
- `math_calc` 白名单 AST 求值：仅允许纯算术，幂运算限 100^1000，杜绝 eval 逃逸与指数 DoS
- 路径穿越防护：文件工具与 ls/cat 默认强制限制在项目目录内（`confine_files`）
- `api_get/api_post` 仅允许 http/https 协议（防 SSRF）
- 快照支持 HMAC-SHA256 签名（`signing_key` 配置项），防元信息伪造
- 诱饵验证循环：首次 code_execute 自动注入语义诱饵 → 修复后重提；按任务隔离，不跨任务泄漏
- AST 熔断：未用导入/类型注解/无限递归/循环引用/硬编码密钥/SQL 注入（收敛为真实注入模式，不误伤正常递归/f-string）
- 守门分层：block 级规则拦截并回滚本轮快照；warn 级规则不阻断；读文件/最终回复只过文本规则
- 未实现的工具返回 501 而非假成功；临时授权单次有效（用后即焚）
- 快照回滚仅回滚本轮快照，防止回滚到过期快照破坏无关修改

> ⚠️ 生产部署注意：`code_execute`/`terminal_exec` 是进程内策略层沙箱，非 OS 级隔离。生产环境建议：容器/虚拟机运行、readonly 起步按需授权、`signing_key` 置于项目目录之外。

## 配置项

```python
config = {
    "flywheel_path": ".../violations.jsonl",   # L5 飞轮落盘路径
    "sandbox_base": "...",                     # code_execute 沙箱临时目录（默认系统临时区）
    "confine_files": True,                     # 文件工具强制限制在项目目录内（含跨盘符检查）
    "signing_key": "你的签名密钥",              # Guardian 快照 HMAC 签名（生产建议配置）
    "max_snapshots": 20,                       # 快照数量硬上限，超出自动清理最旧的（防备份爆炸）
    "session_id": "会话标识",                   # Archive 记忆按会话隔离（多会话互不污染）
    "bait": {
        "enabled": True,    # 是否启用诱饵验证
        "frequency": 0,     # 0 = 每任务仅验证一次；N = 每 N 次成功执行后再次验证
    },
    "guard": {"rules": {"no_hardcoded_secrets": False}},  # 关闭某条守门规则
    "model_callback": fn,   # L3 接入你自己的 LLM（或 base_url + api_key）
}
```

> 文档解析器内置 `MAX_FILE_SIZE = 50MB` 大文件防线（`universal_document_parser.py`），超限直接拒绝，防止解析器内存爆炸。

## 运行环境

- **Python ≥ 3.10**（使用了 `int.bit_count`；建议 3.11/3.12）
- 核心零依赖；接真实模型需 `pip install requests`
- 文档解析增强按需安装：见 `requirements.txt` 注释（python-docx / openpyxl / pdfplumber / pymupdf / pytesseract 等）
- 旧版 Office 格式（.doc/.xls/.ppt/.wps/.et）回退依赖系统级 LibreOffice / antiword
- Windows GBK 控制台已做 UTF-8 兜底；建议全局 `PYTHONUTF8=1`
