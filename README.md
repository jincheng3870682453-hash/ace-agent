<p align="center">
  <img src="assets/logo.svg" alt="ACE logo" width="88" height="88">
</p>

<h1 align="center">ACE · AI Code Engine</h1>


<p align="center">
  <strong>一个把安全下沉到执行层的 AI 编码 Agent —— 模型只负责理解和输出，<br>
  权限、沙箱、快照回滚全部由执行层裁决。</strong>
</p>

<p align="center">
  <a href="https://github.com/jincheng3870682453-hash/ace-agent/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/jincheng3870682453-hash/ace-agent/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="Python" src="https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue">
  <img alt="Dependencies" src="https://img.shields.io/badge/core%20deps-zero-orange">
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-MIT-blue"></a>
</p>

<p align="center">
  <img src="demo/demo.svg" alt="ACE 终端会话演示：提问 → 调用工具 → 作答 → 查状态 → 降权限" width="820">
</p>

<p align="center">
  <sub>上图是 <code>python ai_code.py --mock</code> 的真实会话录制（离线、无需密钥），
  用 <a href="demo/record_demo.py"><code>demo/record_demo.py</code></a> 可随时重录。</sub>
</p>

大多数 Agent 把安全交给提示词："请不要删除文件"。ACE 不这么做：模型的每一次工具调用都要穿过一个独立的执行层，由它做权限裁决、危险行为检测、写入前快照。提示词失效时，执行层仍然拦得住。

配套一个 Claude Code 风格的终端：登录页、`/` 实时补全、10 家模型提供商一键切换、流式输出。核心零第三方依赖。

## 目录

- [快速开始](#快速开始)
- [设计取向](#设计取向)
- [核心能力](#核心能力)
- [架构](#架构)
- [命令参考](#命令参考)
- [安全模型](#安全模型)
- [配置](#配置)
- [项目结构](#项目结构)
- [开发与测试](#开发与测试)
- [许可](#许可)
- [设计参考](#设计参考)

## 快速开始

**前置**：Python ≥ 3.10（用到 `int.bit_count`，建议 3.11/3.12）。核心不需要装任何第三方包。

```bash
git clone https://github.com/jincheng3870682453-hash/ace-agent.git
cd ace-agent
python test_all.py          # 端到端测试，纯 stdlib，应当全绿
```


不配密钥先看效果：

```bash
python ai_code.py --mock    # 离线演示，完整跑一遍 模型↔执行层 闭环
```

接真实模型：启动后在首页选 `2` 走配置向导（① 选提供商 → ② 隐藏输入 API Key → ③ 选模型），再选 `1` 进聊天。

```bash
python ai_code.py                    # 首页菜单
python ai_code.py --input "现在几点"  # 单次对话，跑完即退
```

Windows 上项目目录已带 `ace.cmd`，加入 PATH 后可在任意目录直接敲 `ace`。

<details>
<summary>其他启动方式（本地 Ollama / 原生 function calling / 容器）</summary>

```bash
ace --tools                     # 原生工具调用（OpenAI 兼容 function calling，不支持时自动降级到文本协议）
ace --max-history 12            # 只保留最近 12 轮，防止本地小模型上下文溢出
ace --context-window 8192       # 告诉 ACE 模型窗口有多大（压缩阈值按它算，默认 32768）
ace --no-compact                # 关掉上下文压缩，退回纯硬截断

ace --install-ui                # 装 / 补全 prompt_toolkit（多镜像自动回退）

# 沙箱（真实内核边界，缺一不可的隔离档）：
ace --sandbox job               # Windows Job Object：进程树/内存/进程数上限（需先在 executor/ 下 go build）
ace --sandbox docker            # 一次性容器：--network none + 只挂工作目录（需 Docker + 构建 ace-sandbox 镜像）
                                # job/docker 都不做静默回退：拿不到边界直接报错

# 自定义外挂知识库（kb_search/kb_add/kb_list，跨会话持久）：
ace --kb D:\我的资料库          # 外挂你的资料目录；不指定则用项目 .ace_kb/

# 本地 Ollama（Qwen 支持原生工具调用）
python agent_runner.py --base-url http://localhost:11434/v1 --api-key ollama \
       --model qwen2.5-coder:7b --tools

# 容器：根目录 Dockerfile 是最小可跑镜像（默认 --mock）
docker compose up               # ACE + Ollama 编排
```

`docker/` 下另有 lite / standard / full 三档镜像与模型下载脚本，说明见 [`docker/README-Docker.md`](docker/README-Docker.md)。

</details>

## 设计取向

三条贯穿全项目的决定，先说清楚，免得你读代码时觉得奇怪：

**安全属于执行层，不属于提示词。** 权限裁决、危险命令拦截、写入前快照都在 `execution_layer.py` 里，与模型无关。换模型、模型被越狱、提示词被覆盖，这层都还在。

**默认只读。** 起步权限是 `readonly`，写工具会被 403 拦下。模型可以申请授权（`request_permission`），由用户选「本次」或「本会话」。`terminal_exec` 例外：它只接受逐次确认，因为它的危险命令黑名单本身可被绕过，「人看一眼命令」是它唯一有效的防线。

**边界要说清能挡什么、挡不住什么。** 不开沙箱时，`code_execute` 是进程内策略层沙箱、`terminal_exec` 的判定层只是止血层——两者都不是 OS 级隔离。要真正的内核边界就开 `--sandbox docker`（容器）或 `--sandbox job`（Windows Job Object），见[安全模型](#安全模型)。



## 核心能力

| 能力 | 说明 |
|---|---|
| 三级权限裁决 | `readonly` / `write` / `full`，工具与权限组在 `tools/registry.py` 单点声明，schema 与权限集合全部由它派生 |
| 按权限裁剪工具表 | 发给模型的工具列表随权限档位裁剪（readonly 只给 16 个只读+控制工具）——模型只在真实可用的工具里决策，小模型不再为"看得见用不了"的写工具分心 |
| **三层沙箱** | `off`（Python 层策略校验）/ `job`（Windows Job Object：进程树/内存/进程数上限 + 受限令牌）/ `docker`（一次性容器：network none + 只挂工作目录 + cap-drop ALL）。job/docker 都不做静默回退 |
| **Go 执行器** | `terminal_exec` / `code_execute` 委派给独立 Go 进程（NDJSON 协议），Job Object 整树回收 + 第二道策略复检 |
| **持久目标（goal）** | `goal_create` 建目标后**自动逐轮续跑**直到完成/暂停/阻塞/预算耗尽；revision CAS 防旧状态覆盖；blocked 须给机器 code（难度不算阻塞）；重启后须 `/goal resume` 才续 |
| **子代理** | `subagent` 把子任务交给独立上下文的模型会话（spawn 全新 / fork 继承父会话），拥有自己的工具执行循环（最多 8 轮），结果回传父代理整合 |
| **自定义知识库** | `kb_search` / `kb_add` / `kb_list`：检索与写入自己的资料库（`--kb` 外挂目录或项目 `.ace_kb/`），**跨会话持久**——写进知识库的东西下次还能搜到 |
| **联网读取** | `search`（双引擎兜底）+ `search_read`（搜索并抓取 top 结果正文，RAG 式一步拿到可引用内容）；全部出站走 SSRF 校验 + pin-to-IP + 逐跳复检 + 出站白名单 |
| **会话事件日志** | append-only JSONL 全链路：用户输入 → 模型请求/输出 → 工具往返 → 权限裁决 → 快照/回滚 → 守卫违规，`/audit` 查看；**重启自动恢复上次会话**（消息历史 = 日志派生） |
| 写入前物理快照 | 每次写操作前自动快照，`/undo` 一键回滚；HMAC 签名防元信息伪造，快照目录自身不可被 Agent 改写 |
| Plan Mode | 复杂任务先提议分步计划（`plan_propose`），用户批准后才放行，杜绝"边想边干" |
| 行为检测闸门 | 诱饵验证（首次 `code_execute` 注入语义诱饵）+ AST 检测（6 规则：无限递归 / 硬编码密钥 / SQL 注入等） |
| 本地代码检索 | `grep` 正则搜内容 + `glob` 找文件 + `file_read` 分段读，只读权限下即可用，不必猜文件名 |
| 局部编辑 | `str_replace` 按片段替换：唯一匹配才写，多匹配报 409 让模型补上下文，缩进以文件真实缩进为准 |
| 审批疲劳缓解 | 确认过的命令**同前缀自动放行**（`pip install` 通过后 `pip install x` 不再问）；`bash -c`/`python -c` 等危险包装永不自动放行；`on_failure` 档在沙箱边界下"先试后问" |
| 浏览器自动化 | `browser_navigate` / `browser_click` / `browser_type`：Playwright 受控页面（系统 Edge/Chrome channel），可点击/输入 |
| 10 家提供商 | 智谱 GLM / DeepSeek / Kimi / OpenAI / Claude / Qwen / 硅基流动 / OpenRouter / Ollama，`/provider` 一键切换 |
| 真实工具全家桶 | 联网搜索（双引擎兜底，无需 Key）、SQLite 读写、文档解析（Word/Excel/PPT/PDF/OCR）、浏览器、截图、通知、图像生成 |
| SimHash 记忆 | 主题切换时预注入相关历史，按会话隔离 |
| AGENTS.md 项目指令 | 项目根的约定文件（AGENTS.md/CLAUDE.md）自动发现并注入系统提示（32 KiB 预算、会话缓存）——项目所有者的规则，模型不再猜 |
| 上下文压缩 | 历史逼近窗口时把中间段折成摘要，**第一条用户消息永不丢弃**；摘要失败退回硬截断并明确告知，不静默失忆 |
| 网络退避 | 429 / 5xx / 连接抖动自动退避重试（认 `Retry-After`，含 HTTP-date 形式），与 tools 协议降级分层，一次限流不会把工具关掉 |
| i18n | zh / en / ja，`@lang` 同时切换模型回复语言与界面语言 |

## 架构

```mermaid
flowchart TB
    subgraph 用户层["用户层"]
        U["用户 / 终端"]
    end
    subgraph ACE["命令行（ai_code.py）"]
        L["登录页 / 首页菜单"]
        R["聊天 REPL<br/>/ 实时补全 · 流式输出"]
        P["提供商注册表<br/>10 家 · 一键切换"]
    end
    subgraph LOOP["交互循环（agent_runner.py）"]
        C["模型 ↔ 执行层 多轮闭环<br/>错误自动回喂修正"]
    end
    subgraph GW["网关（gateway_v2/）"]
        L1["L1 意图识别"]
        L2["L2 Skill 推荐"]
        L4["L4 本能守门 · 8 规则"]
        L5["L5 反馈飞轮（SFT 数据）"]
    end
    subgraph EL["执行层（execution_layer.py）"]
        PARSE["INTERNAL/EXTERNAL 协议解析"]
        PERM["三级权限裁决"]
        GATE["诱饵验证 + AST 闸门"]
        EXEC["工具执行器"]
    end
    subgraph TOOLS["工具集（tools/）"]
        T1["file_* / grep / glob<br/>terminal_view 白名单"]
        T2["code_execute 沙箱"]
        T3["math_calc / api_* / db_*"]
        T4["parse_document"]
    end
    subgraph SUPPORT["支撑模块"]
        W["work.py<br/>诱饵 + AST 检测"]
        G["guardian.py<br/>物理快照回滚"]
        A["Archive.py<br/>SimHash 记忆"]
        N["Nuwa.py<br/>POC 报告"]
    end

    U --> L
    L -->|进入聊天| R
    L -->|配置 / 切提供商| P
    R --> C
    C --> L1
    C --> PARSE
    PARSE --> PERM
    PERM --> GATE
    GATE --> EXEC
    EXEC --> T1 & T2 & T3 & T4
    T2 -.-> W
    EXEC -.-> L4
    L4 -.-> L5
    EXEC -.-> G
    C -.-> A
    EXEC -.-> N
```

| 层 | 组件 | 职责 |
|---|---|---|
| 用户层 | `ai_code.py` | 登录页、聊天 REPL、斜杠命令、提供商切换（纯终端，编辑器无关） |
| 交互循环 | `agent_runner.py` | 模型 ↔ 执行层多轮闭环；格式错误 / 守门 / 诱饵自动回喂修正，最多 20 轮 |
| 模型网关 | `gateway_v2/` | L1 意图 → L2 技能 → L4 守门（8 规则）→ L5 飞轮 |
| 执行层 | `execution_layer.py` | 协议解析、权限裁决、安全闸门、快照与守门串联 |
| 工具集 | `tools/` | `registry` 单点声明 + 按域拆分的执行器 |
| 支撑模块 | `work.py` `guardian.py` `Archive.py` `Nuwa.py` | 行为检测、快照回滚、记忆、报告 |

详细架构决策（为什么用 SimHash、为什么双层协议、为什么坚持零依赖）见 [`docs/ADR.md`](docs/ADR.md)。

## 命令参考

**首页**：↑/↓ 选择 · 数字直选 · Enter 确认 · Esc/q 退出。聊天内 `exit` 回首页，首页 `7`/`Esc`/`q` 才真正退出。

**斜杠命令**（聊天里输入 `/` 实时弹菜单，需 `prompt_toolkit`，未装自动降级）：

| 分类 | 命令 |
|---|---|
| 会话 | `/help` `/clear` `/status` `/stats` `/exit` |
| 安全 | `/permission [level]` `/snapshots` `/undo` `/rollback <id>` |
| 模型 | `/provider [名称\|编号] [key]` `/model <名称>` `/config` `/mock` |
| 工具 | `/open <路径>` `/edit <路径>` `/search <关键词>` `/memory` `/report` |

```bash
/provider                   # 列出 10 家提供商（当前标 ✓）
/provider zhipu             # 一键切智谱（自动换到 glm-4.7-flash）
/provider 3 sk-你的key      # 编号 + 密钥一把梭
```

**@ 快捷方式**（输入 `@` 弹菜单）：

| 命令 | 作用 | 示例 |
|---|---|---|
| `@lang` | 切换回复语言 + 界面语言（zh/en/ja） | `@lang en` |
| `@skill` | 切换技能，描述与推荐工具注入提示词 | `@skill coding` |
| `@file` | 把文件内容加入上下文（≤4000 字符自动截断） | `@file README.md` |
| `@folder` | 把文件夹列表加入上下文（≤30 项） | `@folder tools` |
| `@refs` / `@clear` | 查看 / 清空当前引用（最多保留 3 项） | `@refs` |

可选技能：`coding`（默认推荐 `code_execute` `file_write` `terminal_exec`）· `writing` · `analysis` · `fiction` · `general`。

**在对话里打开文件**——默认只给可点击链接，不抢焦点、不弹窗：

```
（自己动手）  ❯ /open 报告.docx        # 系统默认程序打开
              ❯ /edit main.py          # 优先 VS Code
（叫 Agent）  ❯ 帮我打开桌面的报告.docx
              🔗 点击打开文件: C:\Users\...\报告.docx   ← 点一下才展开
```

## 安全模型

配置优先级：命令行参数 > `~/.ai_code.json` > `~/.claude/settings.json` > 环境变量。

**权限与授权**

- 默认 `readonly`；写工具需显式 `/permission write` 或 `--permission write`
- 授权两档：「本次」用后即焚，「本会话」本会话内不再询问
- `terminal_exec` 强制逐次确认，不接受会话级授权
- 非交互模式（非 tty）下一切授权请求与计划审批都 fail-close 拒绝

**执行隔离**

- `terminal_view`：白名单只读命令，内建实现不经 shell，拦 shell 元字符，版本参数严格校验
- `code_execute`：AST 拦危险模块（os/subprocess/socket/pickle/importlib…）与内建逃逸链（`__builtins__`/`__class__`）、`open` 全禁 → 环境变量清洗 → 临时目录 + 30s 超时
- `math_calc`：白名单 AST 求值，仅纯算术，幂运算限 100^1000，杜绝 eval 逃逸与指数 DoS

**路径边界**

- 文件工具默认限制在项目目录内（`confine_files`，含跨盘符检查）；`grep`/`glob` 无条件限项目内，只读检索也不放开项目外
- 读越界按"泄露什么"分档：**读文件内容一律限项目内**（`cat`/`type`、外部命令路径参数、`file_read` 均 403）；**列目录名单允许越界**（`ls`/`dir`）。前者泄露的是凭据本身，后者只是文件名
- 敏感目标硬拦截：绝对路径写入放行（"放到桌面"）但不含凭据与自启动入口（`~/.ssh`、`~/.bashrc`、`~/.ai_code.json`、`.pem`/`.key` 等）

**回滚与网络**

- 写入前自动快照，快照元信息可用 `signing_key` 做 HMAC-SHA256 签名；快照数量有硬上限，自动清理最旧
- `.guardian/` 快照目录对所有工具只读且不可写删——它就在 Agent 可写的项目目录里，不挡住的话改一行 `meta.json` 就能让熔断回滚静默失效；回滚失败会告警而不是静默吞掉
- 守门分层：block 级拦截并回滚本轮快照，warn 级不阻断；只回滚本轮，不动无关修改
- `api_get`/`api_post` 仅 http/https，且 **DNS 解析后**拦截内网 / 回环 / 链路本地地址（防 SSRF）；未实现的工具返回 501 而非假成功

**容器隔离（`--sandbox docker`）**

上面所有校验都是进程内的 Python 逻辑。`terminal_exec` 是 `shell=True`，cwd 固定在项目根挡不住 `cd /`；`code_execute` 的 AST 黑名单也不可能枚举完。真正的边界要靠内核：

```bash
docker build -t ace-sandbox:latest -f docker/Dockerfile.sandbox .
python ai_code.py --sandbox docker
```

开启后 `terminal_exec` / `code_execute` 的每次调用都是一个一次性容器：`--network none`（凭据出不去、也下载不了第二阶段载荷）、`--read-only` + `--tmpfs /tmp`、`--cap-drop ALL` + `no-new-privileges`、内存与 `--pids-limit` 上限（fork bomb 变成容器自己的事）、只挂工作目录到 `/work`、`--rm` 跑完即销毁。其余工具仍在宿主，所以"在桌面建个文件"这类请求照常能做。

两点要知道：容器共享内核，容器逃逸漏洞仍然是逃逸，更强的边界得上虚拟机；**开了沙箱但 Docker 不可用时直接返回 503，不会静默回退宿主执行**——回退会让你以为命令跑在容器里而实际跑在自己机器上。

镜像必须自己 build，它不会发布到任何 registry：它就是执行边界，里面装了什么得由部署方掌握。所以"镜像没构建"是单独判、单独报的一档 503，直接把上面那条 `docker build` 给你——而不是让 `docker run` 去 registry 找 `ace-sandbox`，先等一个网络超时、再回一句 `pull access denied` 让你以为是要登录。


**Job Object 隔离（`--sandbox job`，Windows）**

Docker 没装、或者装了但不想为一条 `dir` 起容器时，还有一档更轻的边界。它由 `executor/` 下的 Go 执行器提供，是项目里唯一需要编译的部分：

```bash
cd executor && go build -o ace-executor.exe .   # 非 Windows 去掉 .exe
python ai_code.py --sandbox job
```

命令会跑在一个 Windows Job Object 里：内存与子进程数上限、限制性令牌 + 中等完整性级别、退出时整棵进程树一起回收。最后那条是宿主直跑做不到的——Python 的 `Process.kill()` 只杀直接子进程，孙进程会变孤儿留在后台。

`terminal_exec` 与 `code_execute` 都走这条边界（代码片段经 `exec_python`：临时文件落盘、`-I -B` 隔离运行，源码不经命令行避免 32K 上限与引号改写）。

执行器同时是第二道判定闸：宿主已经判过的 `policy_decision` 会在独立进程里再检一次，宿主侧写错一处逻辑时它还拦得住。

与 docker 档同样的原则：**二进制没编译、本平台不支持 Tier-1、或隔离只部分生效，都返回 503**，不会偷偷改回宿主执行。`--sandbox off`（默认）下执行器若存在会顺带用一下（只为拿进程树回收），起不来则静默回落宿主——这一档本来就没承诺任何边界。设 `ACE_USE_GO_EXECUTOR=0` 可完全关掉这个可选增强。

> **生产部署必读**：不开 `--sandbox docker` 时，`code_execute` 与 `terminal_exec` 只是进程内策略层，**不是 OS 级隔离**，`python -c` 一类等价路径无法靠枚举封死。生产环境还应配合：低权限账户运行、按需授权而非常开 `write`、`signing_key` 置于项目目录之外。



## 配置

```python
config = {
    "flywheel_path": ".../violations.jsonl",   # L5 飞轮落盘路径
    "sandbox_base": "...",                     # code_execute 沙箱临时目录（默认系统临时区）
    "confine_files": True,                     # 文件工具限制在项目目录内（含跨盘符检查）
    "signing_key": "你的签名密钥",              # Guardian 快照 HMAC 签名（生产建议）
    "max_snapshots": 20,                       # 快照硬上限，自动清理最旧
    "session_id": "会话标识",                   # Archive 记忆按会话隔离
    "bait": {"enabled": True, "frequency": 0}, # 诱饵验证（0 = 每任务一次）
    "guard": {"rules": {"no_hardcoded_secrets": False}},  # 关闭某条守门规则
    "email_smtp": {"host": "smtp.qq.com", "port": 587,
                   "user": "you@qq.com", "password": "授权码",
                   "use_tls": True},           # notify_send email 渠道（缺省时返回 501）
    "egress_allowlist": ["api.github.com", ".openai.com"],  # 出站目的地白名单（缺省 = 闸门关闭）
}
```

### 出站白名单（`egress_allowlist`）

内网判定（`ace_net`）管的是"别打到内网去"，白名单管的是"能把数据带到哪个公网站点去"。后者只有宿主知道哪些站点算正当，所以**默认关闭**：不配这个键，`api_get` / `api_post` / `browser_open` / `web_search` 的行为和以前完全一样。

配上之后：

- **是并集，不是覆盖**：配置的条目会自动并上内置端点（搜索引擎等）。否则配置白名单的第一个可见后果就是搜索坏掉，而用户会把这读成"功能有 bug"，删掉清单——闸门也就没了。
- **逐跳复检**：清单内主机完全可以 `302` 到 `evil.tld`，而第一跳的判定是对的。所以每一跳都重新过清单，中途跳出清单直接掐断连接。
- **403 而不是 400/500**：这是授权问题。同一个地址重试不会变，只有人能把域名加进清单。返回消息里就这么写给模型看，免得它反复重试或改写 URL 试探。
- `browser_open` 也过清单。连接交给系统浏览器之后就不经过本进程（拦不住浏览器自己跟的重定向），但"要不要把这个域名交出去"这个决定本进程还能做。
- 条目写法宽松：`api.github.com`、`.github.com`（含子域）、`https://api.github.com/x`（只取主机）都认。匹配按标签边界，`evil-github.com` 不会命中 `github.com`。
- **`notify_send` 的 SMTP 也归它管**：那条路直连 `smtplib`，主机来自宿主配置而非模型参数（所以不是 SSRF 面），但正文和收件人是模型给的 —— 是实打实的外发通道，所以走同一份清单。

### 检索工具的边界（`grep` / `glob`）

两者属于 `READ_TOOLS`，`readonly` 会话就能调，所以约束不能只管起点：

- `glob` 的 `pattern` 里出现 `..` 直接 **403**，不是"复检后静静丢掉"。丢掉的话模型看到的是"没匹配"，它会换个写法再试。
- 每条命中都在**解析软链接之后**重新确认落点。项目里一个指向 `~/.ssh/id_rsa` 的软链接，`os.walk` 会当普通文件产出。
- 命中还要过 `sensitive_target`：项目内也可能躺着误提交的 `.pem`。
- 遍历文件数撞上限（5000）时回报 `scan_incomplete: true`，与"结果太多"分开报。否则模型会把"没扫完"读成"这个符号不存在"。
- 模型给的正则只在行首 4000 字符上跑。Python 的 `re` 没有超时，灾难性回溯会挂死整个工具调用；限住输入长度不能消除回溯，但能把上界从"行有多长"压到常数。

### `str_replace` 不做有损重编码

读-改-写路径用严格解码（UTF-8 → 系统编码，都失败就 **400 拒绝改写**），并按读进来的那个编码写回。此前是 `errors="ignore"` 解码 + 硬写 UTF-8：一个 GBK 源文件会被静默转码，解码时丢掉的字节永久消失，而模型只看到"替换成功"。

### `db_query` 的只读靠连接，不靠正则

`db_query` 用 `?mode=ro` 的 URI 连接，写入由 SQLite 自己拒绝。SQL 是完整语言，`CREATE TRIGGER`、`INSERT ... SELECT`、CTE 包一层写入、`pragma_table_list` 这类表值函数（`\bpragma\b` 对 `pragma_` 不成立）—— 前缀匹配挡不住的写法列不完。

`db_write` 天生要写，拿不到连接级保护，所以那边仍是黑名单，并且**不闭合**：`DELETE FROM t`（无 WHERE）、`REPLACE INTO`、`CREATE TABLE x AS SELECT` 都在放行范围内。真正的边界是权限档位与 Guardian 快照。两条路都拒绝多语句（分号），因为驱动拒绝多语句时抛的是 `sqlite3.Warning`，它**不是** `sqlite3.Error` 的子类，会一路冒成 500。



## 项目结构

```
ace-agent/
├── ai_code.py                  # 命令行前端：登录页 / REPL / 斜杠补全 / 提供商注册表 / goal 续跑 / 会话恢复
├── agent_runner.py             # 交互循环：模型 ↔ 执行层多轮闭环，错误自动回喂，工具结果确定性裁剪
├── execution_layer.py          # 执行层主入口：协议解析、权限、安全闸门、Plan Mode、全链路日志
├── ace_execpolicy.py           # 命令三值判定（allow / prompt / forbidden），纯函数、可单测
├── ace_net.py                  # 出站请求闸门：全记录校验 + pin-to-IP + 逐跳复检（SSRF）
├── ace_isolation.py            # 外部内容定界与来源标注（SEC-011）
├── ace_http.py                 # 模型调用的重试与退避（Retry-After + full jitter，纯判定可单测）
├── ace_context.py              # 上下文压缩判定：保住任务锚点，中间段折成摘要
├── ace_executor.py             # Go 执行器客户端（NDJSON 协议，纯 stdlib）
├── ace_sessionlog.py           # 会话事件日志：append-only JSONL，seq 契约，深冻结，replay 重建
├── executor/                   # Go 执行器：Job Object 沙箱（唯一需要 go build 的部分）

├── tools/                      # 工具执行器包（40 个工具）
│   ├── registry.py             #   工具唯一声明处（name / schema / 权限组 / handler）
│   ├── base.py                 #   共享助手 + 敏感目标判定 + execute 分发
│   ├── file_tools.py           #   文件/终端/检索（grep/glob/str_replace）
│   ├── code_tools.py           #   代码执行（AST 白名单 + Go 执行器/docker 边界）
│   ├── web_tools.py            #   网络/搜索/search_read/Playwright 浏览器
│   ├── db_tools.py             #   SQLite 读写
│   ├── notify_tools.py         #   通知（console/file/toast）
│   ├── parse_tools.py          #   文档解析（Word/Excel/PPT/PDF/OCR）
│   ├── goal_tools.py           #   持久目标状态机（revision CAS / blocked 白名单 / 轮次驱动）
│   ├── subagent_tools.py       #   子代理（spawn/fork，独立工具执行循环）
│   ├── kb_tools.py             #   自定义知识库（kb_search/kb_add/kb_list）
│   └── docker_sandbox.py       #   容器执行层（--sandbox docker）
├── gateway_v2/                 # 网关包：intent(L1/L2) · guard(L4) · flywheel(L5)
├── work.py                     # 诱饵工厂 + ASTDetector + BehaviorConstraint
├── guardian.py                 # 物理快照回滚：快照 / 完整性预检 / HMAC / 自动清理
├── Archive.py                  # SimHash 记忆引擎
├── Nuwa.py                     # POC 报告（HTML + JSON）
├── universal_document_parser.py# N 合一文档解析 + 懒加载 + 50MB 防线
├── i18n.py + locales/          # 轻量国际化（zh / en / ja JSON 字典）
├── prompts/                    # 系统提示词：v7 完整版 · v8 精简版 · tools 原生调用版
├── test_all.py                 # 全模块端到端测试（纯 stdlib，836 项断言）
├── demo/                       # README 演示动画 + 录制脚本（跑真实 --mock 会话）
├── assets/logo.svg             # 标识（原创几何构图，无第三方素材）

├── docs/                       # 设计文档
│   ├── ADR.md                  #   架构决策记录（内联序列 001-006）
│   ├── ADR-002-executor-boundary.md  #   执行器进程边界 / NDJSON 协议 / Windows 沙箱选型
│   ├── SECURITY-AUDIT.md       #   安全审计（OWASP + STRIDE，P0 全修复记录）
│   ├── codex_research.md       #   Codex 源码调研（45+ 可借鉴设计）
│   └── dsh_research.md         #   DeepSeek Harness 源码调研（62 项可借鉴设计）

├── LICENSE                     # MIT
├── docker/                     # lite / standard / full 三档整体镜像 + sandbox 执行镜像 + 模型下载脚本

└── .github/workflows/ci.yml    # CI：Python 3.10/3.11/3.12 全量测试 + ruff + Go 执行器 vet/build/test/race
```

## 开发与测试

```bash
python test_all.py                          # 全量测试，退出码非 0 即失败
ruff check . --select E9,F63,F7,F82         # CI 用的同一套硬错误检查
python demo/record_demo.py                  # 重录 README 顶部的演示动画
python demo/record_demo.py --check          # 只校验动画是否还和当前输出一致
```

测试是单文件、纯 stdlib、无框架的端到端断言，`check(名称, 条件, 详情)` 逐条打印。用例总数随平台浮动（Windows 上比 Linux 多十来项，差额是 Windows 专有的路径/编码用例），所以这里不写死一个数字——看退出码和失败列表就够了。CI 在 Python 3.10 / 3.11 / 3.12 三个版本上跑编译检查 + 全量测试 + ruff。



改动前请读 [`CONTRIBUTING.md`](CONTRIBUTING.md)（环境 / 测试 / 风格 / 提交流程）。改了行为的话，把断言旧行为的用例一起改掉——不要只加新用例。

Windows 提示：控制台 GBK 已做 UTF-8 兜底，但建议全局设 `PYTHONUTF8=1`。文档解析的增强依赖（python-docx / openpyxl / pdfplumber / pymupdf / pytesseract）按需装，见 `requirements.txt`；旧版 Office 格式（.doc/.xls/.ppt/.wps/.et）回退依赖系统级 LibreOffice 或 antiword。

## 许可

[MIT](LICENSE) © 2026 jincheng3870682453-hash

## 设计参考

架构决策与以下工作对齐——**让模型只负责"理解、选择、输出"，把权限、安全、回滚、记忆全部下沉到执行层**：

- [Agent Harness 工程最佳实践](https://github.com/Delphoa/study-awesome-harness-engineering)（工具 / 权限 / 记忆 / 沙箱 / 可观测性）
- [DeepSeek Harness 设计解析](https://developer.aliyun.com/article/1756780)
- [20 章中文 AI Agent 架构实战](https://github.com/ryzqi/learn-agent)
