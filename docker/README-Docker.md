# ACE Agent Docker 打包方案

这里有**两类**完全不同的用法，别搞混：

- **整体镜像**（lite / standard / full）：把 ACE 自己装进容器跑。隔离最彻底，代价是容器外的东西一概碰不到——"在桌面建个文件"这类请求做不了，只能操作挂载进去的目录。
- **沙箱镜像**（`ace-sandbox`）：ACE 跑在宿主，只把 `terminal_exec` / `code_execute` 丢进一次性容器。日常用法不变，危险面被隔离。见下方「沙箱镜像」一节。

## 三种整体镜像策略

| 镜像 | 大小 | 内置 VLM | 文档解析 | 适用场景 |
|------|------|----------|----------|----------|
| `ace-agent:lite` | ~180MB | ❌ | ❌ | 只连远程 API，体积最小 |
| `ace-agent:standard` | ~2.3GB | ✅ Qwen2.5-VL-3B | 基础 | 离线识图，开箱即用 |
| `ace-agent:full` | ~3GB | ✅ | 完整 | 需要解析 Word/Excel/PDF |

## 快速开始

### 1. 构建镜像

```bash
# 以下 build 命令均在仓库根目录执行

# 最小版 (推荐开发测试)
docker build -f docker/Dockerfile.lite -t ace-agent:lite .

# 标准版 (内置 VLM，推荐生产)
docker build -f docker/Dockerfile.standard -t ace-agent:standard .

# 完整版
docker build -f docker/Dockerfile.full -t ace-agent:full .
```

### 2. 运行

```bash
# Lite: 需要你自己提供 API Key
docker run -it --rm \
  -e AGENT_BASE_URL=https://api.deepseek.com/v1 \
  -e AGENT_API_KEY=sk-xxx \
  -e AGENT_MODEL=deepseek-chat \
  -v $(pwd):/app/project \
  ace-agent:lite

# Standard: 内置 VLM，无需外部 API 也能识图
docker run -it --rm \
  -e AGENT_BASE_URL=https://api.deepseek.com/v1 \
  -e AGENT_API_KEY=sk-xxx \
  -v $(pwd):/app/project \
  -p 8080:8080 \
  ace-agent:standard

# 用 docker compose (推荐)
docker compose -f docker/docker-compose.yml up ace-standard
```

### 3. 模型外挂方案 (镜像保持 200MB)

如果你不想打 2GB 的镜像，可以用 volume 外挂模型：

```bash
# 1. 先下载模型 (仓库根目录执行)
python docker/download_model.py ./models

# 2. 用 docker-compose 的 vlm-server 服务
docker compose -f docker/docker-compose.yml up vlm-server ace-lite
```

## 沙箱镜像（`ace-sandbox`）

和上面三档镜像是两回事：这个镜像里**没有 ACE 的代码**，它只是一个干净的执行环境。ACE 跑在宿主，每次 `terminal_exec` / `code_execute` 都 `docker run` 一个它的容器、跑完即销毁。实现见 [`tools/docker_sandbox.py`](../tools/docker_sandbox.py)。

```bash
# 仓库根目录执行
docker build -t ace-sandbox:latest -f docker/Dockerfile.sandbox .
python ai_code.py --sandbox docker
```

构建卡在 `load metadata for docker.io/library/python` 是拉不到 Docker Hub，不是 Dockerfile 的问题。
用任一可达的镜像源先取基础镜像、再打成 Dockerfile 里写的名字，构建命令本身不用改：

```bash
docker pull <镜像源>/library/python:3.12-slim-bookworm
docker tag  <镜像源>/library/python:3.12-slim-bookworm python:3.12-slim-bookworm
```

容器参数（每一条都对应一类具体威胁，改之前想清楚）：

- `--network none` —— 没有网卡。凭据传不出去，也下载不了第二阶段载荷
- `--read-only` + `--tmpfs /tmp` —— 根文件系统不可写，只有挂进来的工作目录可写
- `--cap-drop ALL` + `--security-opt no-new-privileges` —— 拿不到额外权能
- `--memory` / `--memory-swap` / `--pids-limit` —— 内存耗尽和 fork bomb 变成容器自己的事（`memory-swap` 必须等于 `memory`，否则超额部分会换到 swap，等于没限）
- `-v <工作目录>:/work:rw` + `-w /work` —— 只有工作目录可见，项目外的东西容器里不存在
- `--rm` —— 进程树、临时文件、残留状态随容器一起消失
- POSIX 宿主上额外传 `-u <宿主 uid>`，容器写出的文件在宿主侧归属正确，不留一堆 root 拥有的产物

镜像刻意保持最小：**装了什么，agent 在沙箱里就能用什么**。需要 gcc / node / git 就自己往下加一层，不要为了"可能用得上"预装一堆东西。

两个必须知道的边界：

1. 容器共享内核。容器逃逸漏洞仍然是逃逸，要更强的边界得上虚拟机。
2. **开了沙箱但 Docker 不可用时会直接报 503，不会静默回退宿主执行。** 回退比没有沙箱更危险——你以为命令跑在容器里，实际跑在自己机器上，而且没有任何提示。

## VLM 工具使用

> **尚未实现。** `vision_analyze` 工具目前不在代码里 —— 它没有注册到 `tools/registry.py`，
> 也没有对应的 `_exec_` 实现。上面的 vlm-server 只是把模型服务跑起来，Agent 还调用不到它。
> 之前 `docker/vision_tool_patch.py` 里放着一份手工粘贴用的代码片段，因为从未被应用、
> 且不是合法的 Python 模块（会让 CI 语法检查失败），已删除。
>
> 要接上，需要：注册 ToolSpec（读工具权限档）、在 ToolExecutor 里加 `_exec_vision_analyze`
> 分支、用 `urllib` 而非 `requests` 调 `${VLM_URL}/chat/completions`（本项目核心零依赖）。

## 体积优化技巧

1. **使用 .dockerignore**: 已配置，避免把测试缓存、模型文件打进镜像
2. **多阶段构建**: standard 版分编译/下载/运行三个阶段，只保留必要文件
3. **slim 基础镜像**: python:3.11-slim-bookworm 比 alpine 兼容性好，比完整版小 800MB
4. **模型量化**: Q4_K_M 比 FP16 小 4 倍，精度损失 < 3%
5. **pip --no-cache-dir**: 不保留 pip 缓存

## 内存/显存要求

| 场景 | 最低内存 | 推荐 |
|------|----------|------|
| CPU 推理 VLM | 4GB | 8GB |
| GPU 推理 VLM | 4GB 显存 | 6GB+ |
| 纯 ACE (无 VLM) | 512MB | 1GB |
