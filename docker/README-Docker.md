# ACE Agent Docker 打包方案

## 三种镜像策略

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
