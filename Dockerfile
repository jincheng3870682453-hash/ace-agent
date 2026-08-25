FROM python:3.12-slim

WORKDIR /ace

# 真实模型对话需要 requests；核心仍为零第三方依赖
RUN pip install --no-cache-dir requests

COPY . .

# 非 root 运行。这不是可选的洁癖：容器内 agent 有 terminal_exec，以 root 跑
# 意味着容器逃逸类漏洞的收益直接拉满，而 ace 本身不需要任何特权。
# 与 docker/Dockerfile.lite 的口径保持一致（那边一直是 USER ace）。
RUN useradd --create-home --uid 10001 ace && chown -R ace:ace /ace
USER ace

# 容器内建议 readonly 起步；--mock 可直接离线演示完整循环
CMD ["python", "ai_code.py", "--mock"]

