FROM python:3.12-slim

WORKDIR /ace

# 真实模型对话需要 requests；核心仍为零第三方依赖
RUN pip install --no-cache-dir requests

COPY . .

# 容器内建议 readonly 起步；--mock 可直接离线演示完整循环
CMD ["python", "ai_code.py", "--mock"]
