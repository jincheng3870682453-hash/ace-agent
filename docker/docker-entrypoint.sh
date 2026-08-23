#!/bin/bash
set -e

# 启动 llama.cpp server (内置 VLM) 在后台
# 使用 OpenAI 兼容 API 格式，ACE 通过 http://localhost:8080/v1 调用
llama-server \
  -m /app/models/qwen2.5-vl-3b-q4_k_m.gguf \
  --mmproj /app/models/qwen2.5-vl-3b-mmproj.gguf \
  --host 0.0.0.0 \
  --port 8080 \
  -c 4096 \
  --jinja \
  --timeout 300 \
  &

LLAMA_PID=$!

# 等待 server 就绪
echo "等待 VLM 服务启动..."
for i in {1..30}; do
  if curl -s http://localhost:8080/health > /dev/null 2>&1; then
    echo "VLM 服务已就绪 (PID: $LLAMA_PID)"
    break
  fi
  sleep 1
done

# 启动 ACE Agent
# 如果传入了参数，执行参数；否则默认启动交互模式
if [ $# -eq 0 ]; then
  exec python ai_code.py
else
  exec python ai_code.py "$@"
fi
