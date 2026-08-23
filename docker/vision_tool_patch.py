
# ============================================
# 在 execution_layer.py 的 ToolExecutor 中新增 vision_analyze 工具
# 放在 _exec_image_generate 后面即可
# ============================================

    def _exec_vision_analyze(self, params: Dict) -> ExecutionResult:
        """调用本地 VLM (llama.cpp server) 分析图片"""
        image_path = str(params.get("image_path", "")).strip()
        prompt = str(params.get("prompt", "请详细描述这张图片的内容"))

        if not image_path:
            return ExecutionResult(status="error", error_code="400", message="image_path 参数为空")

        p = self._resolve_read_path(image_path)
        if not p or not p.exists():
            return ExecutionResult(status="error", error_code="404", message=f"图片不存在: {image_path}")

        # 读取图片转 base64
        import base64
        try:
            with open(p, "rb") as f:
                image_b64 = base64.b64encode(f.read()).decode("utf-8")
        except Exception as e:
            return ExecutionResult(status="error", error_code="500", message=f"图片读取失败: {e}")

        # 调用本地 llama.cpp server (OpenAI 兼容格式)
        vlm_url = os.environ.get("VLM_URL", "http://localhost:8080/v1")
        try:
            import requests
            resp = requests.post(
                f"{vlm_url}/chat/completions",
                json={
                    "model": "qwen2.5-vl-3b",
                    "messages": [
                        {"role": "user", "content": [
                            {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{image_b64}"}},
                            {"type": "text", "text": prompt}
                        ]}
                    ],
                    "temperature": 0.2,
                    "max_tokens": 1024
                },
                timeout=120
            )
            resp.raise_for_status()
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            return ExecutionResult(status="success", data={
                "description": content,
                "image_path": str(p),
                "model": "qwen2.5-vl-3b"
            })
        except Exception as e:
            return ExecutionResult(status="error", error_code="500", 
                                 message=f"VLM 调用失败: {e}。请确认 VLM 服务已启动 (llama-server on :8080)")

# ============================================
# 在 execute() 方法中添加分支:
# ============================================
# elif tool_name == "vision_analyze":
#     result = self._exec_vision_analyze(params)

# ============================================
# 在 TOOL_EXAMPLES 中添加:
# ============================================
# "vision_analyze": '{"tool":"vision_analyze","image_path":"screenshot.png","prompt":"描述图片"}',

# ============================================
# 在 READ_TOOLS 中添加 "vision_analyze"
# ============================================
