#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gateway_v2.model —— L3 模型调用适配层

优先 callback，其次 OpenAI 兼容 HTTP API（/chat/completions）。
"""

from typing import Any, Callable, Dict, List, Optional


class ModelAdapter:
    """L3 模型调用：优先 callback，其次 OpenAI 兼容 HTTP API"""

    def __init__(self, callback: Optional[Callable] = None,
                 base_url: Optional[str] = None, api_key: Optional[str] = None,
                 model: Optional[str] = None, timeout: int = 60) -> None:
        self.callback = callback
        self.base_url = base_url
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

    def generate(self, prompt: str, system: Optional[str] = None) -> str:
        if self.callback is not None:
            return str(self.callback(prompt, system))
        if self.base_url:
            return self._generate_http(prompt, system)
        raise RuntimeError(
            "L3 未接入模型：请提供 model_callback 或 base_url+api_key（OpenAI 兼容接口）"
        )

    def _generate_http(self, prompt: str, system: Optional[str]) -> str:
        try:
            import requests
        except ImportError as e:
            raise RuntimeError("L3 HTTP 调用需要 requests 库") from e
        messages: List[Dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        resp = requests.post(
            f"{self.base_url.rstrip('/')}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}"},
            json={"model": self.model or "default", "messages": messages},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data: Dict[str, Any] = resp.json()
        return data["choices"][0]["message"]["content"]

    @property
    def available(self) -> bool:
        return self.callback is not None or bool(self.base_url)
