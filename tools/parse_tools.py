#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools.parse_tools —— 文档解析工具（parse_document）"""

import os
from pathlib import Path
from typing import Dict

from tools.base import sensitive_target
from tools.result import ExecutionResult


class ParseTools:
    def _exec_parse_document(self, params: Dict) -> ExecutionResult:
        """文档解析（路径口径与 file_read 一致：内容读取限项目内 + 敏感目标拦截）"""
        try:
            from universal_document_parser import parse_document
        except ImportError:
            return ExecutionResult(status="error", error_code="500",
                                   message="文档解析器未安装")
        file_path = params.get("path", "")
        force_ocr = params.get("force_ocr", False)
        p = Path(os.path.expanduser(str(file_path)))
        if not p.is_absolute():
            p = self.project_root / p
        if not p.exists():
            return ExecutionResult(status="error", error_code="404",
                                   message=f"文件不存在: {p}"
                                           f"（可先 file_read 确认路径，或让用户提供正确路径）")
        # SEC-02：已存在文件先过“内容读取”口径——越界(含软链/跨盘逃逸)与敏感目标一律 403，
        # 与 file_read/terminal_view cat 同一条边界，禁止 parse_document 成为只读外带通道。
        if self.confine_files and self._confined(p) is None:
            return ExecutionResult(
                status="error", error_code="403",
                message=f"路径越界：parse_document 与 file_read 同口径，仅允许解析项目目录内文件: {p}")
        reason = sensitive_target(p)
        if reason:
            return ExecutionResult(status="error", error_code="403",
                                   message=f"parse_document 拒绝解析{reason}: {p}")
        result = parse_document(str(p), force_ocr=force_ocr)
        if result.success:
            return ExecutionResult(status="success", data=result.to_dict())
        else:
            return ExecutionResult(status="error", error_code="500",
                                   message=result.error)
