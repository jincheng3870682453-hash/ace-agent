#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools.parse_tools —— 文档解析工具（parse_document）"""

import os
from pathlib import Path
from typing import Any, Dict

from tools.result import ExecutionResult


class ParseTools:
    def _exec_parse_document(self, params: Dict) -> ExecutionResult:
        """文档解析"""
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
        result = parse_document(str(p), force_ocr=force_ocr)
        if result.success:
            return ExecutionResult(status="success", data=result.to_dict())
        else:
            return ExecutionResult(status="error", error_code="500",
                                   message=result.error)
