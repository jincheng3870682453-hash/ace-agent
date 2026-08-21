#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools.result —— 工具执行结果（从 execution_layer 拆出）"""

from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class ExecutionResult:
    """执行结果"""
    status: str = "success"           # success / error / guard_violation / bait_triggered / permission_denied
    data: Any = None
    error_code: str = ""
    message: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
