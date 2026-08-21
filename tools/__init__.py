#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools —— 工具执行器包（从 execution_layer.ToolExecutor 拆出）

  按工具域拆分：文件/终端 / 代码沙盒 / 网络搜索 / 数据库 / 通知 / 文档解析
"""

from tools.result import ExecutionResult
from tools.base import ToolExecutorBase, repair_backslash_json
from tools.file_tools import FileTools
from tools.code_tools import CodeTools
from tools.web_tools import WebTools
from tools.db_tools import DbTools
from tools.notify_tools import NotifyTools
from tools.parse_tools import ParseTools


class ToolExecutor(ToolExecutorBase, FileTools, CodeTools, WebTools,
                   DbTools, NotifyTools, ParseTools):
    """实际执行工具调用：组合各工具域 mixin"""
    pass


__all__ = ["ToolExecutor", "ExecutionResult", "repair_backslash_json"]
