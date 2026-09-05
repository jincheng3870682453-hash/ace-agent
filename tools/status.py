#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools.status —— 错误码/状态码唯一目录(Q-10)

契约:
  · 对模型/用户暴露的 `ExecutionResult.error_code` 只允许使用本文件集合中的值;
  · 新增错误码:先在下方登记常量并加入 ERROR_CODES,再使用;
  · `test_all.py` 的 AST 守卫会拒绝代码库中未登记的散落字面量(防漂移)。
  · 数字串语义:400 参数错 · 403 权限/越界/敏感目标/策略拒绝 · 404 不存在 ·
    409 歧义 · 500 内部失败 · 501 未实现/缺渠道 · 503 沙箱档不可用(不静默回退) · 504 超时。
"""

from typing import Final, FrozenSet

ERROR_BAD_REQUEST: Final[str] = "400"
ERROR_FORBIDDEN: Final[str] = "403"
ERROR_NOT_FOUND: Final[str] = "404"
ERROR_CONFLICT: Final[str] = "409"
ERROR_INTERNAL: Final[str] = "500"
ERROR_NOT_IMPLEMENTED: Final[str] = "501"
ERROR_SANDBOX_UNAVAILABLE: Final[str] = "503"
ERROR_TIMEOUT: Final[str] = "504"

ERROR_CODES: FrozenSet[str] = frozenset({
    ERROR_BAD_REQUEST, ERROR_FORBIDDEN, ERROR_NOT_FOUND, ERROR_CONFLICT,
    ERROR_INTERNAL, ERROR_NOT_IMPLEMENTED, ERROR_SANDBOX_UNAVAILABLE,
    ERROR_TIMEOUT,
})
