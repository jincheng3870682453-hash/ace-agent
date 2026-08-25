#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools.notify_tools —— 通知工具（notify_send：console/file/toast/email）"""

import time
from typing import Any, Dict

from tools.result import ExecutionResult


class NotifyTools:
    def _exec_notify_send(self, params: Dict) -> ExecutionResult:
        """发送通知：channel = console / file / toast（toast 可选 plyer；email 未接入）"""
        channel = str(params.get("channel", "console")).lower()
        to = str(params.get("to", ""))
        content = str(params.get("content", ""))
        if not content:
            return ExecutionResult(status="error", error_code="400", message="content 参数为空")
        if channel in ("console", "stdout"):
            print(f"[ACE 通知] {content}")
            return ExecutionResult(status="success", data={"channel": channel, "delivered": True})
        if channel == "file":
            log_path = self.project_root / "notifications.log"
            try:
                with open(log_path, "a", encoding="utf-8") as f:
                    f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {to or '-'}: {content}\n")
            except Exception as e:
                return ExecutionResult(status="error", error_code="500", message=str(e))
            return ExecutionResult(status="success", data={
                "channel": "file", "path": str(log_path), "delivered": True})
        if channel == "toast":
            try:
                from plyer import notification
                notification.notify(title=to or "ACE", message=content[:200], timeout=5)
            except ImportError:
                return ExecutionResult(status="error", error_code="500",
                                       message="toast 通知需要 plyer（pip install plyer）")
            except Exception as e:
                return ExecutionResult(status="error", error_code="500", message=f"toast 失败: {e}")
            return ExecutionResult(status="success", data={"channel": "toast", "delivered": True})
        if channel == "email":
            smtp = self.email_smtp or {}
            host = smtp.get("host", "")
            user = smtp.get("user", "")
            if not host or not user:
                return ExecutionResult(
                    status="error", error_code="501",
                    message="email 通知需要 SMTP 配置（config: email_smtp={host,port,user,password,use_tls}）")
            # SMTP 也过出站白名单。这条路不是 SSRF 面（host 来自宿主配置，模型改不了），
            # 但它是**模型可控内容**的外发通道：正文是模型写的，收件人是模型给的。
            # 白名单的口径是"能把数据带到哪个站点去"，那就该管到这里，
            # 否则"配了白名单"这句话在这条路上是假的。
            egress_err = self._egress_host_reason(host)
            if egress_err:
                return ExecutionResult(status="error", error_code="403", message=egress_err)

            try:
                import smtplib
                from email.mime.text import MIMEText
            except ImportError:
                return ExecutionResult(status="error", error_code="500",
                                       message="email 通知需要 smtplib（标准库）")
            msg = MIMEText(content, "plain", "utf-8")
            msg["Subject"] = to or "ACE 通知"
            msg["From"] = user
            msg["To"] = to
            try:
                port = int(smtp.get("port", 587))
                with smtplib.SMTP(host, port, timeout=15) as server:
                    if smtp.get("use_tls", True):
                        server.starttls()
                    if smtp.get("password"):
                        server.login(user, smtp["password"])
                    server.send_message(msg)
            except Exception as e:
                return ExecutionResult(status="error", error_code="500",
                                       message=f"email 发送失败: {e}")
            return ExecutionResult(status="success", data={
                "channel": "email", "to": to, "delivered": True, "host": host})
        return ExecutionResult(status="error", error_code="400",
                               message=f"未知通知渠道: {channel}（支持 console/file/toast）")

