#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools.notify_tools —— 通知工具（notify_send：console/file/toast/email）"""

import time
from typing import Any, Dict

from tools.result import DenialKind, ExecutionResult


class NotifyTools:
    def _exec_notify_send(self, params: Dict) -> ExecutionResult:
        """发送通知：channel = console / file / toast / email
        （toast 可选 plyer；email 需 config.email_smtp）"""
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
                # 原来是 `message=str(e)`：`open()` 抛的 `OSError`/`PermissionError`
                # 的 str 就是一条完整绝对路径（`[Errno 13] Permission denied:
                # C:\Users\<名字>\...\notifications.log`），而 message 整段进模型
                # 上下文。模型拿这条路径也做不了任何事 —— 它要判断的只是"不是我的
                # 参数错，别原样重试"，异常类型足够；全文进 metadata 给人和日志。
                return self._internal_error("写入通知日志失败", e)
            return ExecutionResult(status="success", data={
                # `data` 同样进模型上下文（`render_result` 白名单含它），所以这里
                # 跟 file_write 用同一个口径。`notifications.log` 结构上永远在项目内，
                # `_model_path_label` 给出的是相对路径 —— 这正是想要的：模型下一步
                # 可能要 file_read 它，而 file_read 收的就是相对路径。
                # 不用 `_launch_path_label`：这个字段没有拼 `file:///` 的消费者
                # （`ai_code._print_clickables` 只认 open_file / browser_screenshot /
                # image_generate），保留绝对路径没有收益、只多一份泄漏。
                "channel": "file", "path": self._model_path_label(log_path),
                "delivered": True})
        if channel == "toast":
            try:
                from plyer import notification
                notification.notify(title=to or "ACE", message=content[:200], timeout=5)
            except ImportError:
                # 501 而不是 500："可选依赖没装"是这台机器上没有这个能力，不是这次
                # 执行出了错。两者模型的正确反应相反：500 会让它怀疑自己的参数、
                # 原样重试（重试一万次 plyer 也不会自己装上，只白烧轮次直到熔断）；
                # 501 才是"换 console/file 渠道，或让用户去装依赖"。
                # 同一个文件里 email 缺 SMTP 配置走的就是 501，判据必须一致。
                #
                # 光有 501 还不够，`denial_kind` 是这条路的另一半：熔断桶是
                # `f"{tool}:{code}"`，所以本文件三处 501 共用 `notify_send:501`
                # 这一个桶 —— 不带这一档时，"试一次 toast + 试两次 email"就把整个
                # notify_send 熔断了，连一次就能送到的 console / file 一起禁掉。
                # 带上它，`_note_tool_failure` 才知道这不是模型在原地打转。
                return ExecutionResult(status="error", error_code="501",
                                       message="toast 通知需要 plyer（pip install plyer）",
                                       denial_kind=DenialKind.DEPENDENCY_MISSING)
            except Exception as e:
                # plyer 背后是平台通知 API（Windows 上走 win32/COM），异常里可能带
                # 模块路径、DLL 位置甚至用户名。这些不是本层能预判的文本，一律只留类型。
                return self._internal_error("toast 通知失败", e)

            return ExecutionResult(status="success", data={"channel": "toast", "delivered": True})
        if channel == "email":
            smtp = self.email_smtp or {}
            host = smtp.get("host", "")
            user = smtp.get("user", "")
            if not host or not user:
                # 与 toast 缺 plyer 同一类，所以同一档 kind：都是"这台机器不具备
                # 这个能力"，模型原样重试不会让配置自己出现，而换 console/file 就成。
                # 这里更需要它 —— 缺配置是最容易被模型连着试几次的一种（它会怀疑
                # 是自己少传了参数），而三次就够熔断整个 notify_send。
                return ExecutionResult(
                    status="error", error_code="501",
                    message="email 通知需要 SMTP 配置（config: email_smtp={host,port,user,password,use_tls}）",
                    denial_kind=DenialKind.DEPENDENCY_MISSING)
            # SEC-013：收件人和正文都来自模型输出，而 write 档位授予的是"改这个项目"，
            # 不是"用我的邮箱往外寄东西"。console/file/toast 三个渠道不问，因为它们
            # 都落在本机；email 是唯一一条把内容送出本机的通道，所以单独设闸。
            gate = self._approve_outbound(f"邮件 {to or '(未指定收件人)'} via {host}", content)
            if gate:
                return self._denied(gate)
            try:
                import smtplib
                from email.mime.text import MIMEText
            except ImportError:
                # 也是"这台机器不具备该能力"，所以跟另外两处同码同档，不再用 500。
                # smtplib 是标准库，正常发行版里这条走不到；但走到的时候（裁剪过的
                # 嵌入式发行版、被 site-packages 里的同名模块顶掉）它和缺 plyer 是
                # 完全一样的处境：模型重试无效、换 channel 有效。留 500 会让它落进
                # "内部故障"那条分支 —— 拿不到"换 channel"的指令，还照常计入熔断，
                # 于是一个装不全的 Python 能把整个 notify_send 熔断掉。
                return ExecutionResult(status="error", error_code="501",
                                       message="email 通知需要 smtplib（标准库）",
                                       denial_kind=DenialKind.DEPENDENCY_MISSING)
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
                # smtplib 的异常全文是这个文件里泄漏面最大的一处：`SMTPConnectError`
                # 带 host:port，`SMTPAuthenticationError` 带服务器返回的认证协商原话
                # （有的服务商会把账号名回显在里面），DNS 失败还会带上解析细节。
                # 这些全部来自用户配置，不是模型给的，回显等于把用户的邮件基础设施
                # 抄进模型上下文；而模型能做的下一步只有"告诉用户发不出去"。
                return self._internal_error("email 发送失败", e)

            return ExecutionResult(
                status="success",
                # 原来这里还有 `"host": host`。它不是路径泄漏而是**配置泄漏**：
                # host 是用户在 config 里填的，可能就是公司内网邮件网关的内部域名
                # （`mail.内部域.corp`），本身即内网拓扑情报；而 `data` 整段进模型
                # 上下文（`render_result` 白名单含它）。模型拿到它做不了任何下一步 ——
                # 它要判断的只是"发出去了 / 没发出去"，`delivered` 已经说完。
                # 也不给"已通过配置的 SMTP 服务器发送"这类替代文案：那句话不含任何
                # 机器可读的新信息，只是把同一个 delivered=True 用中文说第二遍。
                # `to` 保留 —— 它是模型自己传进来的参数，回显它不新增任何泄漏。
                data={"channel": "email", "to": to, "delivered": True},
                # 人排障时确实要知道"发给了哪个 host:port" —— 那份信息走 metadata：
                # 成功 payload 不带 metadata 键（`execution_layer` 只回 data/elapsed），
                # `render_result` 白名单也不含它，所以这是唯一"人能看到、模型看不到"
                # 的通道，与 `_internal_error` 把异常全文放这里是同一个口径。
                # 不放 user / password：日志与 UI 也不需要凭据才能定位问题。
                metadata={"notify": {"channel": "email", "smtp_host": host,
                                     "smtp_port": port}})
        return ExecutionResult(status="error", error_code="400",
                               message=f"未知通知渠道: {channel}（支持 console/file/toast）")

