#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools.web_tools —— 网络与搜索工具（search / api_* / browser_* / image_generate）"""

import html
import os
import re
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Tuple

import ace_net
from tools.result import Denial, DenialKind, ExecutionResult, merge_denials


class WebTools:
    @staticmethod
    def _clean_html(seg: str) -> str:
        return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", seg))).strip()

    @staticmethod
    def _parse_ddg(html_text: str, top_k: int) -> List[Dict]:
        """解析 DuckDuckGo HTML 搜索结果"""
        out: List[Dict] = []
        for m in re.finditer(
                r'<a[^>]*class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
                html_text, re.DOTALL):
            url = html.unescape(m.group(1))   # 先还原 &amp; 等实体再解析
            title = WebTools._clean_html(m.group(2))
            if "uddg=" in url:   # DDG 跳转链接解码
                qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
                url = qs.get("uddg", [url])[0]
            if url.startswith("//"):
                url = "https:" + url
            out.append({"title": title, "url": url, "snippet": ""})
            if len(out) >= top_k:
                break
        snippets = re.findall(
            r'<a[^>]*class="result__snippet"[^>]*>(.*?)</a>', html_text, re.DOTALL)
        for i, sn in enumerate(snippets[:len(out)]):
            out[i]["snippet"] = WebTools._clean_html(sn)
        return out

    @staticmethod
    def _parse_bing(html_text: str, top_k: int) -> List[Dict]:
        """解析 Bing 搜索结果"""
        out: List[Dict] = []
        for m in re.finditer(
                r'<li class="b_algo".*?<h2><a[^>]*href="([^"]+)"[^>]*>(.*?)</a></h2>(.*?)</li>',
                html_text, re.DOTALL):
            url = m.group(1)
            title = WebTools._clean_html(m.group(2))
            p = re.search(r"<p[^>]*>(.*?)</p>", m.group(3), re.DOTALL)
            snippet = WebTools._clean_html(p.group(1)) if p else ""
            out.append({"title": title, "url": url, "snippet": snippet})
            if len(out) >= top_k:
                break
        return out

    @staticmethod
    def _search_engine(engine_url: str, query: str, top_k: int,
                       requests, parser, on_hop=None) -> List[Dict]:
        # 搜索引擎地址是写死的常量，但仍然走 safe_request：出站请求只留一条路径，
        # 才不会下次改动时又冒出一个"直接 requests.get"的旁路（SEC-008 就是这么留下的）。
        try:
            resp, _trail = ace_net.safe_request(
                "GET", engine_url, requests_mod=requests, params={"q": query},
                headers={"User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                                        "Chrome/124.0 Safari/537.36")},
                timeout=15, on_hop=on_hop)
        except Exception:
            return []
        if resp.status_code != 200 or not resp.text:
            return []
        return parser(resp.text, top_k)

    # 多路闸门拒绝合并成一条 403 的规则（严重度表 + 合并算法）住在 `tools.result`：
    # 它是 `DenialKind` 的语义补充，不是"网络工具的私事"。这里只留一层薄壳，
    # 因为合并要用到 `_deny` 这个 Denial 工厂（detail 怎么挂、值怎么转 str 只有一份）。
    def _merge_denials(self, refusals: List[Tuple[str, Any]]) -> Denial:
        return merge_denials(refusals, self._deny)


    def _exec_search(self, params: Dict) -> ExecutionResult:
        """真实联网搜索（DuckDuckGo HTML → Bing 兜底，无需 API Key）"""
        query = str(params.get("query", "")).strip()
        if not query:
            return ExecutionResult(status="error", error_code="400", message="query 参数为空")
        try:
            top_k = max(1, min(int(params.get("top_k", 5)), 10))
        except (TypeError, ValueError):
            top_k = 5
        try:
            import requests
        except ImportError:
            return ExecutionResult(status="error", error_code="500",
                                   message="search 需要 requests 库: pip install requests")
        results = []
        engine = ""
        # 存 (引擎名, Denial) 而不是裸 Denial：合并 detail 时要能说出是哪一路被拒的，
        # 各路的 detail 键名是同一套，不带来源就只能互相覆盖。
        refusals: List[Tuple[str, Any]] = []
        attempted = []
        # 搜索会把用户的问题原文发给第三方引擎，所以它也是出站目的地判定的对象。
        # 默认清单里就有这两个引擎（工具本身的用途就是访问它们）；只有用户把
        # egress_allowlist 收紧过，这里才会问人。被拒的引擎跳过而不是整条链路失败 ——
        # 只允许 bing 的人不该因为拒了 duckduckgo 就搜不了。
        for engine_url, parser, name in (
                ("https://html.duckduckgo.com/html/", self._parse_ddg, "duckduckgo"),
                ("https://www.bing.com/search", self._parse_bing, "bing")):
            if not self._egress_allowlisted(engine_url):
                gate = self._approve_destination(
                    f"{engine_url}?q={urllib.parse.quote(query)}")
                if gate:
                    refusals.append((name, gate))
                    continue
            attempted.append(name)
            results = self._search_engine(engine_url, query, top_k, requests, parser,
                                          on_hop=self._hop_gate(engine_url))
            if results:
                engine = name
                break
        if not results:
            if refusals and not attempted:
                # 全部搜索源都是被拒的：这不是故障，模型该做的是换目的地或让用户放宽清单。
                # 走 `_denied` 而不是自己拼 ExecutionResult —— 后者会丢掉 kind 与 detail，
                # 于是执行层只能发兜底指令，"别去申请提权"这句话就没人说了。
                return self._denied(self._merge_denials(refusals))
            if refusals:
                # 一半被拒、一半没搜到 —— 两件事都要说。只报其中一件会把模型引到
                # 错误的下一步：以为是网络问题就原样重试，以为是被拒就不再试。
                # 这一条刻意**不带** `denial_kind`：它不是"谁拦的"，拒绝只是原因之一，
                # 按拒绝那一档发指令会让模型放弃那条其实只是没搜到的路。
                return ExecutionResult(
                    status="error", error_code="502",
                    message=("部分搜索源被拒绝（"
                             + "；".join(str(gate) for _, gate in refusals) + "）；"
                             + "、".join(attempted) + " 无结果或不可达"))
            return ExecutionResult(status="error", error_code="500",
                                   message="联网搜索失败（无网络或搜索源拒绝访问），请稍后重试")

        return ExecutionResult(status="success", data={
            "query": query,
            "engine": engine,
            "results": results,
            "network_status": "ON",
        })

    def _exec_browser_screenshot(self, params: Dict) -> ExecutionResult:
        """屏幕截图：优先 pillow ImageGrab；Windows 无 pillow 时用 PowerShell 免依赖回退

        SEC-012：这个工具的名字带 browser，抓的却是**整个虚拟桌面** —— 浏览器只是
        恰好在上面的一个窗口，旁边还有密码管理器、聊天窗口、邮件、另一个项目的代码。
        它原先被归进 READ_TOOLS，于是 readonly（"只读"）权限下模型可以自行截屏，
        再把图片路径交给 image 类工具或直接读进上下文 —— 一次读的范围远超工作区。

        所以做两件事：
          1. 归类改成写入类（见 execution_layer.WRITE_TOOLS）—— readonly 不再包含它；
          2. 每次抓屏都单独问人。"允许改我的项目"不等于"允许拍我的屏幕"，
             这两件事之间没有蕴含关系，不该由同一个权限档位一起授予。
        """
        gate = self._approve_action(
            "整个虚拟桌面（含所有显示器与所有窗口，不限于浏览器）",
            "抓取屏幕截图",
            deny_hint="截图内容会进入模型上下文，PNG 文件会留在项目内的 .ace_shots/ 目录。")
        if gate:
            return self._denied(gate)
        shot_dir = self.project_root / ".ace_shots"

        shot_dir.mkdir(parents=True, exist_ok=True)
        shot_path = shot_dir / f"shot_{int(time.time() * 1000)}.png"
        try:
            from PIL import ImageGrab
            try:
                img = ImageGrab.grab()
                img.save(str(shot_path))
                return ExecutionResult(status="success", data={
                    # `_launch_path_label` 而不是 `_model_path_label`：这个字段被
                    # `ai_code._print_clickables` 拿去拼 file:/// 链接，相对路径会拼出
                    # 一条点不开的链接 —— 而截图本来就只落在项目内的 .ace_shots/，
                    # 项目根的绝对前缀每轮都在系统提示词里，回显它不是新泄漏。
                    # 用这个 helper 而不是裸 `str()` 是为了让"落盘目录被改到项目外"
                    # 这件事将来自动收口，而不是又变成一处需要人记得的例外。
                    "image_path": self._launch_path_label(shot_path),
                    "format": "png", "engine": "pillow"})

            except Exception as e:
                # `img.save()` 的 `OSError` 的 str 就是一条完整绝对路径（.ace_shots/…）：
                # 成功路径上给的是 `_launch_path_label`（项目内才回显），失败路径上
                # 裸 `{e}` 等于绕过那个判据 —— 落盘目录一旦被改到项目外，泄漏就从
                # 这条 except 里出去。类型名足够告诉模型"这不是参数错，别原样重试"。
                return self._internal_error("截图失败", e)
        except ImportError:
            pass
        # Windows 免依赖回退：PowerShell System.Drawing 屏幕抓取
        if os.name == "nt":
            import subprocess
            ps = (
                "Add-Type -AssemblyName System.Windows.Forms,System.Drawing;"
                "$b=[System.Windows.Forms.SystemInformation]::VirtualScreen;"
                "$bmp=New-Object System.Drawing.Bitmap $b.Width,$b.Height;"
                "$g=[System.Drawing.Graphics]::FromImage($bmp);"
                "$g.CopyFromScreen($b.Left,$b.Top,0,0,$bmp.Size);"
                f"$bmp.Save('{str(shot_path)}');$g.Dispose();$bmp.Dispose()"
            )
            try:
                subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                               capture_output=True, timeout=30, check=True)
                if shot_path.exists():
                    return ExecutionResult(status="success", data={
                        "image_path": self._launch_path_label(shot_path),
                        "format": "png", "engine": "powershell"})
            except Exception as e:
                # 这一处比 pillow 那一处更狠：`CalledProcessError` / `TimeoutExpired`
                # 的 str 会把**整条命令**打出来，而上面那段 PowerShell 里就嵌着
                # `$bmp.Save('<截图绝对路径>')` —— 异常一抛，落盘的完整路径直接进
                # 模型上下文，连"截图失败"这件事都不需要真的和路径有关。
                return self._internal_error("截图失败", e)
        # 501 而不是 500，理由和 notify_tools 里 toast 缺 plyer 完全一样：走到这里
        # 说明 pillow 没装、而且这台机器也没有免依赖回退（非 Windows，或 PowerShell
        # 那条路没落出文件）—— 这是"本机不具备截屏能力"，不是这次执行出了错。
        # 500 会让模型怀疑自己的参数并原样重试，而重试一万次 pillow 也不会自己装上。
        # `denial_kind` 是另一半：熔断桶是 f"{tool}:{code}"，不带这一档时三次
        # "缺依赖"就把 browser_screenshot 永久熔断，而它下一步该做的是换别的工具
        # 或让用户去装依赖 —— 那正是 `_note_tool_failure` 对这一档豁免计数的原因。
        return ExecutionResult(status="error", error_code="501",
                               message="browser_screenshot 需要 pillow（Windows 可免依赖，"
                                       "其他平台请 pip install pillow）",
                               denial_kind=DenialKind.DEPENDENCY_MISSING)

    def _exec_api_get(self, params: Dict) -> ExecutionResult:
        url = str(params.get("url", ""))
        # 协议先判：非 http/https 连库都不用导（也让"没装 requests"不影响这条拒绝）
        scheme_err = ace_net.check_scheme(url)
        if scheme_err:
            return ExecutionResult(status="error", error_code="400", message=scheme_err)
        # SEC-013 的另一半：SSRF 闸门只回答"是不是内网"，`https://evil.tld/?data=…`
        # 是个完全合规的公网地址，数据照样被查询串带走。所以再按目的地判一次。
        if not self._egress_allowlisted(url):
            # 先做无条件拒绝的判定再问人（同 api_post 的理由：注定被拒的目标
            # 弹确认框只会把用户训练成随手点同意）。代价是这条路径多一次 DNS。
            url_err = ace_net.check_url(url)
            if url_err:
                return ExecutionResult(status="error", error_code="400", message=url_err)
            gate = self._approve_destination(url)
            if gate:
                return self._denied(gate)
        try:

            import requests
        except ImportError:
            return ExecutionResult(status="error", error_code="500",
                                   message="api_get 需要 requests 库: pip install requests")
        try:
            resp, trail = ace_net.safe_request("GET", url, requests_mod=requests, timeout=30,
                                               on_hop=self._hop_gate(url))
        except ace_net.UrlBlocked as e:
            # 400 不是 500：这是拒绝而非故障，模型要换目标而不是原样重试。
            # 全文照发：`UrlBlocked` 的文本全部由 ace_net 自己拼（拒绝类别 + 模型
            # 刚传进来的 host/URL），没有本机产生的新信息，而"回环 / 云元数据 /
            # DNS 解析失败"正是模型判断下一步要靠的东西。
            return ExecutionResult(status="error", error_code="400", message=str(e))
        except Exception as e:
            # requests 的异常不是本层能控的文本：`SSLError` 会带上 CA bundle 路径，
            # `ProxyError` 会带上代理 URL（可能含凭据），底层 `OSError` 会带盘符。
            # 但异常**类型**恰好是模型要区分的那一层 —— ConnectionError / SSLError /
            # ReadTimeout / TooManyRedirects 是四件不同的事，`_internal_error` 保留
            # 类型、把全文挪进 metadata，诊断力没丢，本机布局没出去。
            return self._internal_error("api_get 请求失败", e)
        return ExecutionResult(status="success", data={
            "status_code": resp.status_code,
            "content": resp.text[:5000],
            # 跟了几跳、最后落在哪儿要如实说明：重定向到别的站点属于模型该知道的事实
            "final_url": trail[-1],
            "redirects": len(trail) - 1,
        })

    def _exec_api_post(self, params: Dict) -> ExecutionResult:
        url = str(params.get("url", ""))
        scheme_err = ace_net.check_scheme(url)
        if scheme_err:
            return ExecutionResult(status="error", error_code="400", message=scheme_err)
        # SEC-013：先做"无论如何都不允许"的判定，再问人。
        # 顺序反过来会为一个注定被拒的目标（回环、云元数据）弹一次确认框 ——
        # 那里没有可决定的东西，只有把用户训练成随手点"同意"。
        # 这一步**不是**安全边界：真正的校验仍在 safe_request 里与连接绑定完成
        # （SEC-008），这里只是提前挡掉不值得打扰用户的情况，代价是多一次 DNS 解析。
        url_err = ace_net.check_url(url)
        if url_err:
            return ExecutionResult(status="error", error_code="400", message=url_err)
        body = params.get("data", {})
        # 显式把 URL 交给模型侧那一份摘要：`_approve_outbound` 的默认是"目的地不回显"
        # （见 base 里那段说明 —— notify 的目的地里嵌着用户配置的 SMTP host）。
        # 这里的目的地是模型自己刚传进来的 URL，隐去它没有任何安全收益，只会让模型
        # 分不清是哪一笔外发被拒；而能带走数据的正是查询串，所以给全文而不是域名。
        gate = self._approve_outbound(url, body, model_summary=url)
        if gate:
            return self._denied(gate)

        try:
            import requests
        except ImportError:
            return ExecutionResult(status="error", error_code="500",
                                   message="api_post 需要 requests 库: pip install requests")
        try:
            resp, trail = ace_net.safe_request("POST", url, requests_mod=requests,
                                               json_body=body, timeout=30,
                                               on_hop=self._hop_gate(url))

        except ace_net.UrlBlocked as e:
            # 同 api_get：这一条的文本是 ace_net 按拒绝类别拼的，全文照发。
            return ExecutionResult(status="error", error_code="400", message=str(e))
        except Exception as e:
            return self._internal_error("api_post 请求失败", e)
        return ExecutionResult(status="success", data={
            "status_code": resp.status_code,
            "content": resp.text[:5000],
            "final_url": trail[-1],
            "redirects": len(trail) - 1,
        })

    def _exec_browser_open(self, params: Dict) -> ExecutionResult:
        """用系统默认浏览器打开 URL（真实实现，仅 http/https）"""
        url = str(params.get("url", ""))
        # 这里只能做校验：URL 交给系统浏览器之后，连接不再经过本进程，
        # 没法 pin 到已校验的 IP，也拦不住浏览器自己跟的重定向。
        url_err = self._check_url(url)
        if url_err:
            return ExecutionResult(status="error", error_code="400", message=url_err)
        # 出站白名单同样管这条路（原先漏了）：`api_get` 把 URL 发出去要过闸门，
        # browser_open 把**同一个 URL** 交给浏览器发出去却不过，等于在闸门旁边开了
        # 一扇门 —— 而这扇门更宽：浏览器会带上已登录的 Cookie，且逐跳复检在这里
        # 根本无法实现（连接不经过本进程）。所以清单外一律先问人。
        if not self._egress_allowlisted(url):
            gate = self._approve_destination(url)
            if gate:
                return self._denied(gate)
        import webbrowser
        try:
            ok = webbrowser.open(url)
        except Exception as e:
            # `webbrowser` 抛的是本机环境的事：找不到可执行文件时 `FileNotFoundError`
            # 的 str 带着浏览器的完整安装路径，Linux 上还会带 `BROWSER` 环境变量的内容。
            # 这些都不是模型传进来的，也不影响它的下一步（它只需要知道"没打开"）。
            return self._internal_error("browser_open 调起浏览器失败", e)
        return ExecutionResult(status="success", data={"url": url, "opened": bool(ok)})

    def _exec_browser_click(self, params: Dict) -> ExecutionResult:
        return ExecutionResult(status="error", error_code="501",
                               message="browser_click 尚未接入浏览器（POC 占位）")

    def _exec_browser_type(self, params: Dict) -> ExecutionResult:
        return ExecutionResult(status="error", error_code="501",
                               message="browser_type 尚未接入浏览器（POC 占位）")

    def _exec_image_generate(self, params: Dict) -> ExecutionResult:
        """真实图像生成（pollinations.ai 免费端点，无需密钥），保存到项目 .ace_images/"""
        prompt = str(params.get("prompt", "")).strip()
        if not prompt:
            return ExecutionResult(status="error", error_code="400", message="prompt 参数为空")
        size = str(params.get("size", "512x512"))
        m = re.match(r"^(\d{2,4})x(\d{2,4})$", size)
        if not m:
            return ExecutionResult(status="error", error_code="400",
                                   message=f"size 格式应为 宽x高（如 512x512），收到: {size}")
        width, height = m.group(1), m.group(2)
        try:
            import requests
        except ImportError:
            return ExecutionResult(status="error", error_code="500",
                                   message="image_generate 需要 requests 库: pip install requests")
        img_dir = self.project_root / ".ace_images"
        img_dir.mkdir(parents=True, exist_ok=True)
        img_path = img_dir / f"gen_{int(time.time() * 1000)}.png"
        url = (f"https://image.pollinations.ai/prompt/{urllib.parse.quote(prompt)}"
               f"?width={width}&height={height}&nologo=true")
        # prompt 原文进的是 URL 路径 —— 这条路同样能带走数据。默认清单里有
        # pollinations（工具的用途就是访问它），清单被收紧后才会问人，
        # 且摘要展示的是完整 URL，人能看见 prompt 里到底写了什么。
        if not self._egress_allowlisted(url):
            gate = self._approve_destination(url)
            if gate:
                return self._denied(gate)
        try:

            resp, _trail = ace_net.safe_request("GET", url, requests_mod=requests, timeout=60,
                                                on_hop=self._hop_gate(url))
            resp.raise_for_status()
            img_path.write_bytes(resp.content)
        except Exception as e:
            # 这个 try 块里有两类失败：网络请求（requests 异常，见 api_get 那段说明）
            # 和 `img_path.write_bytes()` 的 `OSError` —— 后者的 str 是 .ace_images/
            # 下的完整绝对路径。两类都靠类型名区分够了，全文进 metadata 给人排障。
            return self._internal_error("图像生成失败", e)
        return ExecutionResult(status="success", data={
            "image_path": self._launch_path_label(img_path), "size": f"{width}x{height}",
            "bytes": len(resp.content), "service": "pollinations.ai",
        })

