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
from typing import Any, Dict, List, Optional, Tuple

import ace_net
from tools.result import ExecutionResult


# 第三方搜索 API 的官方端点（search 双通道里的「API-key 通道」）。
# provider=bocha 走这里（api.bocha.cn，响应兼容 Bing Web Search）；
# provider=custom 时用配置里的 url（ACE_SEARCH_API_URL）。
_SEARCH_API_ENDPOINTS = {
    "bocha": "https://api.bocha.cn/v1/web-search",
}


class WebTools:
    # 联网工具清单（/net 开关控制；关闭时这些工具一律拒绝）
    NETWORK_TOOLS = {"search", "search_read", "api_get", "api_post",
                     "image_generate", "browser_open", "browser_navigate"}

    def _net_gate(self) -> Optional[ExecutionResult]:
        """联网开关门卫：关闭时返回 403，开启时返回 None。"""
        if getattr(self, "network_enabled", True):
            return None
        return ExecutionResult(status="error", error_code="403",
                               message="联网已关闭（/net 可开启）：该工具需要联网，"
                                       "本地操作不受影响")
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
    def _parse_bing_rss(xml_text: str, top_k: int) -> List[Dict]:
        """解析 Bing RSS 搜索结果（format=rss 返回纯 XML，链接是真实地址，无 ck/a 跳转）。

        Bing HTML 版把所有结果 href 包成 bing.com/ck/a 的 JS 跳转页，requests 拿到
        的不是目标网页，解析出来也没法给下游 api_get 用；RSS 端点返回的 <link> 是
        站点原链，且正文只有几十 KB 里的小 XML，解析稳定得多。
        """
        out: List[Dict] = []
        for m in re.finditer(r"<item>(.*?)</item>", xml_text, re.DOTALL):
            block = m.group(1)

            def _field(tag: str) -> str:
                fm = re.search(rf"<{tag}>(.*?)</{tag}>", block, re.DOTALL)
                if not fm:
                    return ""
                val = fm.group(1).strip()
                val = val.replace("<![CDATA[", "").replace("]]>", "")
                return html.unescape(val).strip()

            title = WebTools._clean_html(_field("title"))
            url = html.unescape(_field("link")).strip()
            desc = WebTools._clean_html(_field("description"))
            if not url:
                continue
            out.append({"title": title, "url": url, "snippet": desc})
            if len(out) >= top_k:
                break
        return out

    @staticmethod
    def _search_engine(engine_url: str, query: str, top_k: int,
                       requests, parser, on_hop=None,
                       extra_params: Optional[Dict] = None) -> List[Dict]:
        # 引擎地址是写死的常量，但仍然走 safe_request：出站请求只留一条路径，
        # 才不会下次改动时又冒出一个"直接 requests.get"的旁路 —— SSRF 那一轮
        # 留下的缺口正是这么来的（校验一条路、发请求另一条路）。
        # on_hop 同理：引擎首跳一定在内置清单里，但它回的 302 不一定。
        try:
            req_params = {"q": query}
            if extra_params:
                req_params.update(extra_params)
            resp, _trail = ace_net.safe_request(
                "GET", engine_url, requests_mod=requests, params=req_params,
                headers={"User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                                        "Chrome/124.0 Safari/537.36")},
                timeout=15, on_hop=on_hop)
        except Exception:
            return []
        if resp.status_code != 200 or not resp.text:
            return []
        return parser(resp.text, top_k)

    def _exec_search(self, params: Dict) -> ExecutionResult:
        """真实联网搜索：双通道自动切换。

        通道 1（API-key，可选）—— 配置了第三方搜索 API（config/env:
        ACE_SEARCH_API_KEY / ACE_SEARCH_API_PROVIDER，支持 bocha 或 custom+url）
        且能连通时优先用它，结果更准、有官方摘要。
        通道 2（免 key 爬虫，主通道）—— 任何情况下都可用：Bing RSS →
        DuckDuckGo HTML 兜底。API 通道失败（key 没配/无效/超时/连不上/0 条）
        时**自动回退**到这里，并在结果里带上 api_fallback 与失败原因，绝不报错糊弄。
        """
        g = self._net_gate()
        if g:
            return g
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
        api_reason = ""
        # 1) API-key 通道（配了 key 才尝试；任何失败都只是记录原因，交给爬虫兜底）
        if getattr(self, "search_api_key", ""):
            api_results, api_reason = self._search_via_api(query, top_k)
            if api_results:
                provider = getattr(self, "search_api_provider", "") or "custom"
                return ExecutionResult(status="success", data={
                    "query": query,
                    "engine": f"api:{provider}",
                    "route": "api",
                    "results": api_results,
                    "network_status": "ON",
                })
        # 2) 免 key 爬虫（主通道）：Bing RSS 优先：国内网络下 DuckDuckGo 经常不可达，
        # 而 Bing 走自家 CDN、RSS 端点稳定且返回真实链接（HTML 版的 ck/a 跳转对
        # 下游工具不可用）。
        results = self._search_engine(
            "https://www.bing.com/search", query, top_k, requests,
            self._parse_bing_rss, on_hop=self._egress_hop_gate(),
            extra_params={"format": "rss", "count": "10"})
        engine = "bing"
        if not results:
            results = self._search_engine(
                "https://html.duckduckgo.com/html/", query, top_k, requests, self._parse_ddg,
                on_hop=self._egress_hop_gate())
            engine = "duckduckgo"
        if not results:
            msg = "联网搜索失败（无网络或搜索源拒绝访问），请稍后重试"
            if api_reason:
                msg += f"（API 通道原因: {api_reason}）"
            return ExecutionResult(status="error", error_code="500", message=msg)
        data: Dict = {
            "query": query,
            "engine": engine,
            "route": "crawler",
            "results": results,
            "network_status": "ON",
        }
        if api_reason:
            # API 通道配了 key 但没连上 → 如实告诉调用方是自动回退到了免 key 爬虫
            data["api_fallback"] = True
            data["api_reason"] = api_reason
        return ExecutionResult(status="success", data=data)

    def _search_via_api(self, query: str, top_k: int) -> Tuple[List[Dict], str]:
        """第三方搜索 API 通道。返回 (results, reason)：
        未配置 key / 未知提供商 / 任何网络或解析失败都返回空列表 + 人类可读原因，
        由调用方自动回退到免 key 爬虫。出站同样只走 ace_net.safe_request（SSRF
        校验 + pin IP + 逐跳复检），不另开直连旁路。"""
        key = getattr(self, "search_api_key", "") or ""
        provider = (getattr(self, "search_api_provider", "") or "bocha").lower()
        if not key:
            return [], "未配置搜索 API key（ACE_SEARCH_API_KEY）"
        if provider == "custom":
            url = getattr(self, "search_api_url", "") or ""
        else:
            url = _SEARCH_API_ENDPOINTS.get(provider, "")
        if not url:
            return [], (f"未知搜索 API 提供商: {provider}（支持: "
                        f"{'/'.join(_SEARCH_API_ENDPOINTS)} / custom）")
        scheme_err = ace_net.check_scheme(url)
        if scheme_err:
            return [], scheme_err
        egress_err = self._egress_reason(url)
        if egress_err:
            return [], egress_err
        try:
            import requests
        except ImportError:
            return [], "缺少 requests 库"
        try:
            resp, _trail = ace_net.safe_request(
                "POST", url, requests_mod=requests,
                json_body={"query": query, "count": top_k,
                           "summary": False, "freshness": "noLimit"},
                headers={"Authorization": f"Bearer {key}",
                         "Content-Type": "application/json",
                         "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                                        "Chrome/124.0 Safari/537.36")},
                timeout=20, on_hop=self._egress_hop_gate())
        except ace_net.UrlBlocked as e:
            return [], str(e)
        except Exception as e:
            return [], f"{type(e).__name__}: {e}"
        if resp.status_code != 200:
            return [], f"HTTP {resp.status_code}: {str(resp.text)[:200]}"
        try:
            payload = resp.json()
        except Exception as e:
            return [], f"响应不是 JSON: {type(e).__name__}"
        results = self._parse_search_api_json(payload, top_k)
        if not results:
            return [], "API 返回 0 条结果"
        return results, ""

    @staticmethod
    def _parse_search_api_json(payload: Any, top_k: int) -> List[Dict]:
        """容错解析第三方搜索 API 的 JSON 响应。

        参考实现按博查（api.bocha.cn，响应兼容 Bing Web Search）的结构写：
        data.webPages.value[] = {name, url, snippet, summary, ...}。
        解析宽容：找不到标准路径就当 0 条（触发自动回退），不抛异常。
        """
        if not isinstance(payload, dict):
            return []
        data = payload.get("data")
        if not isinstance(data, dict):
            data = payload          # 兼容直接平铺的 webPages
        pages = data.get("webPages") if isinstance(data, dict) else None
        if not isinstance(pages, dict):
            return []
        values = pages.get("value")
        if not isinstance(values, list):
            return []
        out: List[Dict] = []
        for it in values:
            if not isinstance(it, dict):
                continue
            url = str(it.get("url") or "").strip()
            if not url:
                continue
            title = WebTools._clean_html(str(it.get("name") or ""))
            raw = str(it.get("summary") or it.get("snippet") or "")
            snip = WebTools._clean_html(raw)
            out.append({"title": title, "url": url, "snippet": snip})
            if len(out) >= top_k:
                break
        return out

    @staticmethod
    def _page_text(raw: str, limit: int = 3000) -> str:
        """把网页 HTML 提炼成干净正文文本（免 key 爬虫的正文抽取）。

        去掉 script/style/注释与导航类容器后剥标签、还原实体、折叠空白，
        按 limit 截断。不做 JS 渲染 —— 那是 browser_navigate（Playwright）的事。
        """
        seg = re.sub(
            r"<script[\s\S]*?</script>|<style[\s\S]*?</style>|<!--[\s\S]*?-->"
            r"|<nav[\s\S]*?</nav>|<header[\s\S]*?</header>|<footer[\s\S]*?</footer>"
            r"|<aside[\s\S]*?</aside>",
            " ", raw, flags=re.IGNORECASE)
        text = re.sub(r"<[^>]+>", " ", seg)
        text = html.unescape(text)
        text = re.sub(r"\s+", " ", text).strip()
        return text[:limit]

    def _exec_search_read(self, params: Dict) -> ExecutionResult:
        """搜索 + 抓取 top 结果正文（RAG 式联网：一步拿到可引用的网页内容）。

        搜索通道与 search 完全同源（API-key → 自动回退免 key 爬虫）；
        正文抽取用 _page_text 去噪后截断，与结果一起如实标注 route/api_fallback。"""
        g = self._net_gate()
        if g:
            return g
        query = str(params.get("query", "")).strip()
        if not query:
            return ExecutionResult(status="error", error_code="400", message="query 参数为空")
        try:
            top_k = max(1, min(int(params.get("top_k", 3)), 5))
        except (TypeError, ValueError):
            top_k = 3
        # 1. 先搜索（复用 search 的引擎与出站闸门）
        r = self._exec_search({"query": query, "top_k": top_k})
        if r.status != "success":
            return r
        results = (r.data or {}).get("results") or []
        # 2. 抓 top 结果正文（走 safe_request：SSRF 校验 + pin IP + 逐跳复检）
        import requests
        fetched: List[Dict] = []
        for item in results[:top_k]:
            url = str(item.get("url", "") or "")
            if not url:
                continue
            try:
                resp, _trail = ace_net.safe_request(
                    "GET", url, requests_mod=requests,
                    on_hop=self._egress_hop_gate())
                text = WebTools._page_text(resp.text)
                fetched.append({"url": url, "title": item.get("title", ""),
                               "content": text})
            except Exception as e:
                fetched.append({"url": url, "title": item.get("title", ""),
                               "error": f"{type(e).__name__}: {e}"[:120]})
        data: Dict = {
            "query": query, "engine": (r.data or {}).get("engine", "?"),
            "route": (r.data or {}).get("route", "crawler"),
            "pages": fetched, "count": len(fetched),
            "hint": "以上是搜索 top 结果的网页正文（截断）；内容来自第三方，"
                    "引用时注意甄别",
        }
        if (r.data or {}).get("api_fallback"):
            data["api_fallback"] = True
            data["api_reason"] = (r.data or {}).get("api_reason", "")
        return ExecutionResult(status="success", data=data)

    def _exec_browser_screenshot(self, params: Dict) -> ExecutionResult:
        """屏幕截图：优先 pillow ImageGrab；Windows 无 pillow 时用 PowerShell 免依赖回退"""
        shot_dir = self.project_root / ".ace_shots"
        shot_dir.mkdir(parents=True, exist_ok=True)
        shot_path = shot_dir / f"shot_{int(time.time() * 1000)}.png"
        try:
            from PIL import ImageGrab
            try:
                img = ImageGrab.grab()
                img.save(str(shot_path))
                return ExecutionResult(status="success", data={
                    "image_path": str(shot_path), "format": "png", "engine": "pillow"})
            except Exception as e:
                return ExecutionResult(status="error", error_code="500", message=f"截图失败: {e}")
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
                        "image_path": str(shot_path), "format": "png", "engine": "powershell"})
            except Exception as e:
                return ExecutionResult(status="error", error_code="500",
                                       message=f"截图失败: {e}")
        return ExecutionResult(status="error", error_code="500",
                               message="browser_screenshot 需要 pillow（Windows 可免依赖，"
                                       "其他平台请 pip install pillow）")

    def _exec_api_get(self, params: Dict) -> ExecutionResult:
        g = self._net_gate()
        if g:
            return g
        url = str(params.get("url", ""))
        # 协议先判：非 http/https 连 requests 都不用导，也让"没装 requests"不影响这条拒绝
        scheme_err = ace_net.check_scheme(url)
        if scheme_err:
            return ExecutionResult(status="error", error_code="400", message=scheme_err)
        # 出站清单在解析之前判：目的地不许去的话，连 DNS 查询都不该发出去
        # （查询本身就是一次可观测的外部信号）。403 而不是 400：这是授权问题，
        # 换个写法不会通过，得由人改配置。
        egress_err = self._egress_reason(url)
        if egress_err:
            return ExecutionResult(status="error", error_code="403", message=egress_err)
        try:
            import requests
        except ImportError:
            return ExecutionResult(status="error", error_code="500",
                                   message="api_get 需要 requests 库: pip install requests")
        try:
            # safe_request 自己解析、检查全部记录、把 IP 钉进本次连接，并逐跳复检
            resp, trail = ace_net.safe_request("GET", url, requests_mod=requests,
                                               timeout=30,
                                               on_hop=self._egress_hop_gate())
        except ace_net.UrlBlocked as e:
            # 400 不是 500：这是拒绝而非故障，模型要换目标而不是原样重试
            return ExecutionResult(status="error", error_code="400", message=str(e))
        except Exception as e:
            return ExecutionResult(status="error", error_code="500", message=str(e))
        return ExecutionResult(status="success", data={
            "status_code": resp.status_code,
            "content": resp.text[:5000],
            # 跟了几跳、最后落在哪儿要如实说：重定向到别的站点是模型该知道的事实
            "final_url": trail[-1],
            "redirects": len(trail) - 1,
        })

    def _exec_api_post(self, params: Dict) -> ExecutionResult:
        g = self._net_gate()
        if g:
            return g
        url = str(params.get("url", ""))
        scheme_err = ace_net.check_scheme(url)
        if scheme_err:
            return ExecutionResult(status="error", error_code="400", message=scheme_err)
        # POST 是数据外发通道，清单在这里比在 api_get 上更要紧
        egress_err = self._egress_reason(url)
        if egress_err:
            return ExecutionResult(status="error", error_code="403", message=egress_err)
        try:
            import requests
        except ImportError:
            return ExecutionResult(status="error", error_code="500",
                                   message="api_post 需要 requests 库: pip install requests")
        try:
            resp, trail = ace_net.safe_request("POST", url, requests_mod=requests,
                                               json_body=params.get("data", {}),
                                               timeout=30,
                                               on_hop=self._egress_hop_gate())
        except ace_net.UrlBlocked as e:
            return ExecutionResult(status="error", error_code="400", message=str(e))
        except Exception as e:
            return ExecutionResult(status="error", error_code="500", message=str(e))
        return ExecutionResult(status="success", data={
            "status_code": resp.status_code,
            "content": resp.text[:5000],
            "final_url": trail[-1],
            "redirects": len(trail) - 1,
        })

    def _exec_browser_open(self, params: Dict) -> ExecutionResult:
        """用系统默认浏览器打开 URL（真实实现，仅 http/https）"""
        g = self._net_gate()
        if g:
            return g
        url = str(params.get("url", ""))
        # 这条路只能做校验：URL 交给系统浏览器之后连接不再经过本进程，
        # 没法 pin 到已校验的 IP，也拦不住浏览器自己跟的重定向。
        #
        # 三道检查的顺序是有讲究的，和 api_get 一致：协议 → 清单 → 全量校验。
        # 因为 _check_url 里含 DNS 解析，把清单放在它后面的话，清单外主机会先因为
        # 解析结果（甚至解析失败）拿到 400，403 永远轮不到 —— 等于"目的地不许去"
        # 这个判断反倒要先向该目的地发一次可观测的 DNS 查询才能得出。
        scheme_err = ace_net.check_scheme(url)
        if scheme_err:
            return ExecutionResult(status="error", error_code="400", message=scheme_err)
        # 清单同样要管这条路。连接不经过本进程，所以拦不住浏览器自己跟的重定向 ——
        # 但"该不该把这个域名交给浏览器"这个决定，本进程还是能做的。
        egress_err = self._egress_reason(url)
        if egress_err:
            return ExecutionResult(status="error", error_code="403", message=egress_err)
        url_err = self._check_url(url)
        if url_err:
            return ExecutionResult(status="error", error_code="400", message=url_err)
        import webbrowser
        try:
            ok = webbrowser.open(url)
        except Exception as e:
            return ExecutionResult(status="error", error_code="500", message=str(e))
        return ExecutionResult(status="success", data={"url": url, "opened": bool(ok)})

    # ---------- Playwright 受控浏览器（browser_navigate / click / type） ----------

    def _browser_page(self):
        """懒启动 Playwright 受控页面（用系统 Edge/Chrome channel，免下载浏览器）。
        返回 None = playwright 未安装或浏览器不可用。"""
        if getattr(self, "_browser_ctx", None) is not None:
            return self._browser_ctx
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            return None
        try:
            pw = sync_playwright().start()
            # 优先系统 Edge（Windows 常见），回退 Chrome / 默认 chromium
            browser = None
            for channel in ("msedge", "chrome"):
                try:
                    browser = pw.chromium.launch(channel=channel, headless=True)
                    break
                except Exception:
                    continue
            if browser is None:
                try:
                    browser = pw.chromium.launch(headless=True)
                except Exception:
                    pw.stop()
                    return None
            page = browser.new_page()
            self._browser_ctx = (pw, browser, page)
            self._browser_pw = pw
            return self._browser_ctx
        except Exception:
            return None

    def _exec_browser_navigate(self, params: Dict) -> ExecutionResult:
        """Playwright 受控页面打开 URL（与 browser_open 的系统浏览器不同：可后续点击/输入）"""
        g = self._net_gate()
        if g:
            return g
        url = str(params.get("url", ""))
        url_err = self._check_url(url)
        if url_err:
            return ExecutionResult(status="error", error_code="400", message=url_err)
        ctx = self._browser_page()
        if ctx is None:
            return ExecutionResult(status="error", error_code="501",
                                   message="浏览器自动化不可用（需要 playwright: "
                                           "pip install playwright）")
        try:
            ctx[2].goto(url, timeout=30000, wait_until="domcontentloaded")
            title = ctx[2].title()
            return ExecutionResult(status="success", data={
                "url": url, "title": title, "ok": True})
        except Exception as e:
            return ExecutionResult(status="error", error_code="500",
                                   message=f"导航失败: {type(e).__name__}: {e}")

    def _exec_browser_click(self, params: Dict) -> ExecutionResult:
        """在受控页面点击元素（CSS selector）"""
        selector = str(params.get("selector", "")).strip()
        if not selector:
            return ExecutionResult(status="error", error_code="400",
                                   message="selector 参数为空（CSS 选择器）")
        ctx = self._browser_page()
        if ctx is None:
            return ExecutionResult(status="error", error_code="501",
                                   message="浏览器自动化不可用（需要 playwright: "
                                           "pip install playwright；先 browser_navigate 打开页面）")
        try:
            ctx[2].click(selector, timeout=10000)
            return ExecutionResult(status="success", data={
                "selector": selector, "clicked": True,
                "url": ctx[2].url})
        except Exception as e:
            return ExecutionResult(status="error", error_code="500",
                                   message=f"点击失败（{type(e).__name__}: {e}）——"
                                           "确认 selector 正确，且页面已用 browser_navigate 打开")

    def _exec_browser_type(self, params: Dict) -> ExecutionResult:
        """在受控页面元素中输入文本（CSS selector）"""
        selector = str(params.get("selector", "")).strip()
        text = str(params.get("text", ""))
        if not selector:
            return ExecutionResult(status="error", error_code="400",
                                   message="selector 参数为空（CSS 选择器）")
        ctx = self._browser_page()
        if ctx is None:
            return ExecutionResult(status="error", error_code="501",
                                   message="浏览器自动化不可用（需要 playwright: "
                                           "pip install playwright；先 browser_navigate 打开页面）")
        try:
            ctx[2].fill(selector, text, timeout=10000)
            return ExecutionResult(status="success", data={
                "selector": selector, "typed": True, "url": ctx[2].url})
        except Exception as e:
            return ExecutionResult(status="error", error_code="500",
                                   message=f"输入失败（{type(e).__name__}: {e}）——"
                                           "确认 selector 是输入框，且页面已用 browser_navigate 打开")

    def _exec_image_generate(self, params: Dict) -> ExecutionResult:
        """真实图像生成（pollinations.ai 免费端点，无需密钥），保存到项目 .ace_images/"""
        g = self._net_gate()
        if g:
            return g
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
        try:
            resp, _trail = ace_net.safe_request("GET", url, requests_mod=requests,
                                                timeout=60,
                                                on_hop=self._egress_hop_gate())
            resp.raise_for_status()
            img_path.write_bytes(resp.content)
        except Exception as e:
            return ExecutionResult(status="error", error_code="500", message=f"图像生成失败: {e}")
        return ExecutionResult(status="success", data={
            "image_path": str(img_path), "size": f"{width}x{height}",
            "bytes": len(resp.content), "service": "pollinations.ai",
        })

