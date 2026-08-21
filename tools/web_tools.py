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
import ipaddress
from pathlib import Path
from typing import Any, Dict, List

from tools.result import ExecutionResult


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
                       requests, parser) -> List[Dict]:
        try:
            resp = requests.get(
                engine_url, params={"q": query},
                headers={"User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                                        "Chrome/124.0 Safari/537.36")},
                timeout=15)
        except Exception:
            return []
        if resp.status_code != 200 or not resp.text:
            return []
        return parser(resp.text, top_k)

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
        results = self._search_engine(
            "https://html.duckduckgo.com/html/", query, top_k, requests, self._parse_ddg)
        engine = "duckduckgo"
        if not results:
            results = self._search_engine(
                "https://www.bing.com/search", query, top_k, requests, self._parse_bing)
            engine = "bing"
        if not results:
            return ExecutionResult(status="error", error_code="500",
                                   message="联网搜索失败（无网络或搜索源拒绝访问），请稍后重试")
        return ExecutionResult(status="success", data={
            "query": query,
            "engine": engine,
            "results": results,
            "network_status": "ON",
        })

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
        url = str(params.get("url", ""))
        url_err = self._check_url(url)
        if url_err:
            return ExecutionResult(status="error", error_code="400", message=url_err)
        try:
            import requests
            resp = requests.get(url, timeout=30)
            return ExecutionResult(status="success", data={
                "status_code": resp.status_code,
                "content": resp.text[:5000]
            })
        except Exception as e:
            return ExecutionResult(status="error", error_code="500", message=str(e))

    def _exec_api_post(self, params: Dict) -> ExecutionResult:
        url = str(params.get("url", ""))
        url_err = self._check_url(url)
        if url_err:
            return ExecutionResult(status="error", error_code="400", message=url_err)
        try:
            import requests
            resp = requests.post(url, json=params.get("data", {}), timeout=30)
            return ExecutionResult(status="success", data={
                "status_code": resp.status_code,
                "content": resp.text[:5000]
            })
        except Exception as e:
            return ExecutionResult(status="error", error_code="500", message=str(e))

    def _exec_browser_open(self, params: Dict) -> ExecutionResult:
        """用系统默认浏览器打开 URL（真实实现，仅 http/https）"""
        url = str(params.get("url", ""))
        url_err = self._check_url(url)
        if url_err:
            return ExecutionResult(status="error", error_code="400", message=url_err)
        import webbrowser
        try:
            ok = webbrowser.open(url)
        except Exception as e:
            return ExecutionResult(status="error", error_code="500", message=str(e))
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
        try:
            resp = requests.get(url, timeout=60)
            resp.raise_for_status()
            img_path.write_bytes(resp.content)
        except Exception as e:
            return ExecutionResult(status="error", error_code="500", message=f"图像生成失败: {e}")
        return ExecutionResult(status="success", data={
            "image_path": str(img_path), "size": f"{width}x{height}",
            "bytes": len(resp.content), "service": "pollinations.ai",
        })

