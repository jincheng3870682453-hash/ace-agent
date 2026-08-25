#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ace_net —— 出站网络访问的统一闸门（SSRF 防护，对应 SEC-008）

为什么独立成一个模块，而不是继续在 `tools.base._check_url` 里加判断：
旧实现把"校验 URL"和"发起请求"当成两件互不相干的事 —— 校验时 `getaddrinfo`
看一眼，`requests` 随后自己再解析一次、自己跟重定向。校验结果没有任何一条
传到实际连接上，于是留下四个窗口：

  1. **多记录只看第一条**：`for info in getaddrinfo(...)` 里带着 `break`，
     第一条是公网就放行，后面挂着的 `127.0.0.1` 根本不看。
  2. **解析失败等于放行**：`except Exception: pass` —— 解析不出来反而畅通。
  3. **校验没 pin 到连接**：两次解析之间攻击者可以换答案（DNS rebinding）。
  4. **重定向完全不复检**：`allow_redirects` 默认 True，公网地址 302 到
     `http://127.0.0.1:8080/` 即可，这条路径连 DNS 缓存行为都不依赖，最稳。

所以这里提供的不是"更严格的校验函数"，而是一条**校验与连接绑定**的请求路径
`safe_request()`：自己解析 → 检查全部记录 → 把 DNS 结果钉死在本次连接上 →
关掉自动重定向、每一跳重新走一遍。

`check_url()` 只保留给无法接管连接的场景（例如 `browser_open` 把 URL 交给系统
浏览器）。凡是本进程自己发的请求，都必须走 `safe_request()` —— 校验和连接一分开，
上面第 3、4 条就立刻回来了。
"""

import contextlib
import ipaddress
import socket
import threading
import urllib.parse
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

ALLOWED_SCHEMES = ("http", "https")
MAX_REDIRECTS = 5
DEFAULT_TIMEOUT = 30
REDIRECT_CODES = (301, 302, 303, 307, 308)

# 运营商级 NAT（RFC 6598）。`is_private` 不含它，但它同样是"到不了公网、
# 却可能到得了别人内网"的地址段。
_CGNAT_V4 = ipaddress.ip_network("100.64.0.0/10")


class UrlBlocked(Exception):
    """URL 未通过出站校验。

    调用方应把它映射成 4xx 而不是 5xx：这是**拒绝**，不是故障 ——
    模型看到 4xx 才知道该换目标，看到 5xx 只会原样重试。
    """


# ---------------------------------------------------------------- IP 判定

def _inner_addrs(addr) -> List[Any]:
    """展开 IPv6 里包着的 IPv4 表示法，返回需要一并检查的地址列表。

    `::ffff:127.0.0.1`、6to4、Teredo 在 `ipaddress` 眼里都只是"某个 IPv6 地址"，
    不展开的话回环和内网就能靠这层包装混过去。
    展开出来的地址排在前面：`::ffff:127.0.0.1` 本身也满足 `is_private`，
    先看里层才能给出"回环"这个准确原因，而不是含糊的"内网"。
    """
    if addr.version != 6:
        return [addr]
    out: List[Any] = []
    mapped = addr.ipv4_mapped
    if mapped is not None:
        out.append(mapped)
    sixtofour = getattr(addr, "sixtofour", None)
    if sixtofour is not None:
        out.append(sixtofour)
    teredo = getattr(addr, "teredo", None)
    if isinstance(teredo, tuple):
        out.extend([t for t in teredo if t is not None])
    out.append(addr)
    return out


def _category(addr) -> Optional[str]:
    """单个地址的拒绝原因；None 表示这是个可以访问的公网地址。

    顺序有讲究：回环/链路本地也满足 `is_private`，先判具体类别才能给出
    有用的原因（"回环" 比 "内网" 更能让人一眼看懂拦的是什么）。
    """
    if addr.is_loopback:
        return "拒绝访问回环地址"
    if addr.is_link_local:
        return "拒绝访问链路本地地址（含 169.254.169.254 云元数据端点）"
    if addr.is_multicast:
        return "拒绝访问组播地址"
    if addr.is_unspecified:
        return "拒绝访问未指定地址"
    if addr.is_private:
        return "拒绝访问内网地址"
    if addr.is_reserved:
        return "拒绝访问保留地址"
    if addr.version == 4 and addr in _CGNAT_V4:
        return "拒绝访问运营商级 NAT 地址"
    # 兜底：上面逐类列举总会漏（新分配的特殊段、IPv6 的各种保留前缀），
    # 所以最后再问一次标准库"这算公网吗"。方向是 fail-closed。
    if not addr.is_global:
        return "拒绝访问非公网地址"
    return None


def ip_reject_reason(ip_str: str) -> Optional[str]:
    """IP 字符串的拒绝原因；None = 允许。无法解析的一律拒绝（不是放行）。"""
    raw = str(ip_str).split("%")[0].strip().strip("[]")
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return f"无法解析为 IP 地址，拒绝访问: {ip_str}"
    for cand in _inner_addrs(addr):
        reason = _category(cand)
        if reason:
            return f"{reason}: {ip_str}"
    return None


# ---------------------------------------------------------------- 解析

def _as_literal(host: str) -> Optional[str]:
    """host 本身就是 IP 字面量时返回规范化字符串，否则 None（需要 DNS）。"""
    raw = str(host).strip().strip("[]")
    try:
        ipaddress.ip_address(raw)
    except ValueError:
        return None
    return raw


def _port_num(port: Any, scheme: str = "http") -> int:
    if isinstance(port, int):
        return port
    if isinstance(port, str) and port:
        try:
            return int(port)
        except ValueError:
            try:
                return socket.getservbyname(port)
            except OSError:
                pass
    return 443 if scheme == "https" else 80


def resolve_host(host: str, port: int = 0, *, resolver=None) -> List[str]:
    """解析主机名，并检查**每一条**返回记录；任一条命中内网即整体拒绝。

    抛 `UrlBlocked` 表示不允许访问 —— 包括解析失败。解析不出来就不该连，
    旧实现在这里 `except Exception: pass`，是四个窗口里最容易利用的一条：
    攻击者只要让第一次解析报错，校验就整段跳过。

    `resolver` 仅用于测试注入（签名同 `socket.getaddrinfo`）。
    """
    literal = _as_literal(host)
    if literal is not None:
        reason = ip_reject_reason(literal)
        if reason:
            raise UrlBlocked(reason)
        return [literal]

    getaddrinfo = resolver or socket.getaddrinfo
    try:
        infos = getaddrinfo(host, port or 0, 0, socket.SOCK_STREAM)
    except Exception as e:
        raise UrlBlocked(f"DNS 解析失败，拒绝访问 {host}（{e.__class__.__name__}: {e}）")

    ips: List[str] = []
    for info in infos:
        try:
            ip = str(info[4][0]).split("%")[0]
        except (IndexError, TypeError):
            continue
        if ip and ip not in ips:
            ips.append(ip)
    if not ips:
        raise UrlBlocked(f"DNS 未返回任何地址，拒绝访问 {host}")

    for ip in ips:
        reason = ip_reject_reason(ip)
        if reason:
            # 不 break：一个域名可以同时挂公网和内网记录，只看第一条就等于没查。
            raise UrlBlocked(f"{reason}（{host} 的解析结果之一）")
    return ips


# ---------------------------------------------------------------- URL 校验

def check_scheme(url: Any) -> Optional[str]:
    """只看协议，不做 DNS。用于"连库都还没导入就该拒绝"的早期判断。"""
    try:
        parsed = urllib.parse.urlsplit(str(url))
        scheme = (parsed.scheme or "").lower()
    except Exception:
        return "URL 解析失败"
    if not scheme:
        return "URL 缺少协议（需要 http/https）"
    if scheme not in ALLOWED_SCHEMES:
        return f"仅支持 http/https 协议，拒绝: {scheme}"
    return None


def validate_url(url: str, *, resolve: bool = True, resolver=None) -> Dict[str, Any]:
    """校验单个 URL，返回 {scheme, host, port, ips, url}；不合规抛 UrlBlocked。"""
    err = check_scheme(url)
    if err:
        raise UrlBlocked(err)
    parsed = urllib.parse.urlsplit(str(url))
    if "\\" in parsed.netloc:
        # 反斜杠必须直接拒绝，而不是"解析出主机名就算过"：`urlsplit` 把 `\` 当成
        # userinfo 的普通字符，浏览器（WHATWG URL）把它当成路径分隔符 `/` ——
        # 同一个字符串两边解析出**不同的主机**。实测 `http://127.0.0.1\@ok.tld/x`：
        # urlsplit 认为主机是 `ok.tld`（过 SSRF 判定、过白名单），浏览器认为主机是
        # `127.0.0.1`、路径是 `/@ok.tld/x`。凡是"校验方与执行方对同一输入理解不同"
        # 的地方，校验就是空的；`browser_open` 的执行方正是系统浏览器。
        raise UrlBlocked("URL 主机部分含反斜杠，拒绝（浏览器与解析器对它的理解不一致）")
    scheme = parsed.scheme.lower()
    try:
        raw_port = parsed.port
    except ValueError:
        raise UrlBlocked("URL 端口非法")
    host = parsed.hostname
    if not host:
        raise UrlBlocked("URL 缺少主机名")
    port = _port_num(raw_port, scheme)
    ips = resolve_host(host, port, resolver=resolver) if resolve else []
    return {"scheme": scheme, "host": host, "port": port, "ips": ips, "url": str(url)}


def check_url(url: str, *, resolve: bool = True) -> Optional[str]:
    """不抛异常的校验入口：通过返回 None，否则返回拒绝原因文本。"""
    try:
        validate_url(url, resolve=resolve)
    except UrlBlocked as e:
        return str(e)
    return None


# ---------------------------------------------------------------- 出站白名单
#
# SEC-013 的另一半。上面所有 IP 判定回答的都是同一个问题："这个地址是不是内网"，
# 它挡不住 `https://evil.tld/?data=<.env 内容>` —— 目标是个规规矩矩的公网地址，
# 每一条记录都过检，数据照样带走了。要挡这条只能改判据：按**目的地**判定。
#
# 为什么是"目的地"粒度而不是"每次取网页都点一下"：`api_get` 是模型查文档、
# 调接口的日常工具，逐次确认会把它变成每轮都要点的噪音，而噪音会训练用户无脑点
# 同意（同 SEC-002 另一半的理由）。所以清单内直接放行，清单外问一次，并且这类
# 审批的 `rule` 是 `egress:<host>` —— hook 的 "a" 能把这个域名记住整场会话。
# 这与抓屏 / 外发（`rule` 为空、每次都问）刻意不同：换一个域名是一个新决定，
# 同一个域名的第二次请求不是。
#
# 明确的残留风险：一个域名一旦被批准，后续请求可以往它的查询串里塞任何东西。
# 这是"目的地粒度"这个选择自带的代价，不是漏掉的分支 —— 消除它只能回到逐次确认。
_WILDCARD_ALL = ("*", "all")


# 默认清单只装 ACE 自己的工具本来就要访问的端点：search 的两个引擎、
# image_generate 的图像端点。为它们弹确认框等于给工具本身的用途加一道门。
DEFAULT_EGRESS_ALLOWLIST = (
    "duckduckgo.com",
    "bing.com",
    "pollinations.ai",
)


def normalize_host(host: Any) -> str:
    """小写、去掉 [] 与末尾点、IDN 转 punycode。比较前两边都要过这一步。

    末尾点必须去掉：`evil.tld.` 和 `evil.tld` 是同一台主机，DNS 认，
    字符串比较不认 —— 不规范化就等于给了一个一个字符的绕过。

    IDN 优先用 `idna` 库的 UTS-46 转换，因为 `requests` 实际发请求时用的就是它：
    实测 `faß.de` 在 `idna` 下是 `xn--fa-hia.de`，在标准库的 IDNA2003 下是
    `fass.de` —— **两个不同的主机**。判定用一套规则、连接用另一套规则，就会出现
    "判定看的是 A、连上去的是 B"，与连接层对齐比自己算得"更严"重要。
    """
    raw = str(host or "").strip().strip("[]").rstrip(".").lower()
    if not raw:
        return ""
    try:
        import idna as _idna
        return _idna.encode(raw, uts46=True).decode("ascii").lower()
    except Exception:
        # idna 未安装、或输入是 IP 字面量 / 含下划线的内部名（IDNAError）——
        # 都不是错误，往下退到标准库，最后原样返回。
        pass
    try:
        return raw.encode("idna").decode("ascii").lower()
    except (UnicodeError, UnicodeDecodeError):
        # IP 字面量、含下划线的内部名等 encode('idna') 会失败：原样返回即可，
        # 这里只是规范化，判定仍由下面的逐段比较负责。
        return raw


def normalize_entry(entry: Any) -> str:
    """把清单条目收成可比较的主机模式（保留 `*.` 前缀）。

    人写清单时会顺手写成 URL、带端口、带前导点：`https://api.mycorp.com/v1`、
    `api.mycorp.com:443`、`.mycorp.com`。这三种写法原先**永远不匹配** ——
    而失败的方向是"以为写了就放行了、实际每次都弹框"，用户的应对通常是随手点
    同意，等于把白名单变成了噪音源。所以在这里统一收干净，而不是要求人写得准。
    """
    raw = str(entry or "").strip().lower()
    if not raw:
        return ""
    if raw in _WILDCARD_ALL:
        return raw
    if "//" in raw:                      # 带协议：scheme://host/...
        raw = raw.split("//", 1)[1]
    raw = raw.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in raw:                       # userinfo@host
        raw = raw.rsplit("@", 1)[1]
    star = raw.startswith("*.")
    if star:
        raw = raw[2:]
    if raw.startswith("["):              # IPv6 字面量 [::1]:8080
        raw = raw.split("]", 1)[0].lstrip("[")
    elif raw.count(":") == 1:            # host:port（多个冒号 = 裸 IPv6，不动它）
        raw = raw.split(":", 1)[0]
    out = normalize_host(raw.lstrip("."))
    return ("*." + out) if (star and out) else out


def _match_normalized(h: str, e: str) -> bool:
    """h 已规范化的主机、e 已规范化的条目之间的比较。"""
    if not h or not e:
        return False
    if e in _WILDCARD_ALL:
        return True
    if e.startswith("*."):
        e = e[2:]
        return bool(e) and h.endswith("." + e)
    return h == e or h.endswith("." + e)


def host_matches(host: str, entry: str) -> bool:
    """单条清单项的匹配。`example.com` 同时匹配 `example.com` 与 `*.example.com`。

    只在**标签边界**上做后缀匹配：`notexample.com` 不该命中 `example.com`，
    而纯字符串 `endswith` 会让它命中 —— 那是个能注册域名就能利用的绕过。
    """
    return _match_normalized(normalize_host(host), normalize_entry(entry))


def host_in_allowlist(host: str, allowlist: Optional[Sequence[str]] = None) -> bool:
    entries = DEFAULT_EGRESS_ALLOWLIST if allowlist is None else allowlist
    # 主机只规范化一次：条目通常只有几条，主机侧的 IDNA 转换才是那笔开销。
    h = normalize_host(host)
    if not h:
        return False
    return any(_match_normalized(h, normalize_entry(e)) for e in entries or ())


def url_host(url: Any) -> str:
    """从 URL 里取规范化后的主机名；取不到返回空串（调用方按"不在清单里"处理）。"""
    try:
        return normalize_host(urllib.parse.urlsplit(str(url)).hostname or "")
    except Exception:
        return ""


def url_in_allowlist(url: Any, allowlist: Optional[Sequence[str]] = None) -> bool:
    host = url_host(url)
    return bool(host) and host_in_allowlist(host, allowlist)


def effective_allowlist(allowlist: Sequence[str]) -> tuple:
    """配置的条目 ∪ 内置端点。

    并进 DEFAULT_EGRESS_ALLOWLIST 而不是让配置完全覆盖：用户收紧清单是为了限制
    **模型自己挑的**目的地，不是为了把 search / image_generate 这些工具本身弄坏。
    如果覆盖，那么"配了清单"的第一个可见后果是联网搜索不能用了 —— 用户会把这
    理解成功能坏了，然后把清单删掉，闸门也就没了。
    """
    return tuple(allowlist) + tuple(DEFAULT_EGRESS_ALLOWLIST)


def egress_reject_reason(url: Any,
                         allowlist: Optional[Sequence[str]] = None) -> Optional[str]:
    """出站目的地判定：放行返回 None，否则返回可直接给模型看的拒绝原因。

    **注意 `allowlist=None` 在这里的含义和 `host_in_allowlist` 相反**：
    那边 None = 用内置清单，这里 None = **闸门关闭，一律放行**。看着像是自找麻烦，
    但两个默认值各自的方向都是对的：`host_in_allowlist` 是个判定函数，问它
    "在不在清单里"总得有个清单；而这个函数是闸门入口，宿主**没配**清单时
    正确行为是不拦（否则升级到这个版本的人会发现 api_get 突然全废）。
    真正危险的是把两者混为一谈，所以这里不复用那边的 None 分支，显式分开写。

    空清单（`[]`）与 None 不同：那是"配了，但一条都不许" —— 除内置端点外全拦。
    """
    if allowlist is None:
        return None
    entries = effective_allowlist(allowlist)
    if any(normalize_entry(e) in _WILDCARD_ALL for e in entries):
        return None
    host = url_host(url)
    if not host:
        return "ACE 出站拦截：URL 里取不出主机名"
    if host_in_allowlist(host, entries):
        return None
    shown = ", ".join(str(e) for e in allowlist) or "（空）"
    return (f"ACE 出站拦截：{host} 不在出站白名单里。"
            f"当前清单: {shown}（另含内置端点 "
            f"{', '.join(DEFAULT_EGRESS_ALLOWLIST)}）。"
            "这不是网络故障，重试同一个地址不会变。要么改用清单内的地址，"
            "要么请用户把该域名加进配置 egress_allowlist —— 你自己加不了。")



# ---------------------------------------------------------------- pin-to-IP

# 把已校验的解析结果钉到实际连接上。
#
# 实现方式是在请求期间接管 `socket.getaddrinfo`，而不是"把 URL 里的主机名换成 IP"：
# 换 URL 会同时毁掉 SNI、证书校验和 Host 头，为了防 SSRF 去关掉 TLS 校验是把
# 一个洞换成另一个洞。接管解析则让 requests/urllib3 拿到的就是我们校验过的那几个
# IP，主机名一路保持原样。
#
# 只对**被 pin 的主机**生效：其它主机名照常走真实解析、不做拦截。这是刻意的 ——
# 本模块不该顺手管住同进程里别人的连接（比如指向 127.0.0.1 的本地模型网关）。
# 本次请求的出站目标由 pin 约束，重定向由 safe_request 逐跳复检，够了。
#
# 已知边界：配置了 HTTP(S)_PROXY 时，目标主机名不在本机解析，实际出站由代理完成，
# pin 只能约束到代理这一跳。代理是用户显式配置的基础设施（不是模型能控制的输入），
# 这条边界写在 docs/SECURITY-AUDIT.md 里，不在这里偷偷收紧。
_PIN_LOCK = threading.RLock()
_PIN_MAP: Dict[str, List[str]] = {}
_PIN_DEPTH = 0
_REAL_GETADDRINFO = socket.getaddrinfo


def _pin_entries(ips: Sequence[str], port: Any, family: int, socktype: int,
                 proto: int) -> List[Tuple]:
    entries: List[Tuple] = []
    pnum = _port_num(port)
    stype = socktype or socket.SOCK_STREAM
    for ip in ips:
        try:
            addr = ipaddress.ip_address(str(ip))
        except ValueError:
            continue
        if addr.version == 6:
            if family in (socket.AF_INET,):
                continue
            entries.append((socket.AF_INET6, stype, proto, "", (str(addr), pnum, 0, 0)))
        else:
            if family in (socket.AF_INET6,):
                continue
            entries.append((socket.AF_INET, stype, proto, "", (str(addr), pnum)))
    return entries


def _guarded_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    key = str(host).strip("[]").lower() if host else ""
    with _PIN_LOCK:
        pinned = _PIN_MAP.get(key)
    if not pinned:
        return _REAL_GETADDRINFO(host, port, family, type, proto, flags)
    entries = _pin_entries(pinned, port, family, type, proto)
    if not entries:
        # 请求的地址族和校验结果对不上：拒绝，而不是回退到真实解析 ——
        # 回退就等于把 pin 让掉了。
        raise socket.gaierror(f"ACE 出站拦截：{host} 无可用的已校验地址")
    return entries


@contextlib.contextmanager
def pin_host(host: str, ips: Sequence[str]):
    """在上下文内，把 host 的解析结果固定为 ips（已校验过的公网地址）。"""
    global _PIN_DEPTH
    key = str(host).strip("[]").lower()
    with _PIN_LOCK:
        previous = _PIN_MAP.get(key)
        _PIN_MAP[key] = list(ips)
        _PIN_DEPTH += 1
        if _PIN_DEPTH == 1:
            socket.getaddrinfo = _guarded_getaddrinfo
    try:
        yield
    finally:
        with _PIN_LOCK:
            if previous is None:
                _PIN_MAP.pop(key, None)
            else:
                _PIN_MAP[key] = previous
            _PIN_DEPTH -= 1
            if _PIN_DEPTH <= 0:
                _PIN_DEPTH = 0
                _PIN_MAP.clear()
                socket.getaddrinfo = _REAL_GETADDRINFO


# ---------------------------------------------------------------- 请求

def safe_request(method: str, url: str, *, requests_mod=None,
                 timeout: int = DEFAULT_TIMEOUT, headers: Optional[Dict] = None,
                 params: Any = None, json_body: Any = None, data: Any = None,
                 stream: bool = False, max_redirects: int = MAX_REDIRECTS,
                 resolver=None,
                 on_hop: Optional[Callable[[str], Optional[str]]] = None
                 ) -> Tuple[Any, List[str]]:
    """发一个 http/https 请求，返回 (response, 跳转链)。被拒绝时抛 UrlBlocked。

    与 `requests.get(url)` 的区别全在两处：
    - 每一跳都先 `validate_url` 再在 `pin_host` 里发出去（校验 = 连接）；
    - `allow_redirects=False`，重定向由这里手动跟，Location 要重新过一遍校验。

    `on_hop(next_url)` 是**调用方的**逐跳判定（返回拒绝原因字符串即中止，None 放行）。
    `validate_url` 只回答"是不是内网"，答不了"这个目的地允不允许"——而后者的判定
    在首跳做完就失效了：清单内的任意开放重定向器都能把首跳判定变成一句空话
    （`duckduckgo.com/l/?uddg=…` 就是一个，本项目自己的 `_parse_ddg` 正在解它）。
    所以出站白名单必须逐跳复检，而白名单/确认框只有工具层拿得到，这里留回调。
    首跳**不**过 `on_hop`：那一跳由调用方在发请求前自己判过了，再问一遍是同一个
    决定问两遍。
    """
    if requests_mod is None:
        import requests as requests_mod  # noqa: N806

    verb = str(method).upper()
    body: Dict[str, Any] = {}
    if json_body is not None:
        body["json"] = json_body
    if data is not None:
        body["data"] = data

    current = str(url)
    trail: List[str] = []
    query = params
    for _hop in range(max_redirects + 1):
        info = validate_url(current, resolver=resolver)
        trail.append(current)
        with pin_host(str(info["host"]), list(info["ips"])):
            resp = requests_mod.request(
                verb, current, timeout=timeout, headers=headers, params=query,
                allow_redirects=False, stream=stream, **body)

        location = ""
        try:
            if resp.status_code in REDIRECT_CODES:
                location = resp.headers.get("Location") or ""
        except AttributeError:
            location = ""
        if not location:
            return resp, trail

        nxt = urllib.parse.urljoin(current, location)
        if on_hop is not None:
            denial = on_hop(nxt)
            if denial:
                # 拒绝原因原样抛出：调用方（工具层）比这里更清楚为什么拒。
                raise UrlBlocked(str(denial))
        if resp.status_code in (301, 302, 303) and verb not in ("GET", "HEAD"):
            # 与浏览器/requests 的行为一致：这三个码把方法降级为 GET 并丢掉请求体。
            # 顺带一个安全收益：POST 的数据不会被 302 转发到第二个站点。
            verb, body = "GET", {}
        # 查询串已经在 Location 里了，再带一次会重复
        query = None
        current = nxt

    raise UrlBlocked(f"重定向超过 {max_redirects} 跳，已中止: " + " -> ".join(trail))


def safe_get(url: str, **kw) -> Tuple[Any, List[str]]:
    return safe_request("GET", url, **kw)


def safe_post(url: str, **kw) -> Tuple[Any, List[str]]:
    return safe_request("POST", url, **kw)
