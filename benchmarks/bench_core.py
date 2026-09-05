#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bench_core.py —— ACE 核心能力实测基准（纯标准库，不联网，无第三方依赖）

测量并报告**真实数字**（正确率 / 延迟 / 吞吐），替换文档里拍脑袋的百分比：
结果写入 benchmarks/results/（bench_report.md + bench_report.json），
任何机器、任何时间都能一键复现：

    python benchmarks/bench_core.py          # 全量
    python benchmarks/bench_core.py --quick  # 样本减半（CI 冒烟用）

指标分组（与 README「实测基准」一节对应）：
    parser     文档解析：格式覆盖 / 超长截断 / 平均耗时
    exec       工具链路往返 + 权限不足裁决（readonly→PERMISSION_REQUEST）
    guard      L4 守门：吞吐与正确率
    ast        AST 行为检测：6 规则正确率
    guardian   快照-回滚：字节一致性与耗时
    memory     SimHash 记忆：吞吐与基础语义

退出码恒为 0（基准如实报告，不因机器慢而红 CI）；
checks 段的 pass/fail 反映功能正确性。
"""

import json
import platform
import statistics
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr.encoding and sys.stderr.encoding.lower() not in ("utf-8", "utf8"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

FOLDER = Path(__file__).resolve().parent.parent  # ace 仓库根
sys.path.insert(0, str(FOLDER))

QUICK = "--quick" in sys.argv
SCALE = 0.5 if QUICK else 1.0
OUT_DIR = FOLDER / "benchmarks" / "results"

# 测试临时区（gitignore 覆盖 .test_tmp/）
TMP_ROOT = FOLDER / ".test_tmp"
TMP_ROOT.mkdir(exist_ok=True)


def mktemp(name: str = "bench") -> Path:
    d = TMP_ROOT / f"{name}_{uuid.uuid4().hex[:8]}"
    d.mkdir(parents=True, exist_ok=True)
    return d


# ---------------------------------------------------------------- 基础工具
def run_agent(el, tool: str, user: str = "基准输入", **params) -> dict:
    """按 <INTERNAL>/<EXTERNAL> 文本协议构造一次模型工具调用（与 test_all 同构）"""
    body = json.dumps({"tool": tool, **params}, ensure_ascii=False)
    out = (f"<INTERNAL>\n[INTERNAL_THINKING]\n[ACT] {tool}\n[/INTERNAL_THINKING]\n</INTERNAL>\n"
           f"<EXTERNAL>\nanswer.\n{body}\n</EXTERNAL>")
    return el.process_agent_output(out, user)


def time_ms(fn, n: int):
    """执行 n 次，返回 (每次平均毫秒, 全部成功否)。首轮作预热不计入。"""
    fn()  # 预热（import/缓存/平台初始化）
    ts = []
    ok = 0
    for i in range(n):
        t0 = time.perf_counter()
        good = fn()
        dt = (time.perf_counter() - t0) * 1000.0
        ts.append(dt)
        ok += 1 if good else 0
    return round(statistics.mean(ts), 3), ok


RESULT = []   # 指标行
CHECKS = []   # (名称, passed, 说明)


def metric(group, name, value, unit, samples, detail=""):
    RESULT.append({"group": group, "name": name, "value": value,
                   "unit": unit, "samples": samples, "detail": detail})


def check(name, cond, detail=""):
    CHECKS.append({"name": name, "passed": bool(cond), "detail": str(detail)})


# ================================================================ parser
print("[parser] 文档解析")
from universal_document_parser import parse_document  # noqa: E402

REPO_FILE = FOLDER / "prompts" / "agent_system_prompt_v7.md"
if REPO_FILE.exists():
    res = parse_document(REPO_FILE)
    check("md 直接解析成功", res.success and res.method == "direct_text"
          and "系统身份层" in res.text, res.method if hasattr(res, "method") else "")
    n = int(30 * SCALE)
    mean_ms, ok = time_ms(lambda: parse_document(REPO_FILE).success, n)
    metric("parser", "Markdown 解析平均耗时", mean_ms, "ms", n)
    check("Markdown 解析 100% 成功", ok == n, f"{ok}/{n}")

    # 格式覆盖：仓库真实文件 + 动态生成文本格式样例
    candidates = {
        "py": FOLDER / "i18n.py",
        "txt": FOLDER / "requirements.txt",
    }
    fmt_ok, fmt_list = 0, []
    for ext, p in candidates.items():
        if p.exists():
            r = parse_document(p)
            good = r.success and r.method == "direct_text"
            fmt_ok += good
            fmt_list.append(f"{ext}={good}")
            check(f"parse_document 解析 .{ext}", good, r.error[:80] if not good else "")
    samples_dir = mktemp("fmt")
    generated = {
        "json": '{"name": "ace", "version": 3, "tags": ["a", "b"]}\n',
        "csv": "id,name,score\n1,ace,99\n2,bench,88\n",
        "xml": "<root><item id=\"1\">ace</item></root>\n",
        "html": "<html><body><h1>ACE</h1><p>bench</p></body></html>\n",
        "yaml": "name: ace\nversion: 3.0\n",
    }
    for ext, content in generated.items():
        p = samples_dir / f"sample.{ext}"
        p.write_text(content, encoding="utf-8")
        r = parse_document(p)
        good = r.success and r.method == "direct_text"
        fmt_ok += good
        fmt_list.append(f"{ext}={good}")
        check(f"parse_document 解析 .{ext}", good, r.error[:80] if not good else "")
    fmt_total = len(fmt_list)
    metric("parser", "文本格式直接解析覆盖", f"{fmt_ok}/{fmt_total}", "格式",
           fmt_total, ", ".join(fmt_list))

    # 超长截断
    long_file = samples_dir / "long.txt"
    long_file.write_text("长" * 16000, encoding="utf-8")
    r2 = parse_document(long_file)
    check("16000 字超长文本截断", r2.truncated and len(r2.text) < 16000
          and r2.metadata.get("original_length") == 16000,
          f"len={len(r2.text)} truncated={r2.truncated}")

    # 缺失文件优雅报错
    r3 = parse_document(str(samples_dir / "不存在.docx"))
    check("缺失文件优雅报错", (not r3.success) and "不存在" in r3.error, r3.error)

# ================================================================ exec
print("[exec] 工具链路往返 + 权限裁决")
from execution_layer import ExecutionLayer  # noqa: E402

try:
    work_root = mktemp("exec")
    el_w = ExecutionLayer(project_root=str(work_root), permission_level="write",
                          config={"bait": {"enabled": False},
                                  "sandbox_base": str(TMP_ROOT)})
    n = int(120 * SCALE)

    def _roundtrip():
        r = run_agent(el_w, "terminal_view", command="echo bench-ping")
        return r["status"] == "SUCCESS" and "bench-ping" in r["data"].get("stdout", "")

    mean_ms, ok = time_ms(_roundtrip, n)
    metric("exec", "terminal_view 工具往返平均延迟", mean_ms, "ms", n)
    check("terminal_view 往返 100% 成功", ok == n, f"{ok}/{n}")

    def _datetime():
        return run_agent(el_w, "datetime_now", user="现在几点").get("status") == "SUCCESS"

    mean_dt, ok_dt = time_ms(_datetime, n)
    metric("exec", "datetime_now 往返平均延迟", mean_dt, "ms", n)
    check("datetime_now 100% 成功", ok_dt == n, f"{ok_dt}/{n}")

    # 权限不足裁决：readonly 下 terminal_exec -> PERMISSION_REQUEST
    el_ro = ExecutionLayer(project_root=str(mktemp("ro")), permission_level="readonly",
                           config={"bait": {"enabled": False},
                                   "sandbox_base": str(TMP_ROOT)})

    def _deny():
        r = run_agent(el_ro, "terminal_exec", command="echo hi")
        return r.get("status") == "PERMISSION_REQUEST"

    n_deny = int(60 * SCALE)
    mean_p, ok_p = time_ms(_deny, n_deny)
    metric("exec", "权限不足自动授权请求裁决延迟", mean_p, "ms", n_deny)
    check("readonly+terminal_exec → PERMISSION_REQUEST", ok_p == n_deny,
          f"{ok_p}/{n_deny}")

    # 权限矩阵正确性
    r = run_agent(el_ro, "terminal_view", command="echo a | whoami")
    check("terminal_view 元字符拦截", r.get("status") == "403", r.get("message"))
except Exception as e:  # noqa: BLE001 —— 基准只报告，不让平台差异中断
    check("exec 链路可运行", False, repr(e))

# ================================================================ guard
print("[guard] L4 守门吞吐与正确率")
try:
    from gateway_v2 import WordGateway  # noqa: E402
    gw = WordGateway({})
    dirty = [
        ('api_key = "abcdef1234567890"', False),
        ("SELECT * FROM users WHERE name = 'x' + user_input", False),
        ("```python\nprint(1)", False),
        ("正常输出没有违规内容", True),
        ("帮我写一个排序算法", True),
    ]
    n_guard = int(2000 * SCALE)
    pool = dirty * (n_guard // len(dirty) + 1)

    def _guard_run():
        good = 0
        for text, expect in pool[:n_guard]:
            r = gw.guard.check(text)
            good += 1 if (r.passed == expect) else 0
        return good == len(pool[:n_guard])

    t0 = time.perf_counter()
    good = _guard_run()
    dt = time.perf_counter() - t0
    metric("guard", "L4 守门吞吐", round(len(pool[:n_guard]) / dt), "次/s",
           len(pool[:n_guard]))
    check("L4 守门正确率 100%（脏/净样本）", good, f"{good}/{len(pool[:n_guard])}")
except Exception as e:  # noqa: BLE001
    check("guard 可运行", False, repr(e))

# ================================================================ ast
print("[ast] AST 行为检测正确率")
try:
    from work import ASTDetector  # noqa: E402
    ad = ASTDetector()
    clean = ("import math\n\ndef add(a: int, b: int) -> int:\n"
             "    return a + b\n\nprint(add(1, math.floor(2.5)))")
    dirty_cases = [
        ("import unused_module_xyz\n\ndef f(x):\n    return x + 1\n", "unused_import"),
        ("def f(x):\n    return x + 1\n", "type_hints"),
        ("def f() -> int:\n    return f()\n", "infinite_recursion"),
        ("def a() -> int:\n    return b()\n\ndef b() -> int:\n    return a()\n", "circular_ref"),
        ('api_key = "abcd1234567890"\n', "hardcoded_secrets"),
        ('import sqlite3\nq = "SELECT * FROM t WHERE id=" + uid\n', "sql_injection"),
    ]
    r = ad.check_all(clean)
    check("AST 干净代码 6 规则全通过", all(r.values()), r)
    rule_ok = 0
    for code, rule in dirty_cases:
        rr = ad.check_all(code)
        rule_ok += 1 if rr.get(rule) is False else 0
    check("AST 6 条违规全部检出", rule_ok == 6, f"{rule_ok}/6")
    n_ast = int(300 * SCALE)

    def _ast_run():
        for code, _ in dirty_cases:
            ad.check_all(code)
        return True

    mean_ast, _ = time_ms(_ast_run, n_ast)
    metric("ast", "6 条违规样本单次全检平均耗时", round(mean_ast, 3), "ms", n_ast)
except Exception as e:  # noqa: BLE001
    check("ast 可运行", False, repr(e))

# ================================================================ guardian
print("[guardian] 快照-回滚")
try:
    from guardian import Guardian  # noqa: E402
    gproj = mktemp("guard")
    (gproj / "a.txt").write_text("v1", encoding="utf-8")
    (gproj / "sub").mkdir()
    (gproj / "sub" / "b.txt").write_text("v1-b", encoding="utf-8")
    g = Guardian(str(gproj))
    n_g = int(150 * SCALE)
    ok_snap = 0
    t0 = time.perf_counter()
    for _ in range(n_g):
        sid = g.snapshot("bench")
        (gproj / "a.txt").write_text("v2-CHANGED", encoding="utf-8")
        (gproj / "new.txt").write_text("junk", encoding="utf-8")
        g.rollback(sid)
        if ((gproj / "a.txt").read_text(encoding="utf-8") == "v1"
                and not (gproj / "new.txt").exists()):
            ok_snap += 1
    dt = time.perf_counter() - t0
    metric("guardian", "快照+修改+回滚整循环平均耗时",
           round(dt / n_g * 1000, 2), "ms", n_g)
    check("快照-回滚字节一致 100%", ok_snap == n_g, f"{ok_snap}/{n_g}")
except Exception as e:  # noqa: BLE001
    check("guardian 可运行", False, repr(e))

# ================================================================ memory
print("[memory] SimHash 记忆")
try:
    from Archive import MemoryArchive  # noqa: E402
    am = MemoryArchive()
    check("短输入保护（<10 字不存储）", am.add("你好") is False)
    check("正常输入存储", am.add("帮我把订单数据导出成 Excel 报表") is True)
    check("首个输入初始化锚点 stable",
          am.detect_topic_shift("帮我把订单数据导出成 Excel 报表") == "stable")
    check("同主题 stable",
          am.detect_topic_shift("帮我把订单数据导出成 Excel 报表（进度如何）") == "stable")
    check("主题切换检测 shifted",
          am.detect_topic_shift("给我写一篇关于夏天的小说开头") == "shifted")
    n_mem = int(2000 * SCALE)
    t0 = time.perf_counter()
    for i in range(n_mem):
        am.add(f"第 {i} 条测试记忆:把订单数据按时间排序导出成报表并发送邮件通知")
    dt = time.perf_counter() - t0
    metric("memory", "SimHash 记忆写入吞吐", round(n_mem / dt), "条/s", n_mem)
except Exception as e:  # noqa: BLE001
    check("memory 可运行", False, repr(e))

# ================================================================ 汇总输出
passed = sum(1 for c in CHECKS if c["passed"])
total = len(CHECKS)
sysinfo = {
    "date": datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"),
    "python": platform.python_version(),
    "platform": platform.platform(),
    "machine": platform.machine(),
    "quick": QUICK,
}
payload = {
    "sysinfo": sysinfo,
    "checks": {"passed": passed, "total": total,
               "items": [{"name": c["name"], "passed": c["passed"]} for c in CHECKS]},
    "metrics": RESULT,
}

OUT_DIR.mkdir(parents=True, exist_ok=True)
(OUT_DIR / "bench_report.json").write_text(
    json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

md = ["# ACE 实测基准报告", "",
      f"- 生成时间: `{sysinfo['date']}`"
      f"（{sysinfo['platform']} · {sysinfo['machine']} · Python {sysinfo['python']}）",
      f"- 模式: {'--quick（CI 冒烟）' if QUICK else '全量'}",
      f"- 复现: `python benchmarks/bench_core.py`（纯 stdlib，不联网）", "",
      "## 正确性检查", "",
      f"**{passed}/{total} 通过**" + ("" if passed == total else " ⚠️ 存在失败，请查下表"), ""]
if total - passed:
    md.append("| 检查 | 结果 |")
    md.append("|---|---|")
    for c in CHECKS:
        if not c["passed"]:
            md.append(f"| {c['name']} | ❌ {c['detail'][:120]} |")
    md.append("")
md += ["## 实测指标", "",
       "| 指标 | 数值 | 样本 | 说明 |",
       "|---|---|---|---|"]
group_label = {"parser": "文档解析", "exec": "工具链路",
               "guard": "L4 守门", "ast": "AST 检测",
               "guardian": "快照回滚", "memory": "记忆引擎"}
for m in RESULT:
    md.append(f"| **{group_label.get(m['group'], m['group'])}** · {m['name']} | "
              f"{m['value']} {m['unit']} | {m['samples']} | {m['detail']} |")
md += ["", "_本报告由 benchmarks/bench_core.py 在本机实测生成，指标随硬件波动，"
       "正确性检查应与硬件无关。_"]

(OUT_DIR / "bench_report.md").write_text("\n".join(md), encoding="utf-8")

print(f"\n✅ 正确性: {passed}/{total} 通过")
print(f"📄 报告: {OUT_DIR / 'bench_report.md'}")
print(f"📦 JSON: {OUT_DIR / 'bench_report.json'}")
