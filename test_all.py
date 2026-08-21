#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_all.py —— ai angent 全模块端到端测试（纯 stdlib，无需 pytest）

覆盖：
  1. gateway_v2  五层网关（L1 意图 / L2 技能 / L4 守门 8 规则 / L5 飞轮）
  2. work        诱饵工厂（5 种诱饵注入/验证）+ AST 行为检测（6 规则）
  3. guardian    物理快照回滚（预检/备份/恢复/清理）
  4. Archive     SimHash 记忆（短输入保护/主题切换/催促权重/召回）
  5. Nuwa        POC 报告（HTML+JSON、通过率、平均响应、回滚计数）
  6. universal_document_parser  解析/截断/错误处理
  7. execution_layer  权限/白名单/沙箱/诱饵循环/AST 熔断/守门回滚/模块状态

用法：
    python test_all.py
"""

import json
import os
import sys
import tempfile
from pathlib import Path

# Windows 控制台 GBK 编码兼容：强制 UTF-8 输出
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr.encoding and sys.stderr.encoding.lower() not in ("utf-8", "utf8"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

FOLDER = Path(__file__).resolve().parent
sys.path.insert(0, str(FOLDER))

# 测试临时目录统一放在工作区（部分受限环境禁止写系统临时区 / mkdtemp 目录）
import uuid  # noqa: E402

TEST_TMP = FOLDER / ".test_tmp"
TEST_TMP.mkdir(exist_ok=True)


def mktemp() -> Path:
    d = TEST_TMP / f"tmp_{uuid.uuid4().hex[:8]}"
    d.mkdir(parents=True, exist_ok=True)
    return d

PASSED = []
FAILED = []


def check(name: str, cond: bool, detail=""):
    if cond:
        PASSED.append(name)
        print(f"  ✅ {name}")
    else:
        FAILED.append(name)
        print(f"  ❌ {name}  {detail}")


def run_agent(el, tool: str, user: str = "测试输入", **params):
    body = json.dumps({"tool": tool, **params}, ensure_ascii=False)
    out = (f"<INTERNAL>\n[INTERNAL_THINKING]\n[ACT] {tool}\n[/INTERNAL_THINKING]\n</INTERNAL>\n"
           f"<EXTERNAL>\nanswer.\n{body}\n</EXTERNAL>")
    return el.process_agent_output(out, user)


# ============================================================
print("[1] gateway_v2 —— L1-L5 五层网关")
# ============================================================
from gateway_v2 import WordGateway, GuardViolation, Intent  # noqa: E402

import gateway_v2.flywheel  # noqa: E402
import gateway_v2.guard  # noqa: E402
import gateway_v2.intent  # noqa: E402
import gateway_v2.model  # noqa: E402
check("gateway 包分层模块可导入",
      gateway_v2.intent.Intent is Intent
      and gateway_v2.guard.InstinctGuard is not None
      and gateway_v2.model.ModelAdapter is not None
      and gateway_v2.flywheel.Flywheel is not None)

intent = Intent(raw_input="帮我写一段 python 代码，处理数据")
check("L1 意图识别 coding", intent.intent == "coding", intent.to_dict())

gw = WordGateway({})
check("L2 技能推荐", "code_execute" in gw.route("帮我写代码")["skills"], gw.route("帮我写代码"))

gr = gw.guard.check('api_key = "abcdef1234567890"')
check("L4 硬编码密钥拦截", (not gr.passed) and gr.failed_rule == "no_hardcoded_secrets", gr)

gr_u = gw.guard.check("api_key=abcdef1234567890")
check("L4 无引号密钥拦截（跨平台）", (not gr_u.passed) and gr_u.failed_rule == "no_hardcoded_secrets", gr_u)

gr_p = gw.guard.check("api_key=12345678")
check("L4 占位值放行", gr_p.passed, gr_p)

gr2 = gw.guard.check("SELECT * FROM users WHERE name = 'x' + user_input")
check("L4 SQL 拼接拦截", (not gr2.passed) and gr2.failed_rule == "no_sql_injection", gr2)

gr3 = gw.guard.check("```python\nprint(1)")
check("L4 Markdown 围栏检测", (not gr3.passed) and gr3.failed_rule == "markdown_clean", gr3)

gr4 = gw.guard.check("正常输出没有违规内容")
check("L4 正常输出放行", gr4.passed, gr4)

flywheel_path = str(mktemp() / "v.jsonl")
gw2 = WordGateway({"flywheel_path": flywheel_path})
gw2.flywheel.log_violation(intent, "bad output", "no_sql_injection")
check("L5 飞轮落盘", Path(flywheel_path).exists()
      and len(Path(flywheel_path).read_text(encoding="utf-8").splitlines()) == 1)
check("L5 SFT 样本导出", len(gw2.flywheel.export_for_sft()) == 1)

# ============================================================
print("[2] work —— 诱饵工厂 + AST 行为检测")
# ============================================================
from work import BaitFactory, ASTDetector, BehaviorConstraint  # noqa: E402

bf = BaitFactory(seed=42)
for t in ("unused_import", "type_mismatch", "circular_ref", "infinite_recursion", "missing_return"):
    baited, meta = bf.inject_bait("print(1)", bait_type=t)
    check(f"注入诱饵 {t}", "_bait_" in baited and meta.type == t)
    ok, _ = bf.verify_fixed(baited, meta)
    check(f"验证诱饵未修复 {t}", not ok)
    ok2, _ = bf.verify_fixed("print(1)", meta)
    check(f"验证诱饵已修复 {t}", ok2)

ad = ASTDetector()
clean = "import math\n\ndef add(a: int, b: int) -> int:\n    return a + b\n\nprint(add(1, math.floor(2.5)))"
rep = ad.check_all(clean)
check("AST 干净代码全通过", all(rep.values()), rep)

rep2 = ad.check_all("import unused_module_xyz\n\ndef f(x):\n    return x + 1\n")
check("AST 未用导入检测", rep2["unused_import"] is False, rep2)
check("AST 类型注解检测", rep2["type_hints"] is False, rep2)

rep3 = ad.check_all("def f() -> int:\n    return f()\n")
check("AST 无限递归检测", rep3["infinite_recursion"] is False, rep3)

rep4 = ad.check_all("def a() -> int:\n    return b()\n\ndef b() -> int:\n    return a()\n")
check("AST 循环引用检测", rep4["circular_ref"] is False, rep4)

rep5 = ad.check_all('api_key = "abcd1234567890"\n')
check("AST 硬编码密钥检测", rep5["hardcoded_secrets"] is False, rep5)

rep6 = ad.check_all('import sqlite3\nq = "SELECT * FROM t WHERE id=" + uid\n')
check("AST SQL 注入检测", rep6["sql_injection"] is False, rep6)

bc = BehaviorConstraint()
check("BehaviorConstraint 桥接校验", bc.validate("import x_never_used\n")["passed"] is False)

# ============================================================
print("[3] guardian —— 物理快照回滚")
# ============================================================
from guardian import Guardian  # noqa: E402

proj = mktemp()
(proj / "a.txt").write_text("v1", encoding="utf-8")
(proj / "sub").mkdir()
(proj / "sub" / "b.txt").write_text("v1-b", encoding="utf-8")
g = Guardian(str(proj))
sid = g.snapshot("test")
check("创建快照", sid is not None)
check("完整性预检通过", g.verify_snapshot(sid)[0])

(proj / "a.txt").write_text("v2-CHANGED", encoding="utf-8")
(proj / "new.txt").write_text("added after snapshot", encoding="utf-8")
ok = g.rollback(sid)
check("回滚成功", ok)
check("文件已恢复", (proj / "a.txt").read_text(encoding="utf-8") == "v1")
check("快照后新增文件已清理", not (proj / "new.txt").exists())
check("回滚后备份已清理", len(list(g.backup_dir.iterdir())) == 0)

empty_g = Guardian(str(mktemp()))
check("空项目快照返回 None", empty_g.snapshot("x") is None)

# ============================================================
print("[4] Archive —— SimHash 记忆注入")
# ============================================================
from Archive import MemoryArchive  # noqa: E402

am = MemoryArchive()
check("短输入保护（<10 字不存储）", am.add("你好") is False)
check("正常输入存储", am.add("帮我把订单数据导出成 Excel 报表") is True)
check("首个输入初始化锚点", am.detect_topic_shift("帮我把订单数据导出成 Excel 报表") == "stable")
check("同主题 stable", am.detect_topic_shift("帮我把订单数据导出成 Excel 报表（进度如何）") == "stable")
check("主题切换 shifted", am.detect_topic_shift("给我写一篇关于夏天的小说开头") == "shifted")
check("催促词记忆权重提升", am.add("快点帮我写代码，马上要用了")
      and any(e.urgent for e in am.entries))
mem = am.get_memory(top_k=3)
check("记忆召回", len(mem) >= 1)
st = am.stats()
check("统计输出", st["entries"] >= 2 and "current_topic" in st, st)

# ============================================================
print("[5] Nuwa —— POC 报告生成")
# ============================================================
from Nuwa import POCGenerator  # noqa: E402

nuwa = POCGenerator(output_dir=str(mktemp()), title="测试报告")
nuwa.add_metric("工具执行", "file_read", "pass")
nuwa.add_metric("工具执行", "file_write", "pass")
nuwa.add_metric("工具执行", "code_execute", "fail")
nuwa.add_metric("响应时间", "file_read", "0.12s", "info")
nuwa.add_metric("响应时间", "file_write", "0.28s", "info")
nuwa.add_rollback("诱饵验证失败")
report = nuwa.generate_report()
check("HTML 报告生成", Path(report.html_path).exists())
check("JSON 报告生成", Path(report.json_path).exists())
check("通过率计算 66.7%", report.summary["pass_rate_pct"] == 66.7, report.summary)
check("平均响应时间 0.2s", report.summary["avg_response_s"] == 0.2, report.summary)
check("回滚计数", report.summary["rollback_count"] == 1)

# ============================================================
print("[6] universal_document_parser —— 文档解析")
# ============================================================
from universal_document_parser import parse_document  # noqa: E402

res = parse_document(FOLDER / "agent_system_prompt_v7.md")
check("md 直接解析", res.success and res.method == "direct_text" and "系统身份层" in res.text)

long_file = mktemp() / "long.txt"
long_file.write_text("长" * 16000, encoding="utf-8")
res2 = parse_document(long_file)
check("超长文本截断", res2.truncated and len(res2.text) < 16000)
check("截断记录原始长度", res2.metadata.get("original_length") == 16000, res2.metadata)

res3 = parse_document(str(mktemp() / "nonexistent.pdf"))
check("文件不存在报错", (not res3.success) and "不存在" in res3.error)

res4 = parse_document(FOLDER / "execution_layer.py")
check("py 文件解析", res4.success and "ExecutionLayer" in res4.text)

# ============================================================
print("[7] execution_layer —— 端到端")
# ============================================================
from execution_layer import ExecutionLayer  # noqa: E402

sandbox_root = mktemp()
el = ExecutionLayer(project_root=str(sandbox_root), permission_level="readonly",
                    config={"bait": {"enabled": True, "frequency": 0},
                            "sandbox_base": str(TEST_TMP)})

# —— 权限 ——
r = run_agent(el, "terminal_exec", command="echo hi")
check("readonly 拒绝 terminal_exec", r["status"] == "403", r)
r = run_agent(el, "terminal_view", command="whoami")
check("terminal_view 拦截非白名单命令", r["status"] == "403", r.get("message"))
r = run_agent(el, "terminal_view", command="echo hello world")
check("terminal_view 内建 echo", r["status"] == "SUCCESS" and "hello world" in r["data"]["stdout"], r)
r = run_agent(el, "terminal_view", command="where python" if os.name == "nt" else "which python")
check("terminal_view 白名单外部命令", r["status"] == "SUCCESS" and "python" in r["data"]["stdout"].lower(), r)
r = run_agent(el, "terminal_view", command="echo a | whoami")
check("terminal_view 元字符拦截", r["status"] == "403", r.get("message"))
r = run_agent(el, "datetime_now", user="现在几点了")
check("datetime_now 执行", r["status"] == "SUCCESS" and "datetime" in r["data"], r)

# —— 模式 B 守门 ——
r = el.process_agent_output(
    "<INTERNAL>\n[INTERNAL_THINKING]\n[PLAN] x\n[/INTERNAL_THINKING]\n</INTERNAL>\n"
    "<EXTERNAL>\nanswer.\n我的密码是 password = \"abcdef123456\"\n</EXTERNAL>",
    "测试输入")
check("模式 B 最终回复守门拦截", r["status"] == "GUARD_VIOLATION"
      and r["rule"] == "no_hardcoded_secrets", r)

r = el.process_agent_output(
    "<INTERNAL>\n[INTERNAL_THINKING]\n[PLAN] x\n[/INTERNAL_THINKING]\n</INTERNAL>\n"
    "<EXTERNAL>\nanswer.\n任务已完成\n</EXTERNAL>",
    "帮我写代码")
check("模式 B 正常回复放行", r["status"] == "FINAL_REPLY" and r["message"] == "任务已完成", r)

r = el.process_agent_output(
    "<INTERNAL>\n[INTERNAL_THINKING]\n[PLAN] x\n[/INTERNAL_THINKING]\n</INTERNAL>\n"
    "<EXTERNAL>\nanswer.\n{\"name\": \"datetime_now\", \"arguments\": {\"format\": \"%Y\"}}\n</EXTERNAL>",
    "测试输入")
check("无 tool 键的 JSON 文本按最终回复处理", r["status"] == "FINAL_REPLY", r)

# —— code_execute 诱饵验证循环 ——
el_full = ExecutionLayer(project_root=str(sandbox_root), permission_level="write",
                         config={"bait": {"enabled": True, "frequency": 0},
                                 "sandbox_base": str(TEST_TMP)})
code = "def add(a: int, b: int) -> int:\n    return a + b\n\nprint(add(1, 2))"
r1 = run_agent(el_full, "code_execute", language="python", code=code, user="写个加法函数")
check("诱饵自动注入触发", r1["status"] == "BAIT_TRIGGERED" and "_bait_" in r1["baited_code"], r1.get("message"))
r2 = run_agent(el_full, "code_execute", language="python", code=code, user="写个加法函数")
check("修复诱饵后执行成功", r2["status"] == "SUCCESS" and "3" in r2["data"]["stdout"], r2)
r3 = run_agent(el_full, "code_execute", language="python", code=code, user="写个加法函数")
check("同一会话不再注入诱饵", r3["status"] == "SUCCESS", r3)

# —— AST 门禁分层：风格规则降级为警告，安全规则仍熔断 ——
el_style = ExecutionLayer(project_root=str(sandbox_root), permission_level="write",
                          config={"bait": {"enabled": False}, "sandbox_base": str(TEST_TMP)})
r4 = run_agent(el_style, "code_execute", language="python",
               code="def f(x):\n    return x + 1\n", user="无注解函数")
check("风格问题不再熔断（type_hints 降级为警告）",
      r4["status"] == "SUCCESS" and "type_hints" in (r4.get("ast_warnings") or {}), r4)

r4b = run_agent(el_style, "code_execute", language="python",
                code="api_key = 'abcdef1234567890'\nprint(api_key)", user="硬编码密钥")
check("安全规则仍熔断（hardcoded_secrets）",
      r4b["status"] == "AST_FAILED" and "hardcoded_secrets" in r4b["report"], r4b)

# —— 沙箱拦截（独立关闭诱饵的实例，避免诱饵弹回干扰断言） ——
el_sbx = ExecutionLayer(project_root=str(sandbox_root), permission_level="write",
                        config={"bait": {"enabled": False}, "sandbox_base": str(TEST_TMP)})
r5 = run_agent(el_sbx, "code_execute", language="python",
               code="import subprocess\nsubprocess.run(['whoami'])", user="越权尝试")
check("沙箱拦截 subprocess", r5["status"] == "403", r5.get("message"))
r6 = run_agent(el_sbx, "code_execute", language="python",
               code="open('evil.txt', 'w').write('x')", user="越权尝试")
check("沙箱拦截写模式 open", r6["status"] == "403", r6.get("message"))

# —— 快照 + 守门回滚 ——
el_w = ExecutionLayer(project_root=str(sandbox_root), permission_level="write",
                      config={"bait": {"enabled": False}, "sandbox_base": str(TEST_TMP)})
r = run_agent(el_w, "file_write", path="snap_test.txt", content="version-one")
check("首次写入（空项目无快照）", r["status"] == "SUCCESS" and r["snapshot_id"] is None, r)
r = run_agent(el_w, "file_write", path="snap_test.txt", content="version-two")
check("再次写入前自动快照", r["status"] == "SUCCESS" and r["snapshot_id"] is not None, r)

(el_w.project_root / "secret.txt").write_text('api_key = "abcdef1234567890"', encoding="utf-8")
r = run_agent(el_w, "file_read", path="secret.txt")
check("file_read 守门拦截", r["status"] == "GUARD_VIOLATION"
      and r["rule"] == "no_hardcoded_secrets", r)
check("读工具违规不回滚历史写入", (el_w.project_root / "snap_test.txt").read_text(encoding="utf-8") == "version-two")

# 写工具违规 → 回滚本轮快照（用 && 而非 &：POSIX sh 下 & 是后台执行会产生竞态）
r = run_agent(el_w, "terminal_exec", command='echo x > created.txt && echo api_key="abcdef1234567890"')
check("写工具违规触发守门", r["status"] == "GUARD_VIOLATION"
      and r["rule"] == "no_hardcoded_secrets", r)
check("违规自动回滚（仅本轮快照）", not (el_w.project_root / "created.txt").exists())

# —— 临时授权单次有效 ——
el_t = ExecutionLayer(project_root=str(sandbox_root), permission_level="readonly",
                      config={"bait": {"enabled": False}, "sandbox_base": str(TEST_TMP)})
el_t.permission.grant_temp("terminal_exec")
r = run_agent(el_t, "terminal_exec", command="echo ok")
check("临时授权可用", r["status"] == "SUCCESS", r)
r = run_agent(el_t, "terminal_exec", command="echo ok")
check("临时授权单次有效", r["status"] == "403", r)

# —— 主题切换记忆注入（切到无关话题不注入噪声；切回相关话题注入记忆） ——
el_m = ExecutionLayer(project_root=str(mktemp()), permission_level="readonly")
run_agent(el_m, "datetime_now", user="帮我把这个月的销售数据导出成 Excel 报表")
run_agent(el_m, "datetime_now", user="销售数据报表导出进度如何了")
r = run_agent(el_m, "datetime_now", user="给我写一篇关于夏天的小说开头")
check("切到无关话题不注入噪声记忆", not r.get("memory_injected"), r)
r = run_agent(el_m, "datetime_now", user="把销售数据报表导出的进度再发我一遍")
check("主题回切时注入相关记忆", r.get("memory_injected") is not None
      and len(r["memory_injected"]) >= 1, r)

# —— 生成前记忆预注入（prepare_context） ——
el_pc = ExecutionLayer(project_root=str(mktemp()), permission_level="readonly")
p1 = el_pc.prepare_context("帮我写一个 Python 爬虫抓取新闻")
check("prepare_context 首条输入原样返回", p1 == "帮我写一个 Python 爬虫抓取新闻", p1)
p2 = el_pc.prepare_context("帮我写一个 Python 爬虫抓取新闻")
check("prepare_context 主题稳定不注入记忆", p2 == "帮我写一个 Python 爬虫抓取新闻", p2)
p3 = el_pc.prepare_context("给我写一篇关于夏天的旅行游记")
check("主题切换时 prepare_context 注入记忆前缀", "[记忆注入]" in p3, p3)
r_pc = run_agent(el_pc, "datetime_now", user="给我写一篇关于夏天的旅行游记")
check("prepare_context 后 process 复用缓存注入",
      r_pc.get("memory_injected") is not None and len(r_pc["memory_injected"]) >= 1, r_pc)
dup = [e for e in el_pc.archive.entries if "旅行游记" in e.text]
check("prepare_context 不重复写入 Archive", len(dup) == 1, len(dup))

# —— 模块状态 ——
st = el_full.get_stats()
check("V2 网关已启用", st["v2_gateway"] is True, st)
check("V1 模块全部启用", all(st["v1_modules"].values()), st["v1_modules"])
check("文档解析器已启用", st["parser"] is True, st)
check("诱饵状态统计", "bait" in st, st)

# —— Plan Mode：计划提议 → 未批准拦截 → 批准后放行 ——
el_plan = ExecutionLayer(project_root=str(mktemp()), permission_level="write",
                         config={"bait": {"enabled": False}, "sandbox_base": str(TEST_TMP)})
r = run_agent(el_plan, "plan_propose", title="写一个爬虫",
              steps=["分析需求", "编写代码", "运行测试"], user="帮我写个爬虫")
check("plan_propose 生成计划",
      r["status"] == "PLAN_PROPOSED" and "写一个爬虫" in r["plan"]
      and len(r["steps"]) == 3, r)
r2 = run_agent(el_plan, "datetime_now", user="帮我写个爬虫")
check("计划未批准时拦截其他工具", r2["status"] == "PLAN_PENDING", r2)
check("批准计划", el_plan.approve_plan() is True)
r4 = run_agent(el_plan, "plan_propose", title="写一个爬虫",
               steps=["分析需求", "编写代码", "运行测试"], user="帮我写个爬虫")
check("批准后重复提议不再走批准流程", r4["status"] == "PLAN_ALREADY_APPROVED", r4)
r3 = run_agent(el_plan, "datetime_now", user="帮我写个爬虫")
check("批准后工具放行", r3["status"] == "SUCCESS", r3)

el_plan2 = ExecutionLayer(project_root=str(mktemp()), permission_level="write",
                          config={"bait": {"enabled": False}, "sandbox_base": str(TEST_TMP)})
run_agent(el_plan2, "plan_propose", title="t", steps=["a"], user="u1")
check("拒绝计划后清空", el_plan2.reject_plan() is True and el_plan2.pending_plan is None)

# —— 权限申请：403 → request_permission → 批准后临时放行一次 ——
el_perm = ExecutionLayer(project_root=str(mktemp()), permission_level="readonly",
                         config={"bait": {"enabled": False}, "sandbox_base": str(TEST_TMP)})
r = run_agent(el_perm, "terminal_exec", command="echo ok", user="测试")
check("readonly 下 terminal_exec 被拒", r["status"] == "403", r)
r = el_perm.process_agent_output(
    "<INTERNAL>\n[INTERNAL_THINKING]\n[ACT] x\n[/INTERNAL_THINKING]\n</INTERNAL>\n"
    "<EXTERNAL>\nanswer.\n{\"tool\": \"request_permission\", \"target\": \"terminal_exec\", "
    "\"reason\": \"需要执行命令\"}\n</EXTERNAL>",
    "测试")
check("request_permission 生成授权请求",
      r["status"] == "PERMISSION_REQUEST" and r["tool"] == "terminal_exec", r)
check("批准权限申请", el_perm.grant_pending_permission() is True)
r = run_agent(el_perm, "terminal_exec", command="echo ok", user="测试")
check("批准后临时放行一次", r["status"] == "SUCCESS", r)
r = run_agent(el_perm, "terminal_exec", command="echo ok", user="测试")
check("临时授权仅一次有效", r["status"] == "403", r)

# —— 五层网关 L1/L2 接入执行循环 ——
el_route = ExecutionLayer(project_root=str(mktemp()), permission_level="readonly",
                          config={"bait": {"enabled": False}, "sandbox_base": str(TEST_TMP)})
r = run_agent(el_route, "datetime_now", user="帮我写一个 Python 爬虫抓取新闻")
check("L1 意图识别接入结果", r.get("intent") == "coding", r)
check("L2 技能推荐接入结果",
      isinstance(r.get("skills"), list) and len(r["skills"]) >= 1, r)

# ============================================================
print("[8] agent_runner —— 交互循环（mock 模型离线验证）")
# ============================================================
from agent_runner import (ModelProvider, TOOLS, content_to_tool_protocol,  # noqa: E402
                          final_reply_protocol, load_system_prompt,
                          sanitize_plain_content, tool_calls_to_protocol)

# —— 原生工具调用转换 ——
proto = tool_calls_to_protocol([
    {"function": {"name": "math_calc", "arguments": '{"expression": "1+1"}'}}])
check("原生工具调用转协议文本",
      '"tool": "math_calc"' in proto and '"expression": "1+1"' in proto, proto)
ollama_json = content_to_tool_protocol(
    '{"name": "datetime_now", "arguments": {"format": "%Y-%m-%d"}}')
check("兼容 Ollama 文本 JSON 工具调用",
      '"tool": "datetime_now"' in ollama_json and "%Y-%m-%d" in ollama_json, ollama_json)
self_json = content_to_tool_protocol('{"tool": "math_calc", "expression": "2+2"}')
check("兼容项目自有文本协议",
      '"tool": "math_calc"' in self_json and '"expression": "2+2"' in self_json, self_json)
check("兼容 ```json 围栏包裹的工具调用",
      content_to_tool_protocol('```json\n{"name": "math_calc", "arguments": {"expression": "3*3"}}\n```')
      .startswith("<INTERNAL>"),
      content_to_tool_protocol('```json\n{"name": "math_calc", "arguments": {"expression": "3*3"}}\n```'))
check("非工具 JSON 文本返回空串", content_to_tool_protocol('{"a": 1}') == "",
      content_to_tool_protocol('{"a": 1}'))
check("未注册工具名的 JSON 不误转", content_to_tool_protocol(
      '{"name": "some_unknown_tool", "arguments": {}}') == "",
      content_to_tool_protocol('{"name": "some_unknown_tool", "arguments": {}}'))
check("讲解文本夹杂 JSON 工具调用也能提取",
      content_to_tool_protocol('代码如下：\n```json\n{"name": "math_calc", "arguments": {"expression": "2+2"}}\n```')
      .startswith("<INTERNAL>"),
      content_to_tool_protocol('代码如下：\n```json\n{"name": "math_calc", "arguments": {"expression": "2+2"}}\n```'))
check("清洗完整协议残留",
      sanitize_plain_content("<INTERNAL>[INTERNAL_THINKING]x[/INTERNAL_THINKING]</INTERNAL>\n"
                             "<EXTERNAL>\nanswer.\n你好\n</EXTERNAL>") == "你好",
      sanitize_plain_content("<INTERNAL>[INTERNAL_THINKING]x[/INTERNAL_THINKING]</INTERNAL>\n"
                             "<EXTERNAL>\nanswer.\n你好\n</EXTERNAL>"))
check("清洗残缺协议标签", sanitize_plain_content("你在问什么？</EXTERNAL") == "你在问什么？",
      sanitize_plain_content("你在问什么？</EXTERNAL"))
check("普通纯文本原样保留", sanitize_plain_content("你好，在的") == "你好，在的",
      sanitize_plain_content("你好，在的"))
check("思考块被删除（保留后续工具 JSON）",
      sanitize_plain_content("[INTERNAL_THINKING]获取信息[/INTERNAL_THINKING] "
                             '{"name": "search", "arguments": {}}').startswith("{"),
      sanitize_plain_content("[INTERNAL_THINKING]获取信息[/INTERNAL_THINKING] "
                             '{"name": "search", "arguments": {}}'))
check("整段都是思考块时取其内容作为回复",
      sanitize_plain_content("[INTERNAL_THINKING]用户稍后重试[/INTERNAL_THINKING]")
      == "用户稍后重试",
      sanitize_plain_content("[INTERNAL_THINKING]用户稍后重试[/INTERNAL_THINKING]"))
check("缺失闭合括号的思考标签也被清洗",
      sanitize_plain_content("[INTERNAL_THINKING获取信息[/INTERNAL_THINKING]") == "获取信息",
      sanitize_plain_content("[INTERNAL_THINKING获取信息[/INTERNAL_THINKING]"))
check("状态标签 [PLAN]/[REASON] 被清洗",
      sanitize_plain_content("[PLAN]做个计划\n[REASON]选工具\n你好") == "做个计划\n选工具\n你好",
      sanitize_plain_content("[PLAN]做个计划\n[REASON]选工具\n你好"))
rep = final_reply_protocol("完成")
check("原生纯文本包装为最终回复",
      rep.startswith("<INTERNAL>") and "answer.\n完成" in rep, rep)
check("TOOLS 注册 ≥ 20 个工具", len(TOOLS) >= 20, len(TOOLS))
check("tools 模式加载精简提示词", "工具" in load_system_prompt(tools_mode=True),
      load_system_prompt(tools_mode=True)[:40])
check("默认加载 v8 文本协议提示词", "<INTERNAL>" in load_system_prompt(),
      load_system_prompt()[:40])

# —— 历史裁剪 ——
class _ArgsTrim:
    mock = True
    base_url = None
    api_key = None
    model = None
    tools = False
    max_history = 2


pt = ModelProvider(_ArgsTrim())
for i in range(6):
    pt.history.append({"role": "user", "content": f"u{i}"})
    pt.history.append({"role": "assistant", "content": f"a{i}"})
pt._trim_history()
check("历史裁剪保留最近 N 轮",
      len(pt.history) == 4 and pt.history[0]["content"] == "u4", pt.history)


class _Args:
    mock = True
    base_url = None
    api_key = None
    model = None


class _Args:
    mock = True
    base_url = None
    api_key = None
    model = None


p = ModelProvider(_Args())
elr = ExecutionLayer(project_root=str(mktemp()), permission_level="write",
                     config={"bait": {"enabled": True, "frequency": 0},
                             "sandbox_base": str(TEST_TMP)})
out1 = p.generate("现在几点了")
r = elr.process_agent_output(out1, "现在几点了")
check("runner mock 第一轮工具调用", r["status"] == "SUCCESS" and "datetime" in r["data"], r)
p.mock_tool_result = r["data"]["datetime"]
out2 = p.generate("继续")
r2 = elr.process_agent_output(out2, "现在几点了")
check("runner mock 第二轮最终回复", r2["status"] == "FINAL_REPLY"
      and "当前时间" in r2["message"], r2)

# ============================================================
print("[9] ai_code —— AI Code 命令行")
# ============================================================
import io
import contextlib
import ai_code  # noqa: E402

check("CLI 自动识别 Anthropic 格式",
      ai_code.detect_api_format("https://open.bigmodel.cn/api/anthropic") == "anthropic")
check("CLI 自动识别 OpenAI 格式",
      ai_code.detect_api_format("https://api.deepseek.com/v1") == "openai")
check("CLI 密钥打码",
      ai_code.mask_secret("sk-1234567890abcdef") == "sk-123***cdef")

cfg_cli = {"project_root": str(mktemp()), "permission": "write", "bait": True,
           "base_url": "", "api_key": "", "model": "mock"}
cli = ai_code.AgentCLI(cfg_cli, mock=True)
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    cli.converse("现在几点了")
out_text = buf.getvalue()
check("CLI mock 对话完成", "✓ 完成" in out_text, out_text[-200:])
check("CLI 隐藏内部思考（不泄漏 INTERNAL）",
      "[INTERNAL_THINKING]" not in out_text and "[PLAN] 演示" not in out_text, out_text[:300])
check("CLI 显示思考/调用工具状态",
      "思考中" in out_text and "调用工具" in out_text, out_text[:300])
check("CLI 回复内容对用户可见", "当前时间是" in out_text, out_text[:600])

# —— 斜杠补全 / 模型自定义 / 无感回滚 ——
ai_code.CONFIG_PATH = mktemp() / "cfg.json"
cli_cmd = ai_code.AgentCLI({"project_root": str(mktemp()), "permission": "write",
                            "bait": False, "base_url": "", "api_key": "", "model": "m1"},
                           mock=True)
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    ret = cli_cmd.run_command("/hel")
out_text = buf.getvalue()
check("斜杠前缀唯一匹配自动执行", ret is True and "可用命令" in out_text, out_text[:200])

buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    cli_cmd.run_command("/")
out_text = buf.getvalue()
check("裸 / 列出全部命令", "可用的命令" in out_text and "/undo" in out_text, out_text[:200])

check("裸 exit 直接退出", cli_cmd.run_command("exit") is False)

buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    cli_cmd.run_command("/zzz")
out_text = buf.getvalue()
check("未知前缀给出提示", "没有以" in out_text, out_text[:200])

check("无空格斜杠参数解析 /search",
      ai_code._parse_slash_command("/search今天天气怎么样") == ("/search", "今天天气怎么样"),
      ai_code._parse_slash_command("/search今天天气怎么样"))
check("带空格命令不误解析为内联参数",
      ai_code._parse_slash_command("/provider 3 sk-x") == ("/provider", ""),
      ai_code._parse_slash_command("/provider 3 sk-x"))
check("普通命令原样解析",
      ai_code._parse_slash_command("/status") == ("/status", ""),
      ai_code._parse_slash_command("/status"))

_search_calls = []
_orig_search_web = cli_cmd._search_web
cli_cmd._search_web = lambda q: _search_calls.append(q)
with contextlib.redirect_stdout(io.StringIO()):
    cli_cmd.run_command("/search今天天气怎么样")
cli_cmd._search_web = _orig_search_web
check("无空格 /search 参数正确传递", _search_calls == ["今天天气怎么样"], _search_calls)

with contextlib.redirect_stdout(io.StringIO()):
    cli_cmd.run_command("/model test-model-2")
check("模型自定义并保存", cli_cmd.cfg["model"] == "test-model-2"
      and json.loads(ai_code.CONFIG_PATH.read_text(encoding="utf-8"))["model"] == "test-model-2")

# —— 提供商切换（参考本机 cli/AI-CLI-安装平台/lib/api.js 注册表） ——
check("提供商识别 zhipu",
      ai_code._find_provider({"base_url": "https://open.bigmodel.cn/api/anthropic"})["id"] == "zhipu")

buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    cli_cmd.run_command("/provider")
out_text = buf.getvalue()
check("/provider 列出提供商清单", "智谱" in out_text and "DeepSeek" in out_text
      and "OpenRouter" in out_text, out_text[:300])

with contextlib.redirect_stdout(io.StringIO()):
    cli_cmd.run_command("/provider zhipu")
check("/provider 切换智谱并自动换模型",
      cli_cmd.cfg["base_url"] == "https://open.bigmodel.cn/api/anthropic"
      and cli_cmd.cfg["model"] == "glm-4.7-flash", cli_cmd.cfg)

with contextlib.redirect_stdout(io.StringIO()):
    cli_cmd.run_command("/provider 3 sk-test-1234567890")
check("/provider 编号+密钥切换 DeepSeek",
      cli_cmd.cfg["base_url"] == "https://api.deepseek.com/v1"
      and cli_cmd.cfg["api_key"] == "sk-test-1234567890", cli_cmd.cfg)

buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    cli_cmd.run_command("/model")
out_text = buf.getvalue()
check("/model 显示该提供商可选模型",
      ("deepseek-v4-pro" in out_text) or ("deepseek-v4-flash" in out_text), out_text[:300])

proj_undo = mktemp()
el_undo = ExecutionLayer(project_root=str(proj_undo), permission_level="write",
                         config={"bait": {"enabled": False}, "sandbox_base": str(TEST_TMP)})
cli_undo = ai_code.AgentCLI({"project_root": str(proj_undo), "permission": "write",
                             "bait": False, "base_url": "", "api_key": "", "model": "m1"},
                            mock=True)
run_agent(el_undo, "file_write", path="f.txt", content="v1")
run_agent(el_undo, "file_write", path="f.txt", content="v2")
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    cli_undo.run_command("/undo")
out_text = buf.getvalue()
check("/undo 一键回滚到最近快照", "已回滚" in out_text
      and (proj_undo / "f.txt").read_text(encoding="utf-8") == "v1", out_text)

# —— 文件打开命令（只验证校验分支，不真正弹 GUI） ——
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    cli_cmd.run_command("/open")
out_text = buf.getvalue()
check("/open 无参数给出用法", "用法" in out_text, out_text[:200])

buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    cli_cmd.run_command("/open no_such_file_xyz.txt")
out_text = buf.getvalue()
check("/open 不存在文件报错", "文件不存在" in out_text, out_text[:200])

# —— @ 快捷方式：语言 / 技能 / 文件与文件夹引用 ——
proj_at = mktemp()
(proj_at / "sample.py").write_text("print('hello')\n" * 10, encoding="utf-8")
cli_at = ai_code.AgentCLI({"project_root": str(proj_at), "permission": "write",
                           "bait": False, "base_url": "", "api_key": "", "model": "m1"},
                          mock=True)
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    cli_at._handle_at_command("@lang en")
check("@lang en 切换英文",
      cli_at.lang == "en" and "English" in cli_at._build_system_prompt(),
      buf.getvalue()[:100])
with contextlib.redirect_stdout(io.StringIO()):
    cli_at._handle_at_command("@lang zh")
check("@lang zh 切回中文", cli_at.lang == "zh", cli_at.lang)
with contextlib.redirect_stdout(io.StringIO()):
    cli_at._handle_at_command("@skill coding")
check("@skill coding 切换技能",
      cli_at.skill == "coding" and "编程开发" in cli_at._build_system_prompt(),
      cli_at.skill)
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    cli_at._handle_at_command("@file sample.py")
check("@file 引用文件入上下文",
      len(cli_at.context_refs) == 1 and "print('hello')" in cli_at.context_refs[0],
      buf.getvalue()[:100])
check("引用注入系统提示词", "已引用上下文" in cli_at._build_system_prompt())
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    cli_at._handle_at_command("@folder .")
check("@folder 引用文件夹列表",
      len(cli_at.context_refs) == 2 and "sample.py" in cli_at.context_refs[-1],
      buf.getvalue()[:100])
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    cli_at._handle_at_command("@refs")
check("@refs 列出引用", "2 项" in buf.getvalue(), buf.getvalue()[:100])
with contextlib.redirect_stdout(io.StringIO()):
    cli_at._handle_at_command("@clear")
check("@clear 清空引用", len(cli_at.context_refs) == 0)
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    cli_at._handle_at_command("@")
check("裸 @ 显示快捷方式菜单",
      "@lang" in buf.getvalue() and "@file" in buf.getvalue(), buf.getvalue()[:200])

# —— 防蠢检测（防把 cmd 命令误打进 REPL） ——
check("防蠢: 识别 ace --install-ui", ai_code._looks_like_cli_command("ace --install-ui"))
check("防蠢: 识别 --mock 参数", ai_code._looks_like_cli_command("--mock"))
check("防蠢: 识别 pip install", ai_code._looks_like_cli_command("pip install requests"))
check("防蠢: 正常聊天不误伤", not ai_code._looks_like_cli_command("帮我写一段代码"))
check("防蠢: 中文带 ace 字样不误伤", not ai_code._looks_like_cli_command("帮我看看 ace 这个词"))

buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    cli_cmd._handle_cli_mistype("ace --mock")
out_text = buf.getvalue()
check("防蠢: 误输入给出本地提示", "不是发给 Agent 的话" in out_text, out_text[:200])

hints = ai_code._config_sanity_hints(
    {"model": "deepseek-v4-flash", "base_url": "https://open.bigmodel.cn/api/anthropic"})
check("防蠢: 检测 ZAI 别名模型", len(hints) >= 1 and "glm-4.6" in hints[0], hints)
hints2 = ai_code._config_sanity_hints(
    {"model": "glm-4.6", "base_url": "https://open.bigmodel.cn/api/anthropic"})
check("防蠢: 真实模型名不误报", len(hints2) == 0, hints2)

# —— 配置校验（纯 stdlib dataclass，替代 Pydantic 方案） ——
try:
    ai_code.CLIConfig.from_dict({"permission": "root"})
    _cfg_bad = False
except ValueError:
    _cfg_bad = True
check("CLIConfig 校验非法 permission", _cfg_bad)
try:
    ai_code.CLIConfig.from_dict({"max_history": -1})
    _cfg_bad2 = False
except ValueError:
    _cfg_bad2 = True
check("CLIConfig 校验负数 max_history", _cfg_bad2)
check("CLIConfig 默认值归一化",
      ai_code.CLIConfig.from_dict({}).permission == "write"
      and ai_code.CLIConfig.from_dict({}).max_history == 0)

# —— 登录页 / 首页（AI-CLI 启动平台同款） ——
check("ACE logo 存在", "██" in ai_code.ACE_LOGO)
check("首页菜单 7 项且含进入聊天", len(ai_code.AgentCLI.LANDING_ITEMS) == 7
      and ai_code.AgentCLI.LANDING_ITEMS[0][2] == "chat")


class _FakeStdin:
    def isatty(self):
        return False


_old_stdin = sys.stdin
sys.stdin = _FakeStdin()
key_res = ai_code.AgentCLI._read_key()
sys.stdin = _old_stdin
check("非 tty 下按键读取返回 None", key_res is None)

# 打桩按键等待，避免测试环境伪终端阻塞
_orig_wait_key = ai_code.AgentCLI._wait_key
ai_code.AgentCLI._wait_key = lambda self: None
try:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        ret = cli_cmd._run_landing_action("status")
    out_text = buf.getvalue()
    check("首页动作: 状态页返回菜单", ret is False and "会话" in out_text, out_text[:200])

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        ret = cli_cmd._run_landing_action("exit")
    out_text = buf.getvalue()
    check("首页动作: 退出返回 True", ret is True and "再见" in out_text, out_text[:200])

    # —— mock 可来回切换 + 聊天退出回主界面 ——
    cli_toggle = ai_code.AgentCLI({"project_root": str(mktemp()), "permission": "write",
                                   "bait": False, "base_url": "https://api.deepseek.com/v1",
                                   "api_key": "sk-test", "model": "deepseek-chat"}, mock=True)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cli_toggle._toggle_mock()
    check("mock 可切回真实模式", cli_toggle.client.mock is False, buf.getvalue()[:200])
    with contextlib.redirect_stdout(io.StringIO()):
        cli_toggle._toggle_mock()
    check("真实模式可切回 mock", cli_toggle.client.mock is True)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cli_toggle.run_command("/mock")
    check("/mock 斜杠命令切换", cli_toggle.client.mock is False, buf.getvalue()[:200])
finally:
    ai_code.AgentCLI._wait_key = _orig_wait_key

# ============================================================
print("[10] 上线加固 —— 路径越界 / math_calc 白名单 / API 协议 / 解析器防御")
# ============================================================
el_h = ExecutionLayer(project_root=str(mktemp()), permission_level="write",
                      config={"bait": {"enabled": False}, "sandbox_base": str(TEST_TMP)})
r = run_agent(el_h, "file_write", path="../escape.txt", content="x")
check("file_write 路径越界拦截", r["status"] == "403", r.get("message"))
r = run_agent(el_h, "file_read", path=str(FOLDER.parent / "README.md"))
check("file_read 绝对路径越界拦截", r["status"] == "403", r.get("message"))
r = run_agent(el_h, "file_read", path=str(FOLDER.parent / "README.md"))
check("路径越界 403 附带路径限制提示（不引导申请权限）",
      "路径越界" in r.get("instruction", ""), r.get("instruction"))
# —— terminal_view 路径健壮性（~ 展开 / -la 参数 / Windows 反斜杠） ——
r = run_agent(el_h, "terminal_view", command="ls -la")
check("terminal_view ls -la 忽略参数", r["status"] == "SUCCESS", r.get("message"))
r = run_agent(el_h, "terminal_view")
check("terminal_view 缺省列出项目目录",
      r["status"] == "SUCCESS" and isinstance(r["data"]["stdout"], str), r.get("message"))
(el_h.project_root / "a.py").write_text("x = 1\n", encoding="utf-8")
r = run_agent(el_h, "terminal_view", command="ls *.py")
check("terminal_view 支持通配符 ls *.py",
      r["status"] == "SUCCESS" and "a.py" in r["data"]["stdout"], r.get("message"))
r = run_agent(el_h, "terminal_view", command="dir /b *.py")
check("terminal_view 支持 Windows dir /b *.py",
      r["status"] == "SUCCESS" and "a.py" in r["data"]["stdout"], r.get("message"))
r = run_agent(el_h, "terminal_view", command="ls ~")
check("terminal_view ls ~ 展开主目录", r["status"] == "SUCCESS", r.get("message"))
r = run_agent(el_h, "terminal_view", command='cat "' + str(FOLDER / "README.md") + '"')
check("terminal_view cat 绝对路径可读", r["status"] == "SUCCESS" and "ACE" in r["data"]["stdout"], r.get("message"))
if os.name == "nt":
    r = run_agent(el_h, "terminal_view", command="dir C:\\Users\\69215\\Desktop")
    check("terminal_view Windows 反斜杠路径", r["status"] == "SUCCESS", r.get("message"))
r = run_agent(el_h, "file_write", path="ok.txt", content="in-project")
check("项目内写入正常", r["status"] == "SUCCESS", r)

# —— 写桌面/绝对路径放行（用户明确意图），读文件仍不放行 ——
abs_dir = Path(mktemp())
r = run_agent(el_h, "file_write", path=str(abs_dir / "out.txt"), content="abs-write")
check("file_write 绝对路径放行（用户明确意图）",
      r["status"] == "SUCCESS" and (abs_dir / "out.txt").exists(), r)
r = run_agent(el_h, "file_read", path=str(abs_dir / "out.txt"))
check("file_read 项目外文件仍拦截", r["status"] == "403", r.get("message"))
_orig_profile = os.environ.get("USERPROFILE")
os.environ["USERPROFILE"] = str(abs_dir)
os.environ["HOME"] = str(abs_dir)
try:
    r = run_agent(el_h, "file_write", path="~/Desktop/tilde.txt", content="tilde")
finally:
    if _orig_profile is None:
        os.environ.pop("USERPROFILE", None)
    else:
        os.environ["USERPROFILE"] = _orig_profile
check("file_write ~/Desktop 展开到主目录",
      r["status"] == "SUCCESS" and (abs_dir / "Desktop" / "tilde.txt").exists(), r)
r = run_agent(el_h, "file_move", source="ok.txt", dest=str(abs_dir / "moved.txt"))
check("file_move 绝对目标放行", r["status"] == "SUCCESS"
      and (abs_dir / "moved.txt").exists(), r)
if hasattr(os, "startfile"):
    import unittest.mock as _mock
    with _mock.patch.object(os, "startfile") as _sf:
        r = run_agent(el_h, "open_file", path=str(abs_dir))
        check("open_file 目录 → 打开系统文件管理器",
              r["status"] == "SUCCESS" and _sf.called and r["data"].get("is_dir"), r)

# —— Windows 反斜杠路径 JSON 修复（C:\Users → \U 非法转义被丢弃的坑） ——
from tools.base import repair_backslash_json as _repair
_broken = '{"tool":"file_read","path":"C:\\Users\\Desktop\\a.txt"}'
check("repair_backslash_json 修复 Windows 路径",
      json.loads(_repair(_broken))["path"] == "C:\\Users\\Desktop\\a.txt", _repair(_broken))
_r = el_h.process_agent_output(
    "<INTERNAL>\n[INTERNAL_THINKING]\n[ACT] read\n[/INTERNAL_THINKING]\n</INTERNAL>\n"
    "<EXTERNAL>\nanswer.\n" + _broken + "\n</EXTERNAL>", "测试")
check("execution_layer 修复反斜杠 JSON 并识别工具调用",
      _r.get("tool") == "file_read" and _r.get("status") != "FORMAT_ERROR"
      and "JSON 解析失败" not in (_r.get("message") or ""),
      _r.get("error") or _r.get("message") or str(_r)[:120])
from agent_runner import content_to_tool_protocol as _cttp
_r2 = _cttp('```json\n{"name": "file_write", '
            '"arguments": {"path": "C:\\Users\\Desktop\\x.py", "content": "1"}}\n```')
check("content_to_tool_protocol 修复反斜杠 arguments",
      '"file_write"' in _r2 and "C:\\\\Users\\\\Desktop\\\\x.py" in _r2, _r2[:120])

# —— parse_document / terminal_view ls 不存在 → 404 ——
r = run_agent(el_h, "parse_document", path=str(abs_dir / "不存在.docx"))
check("parse_document 文件不存在报 404", r["status"] == "404", r.get("message"))
r = run_agent(el_h, "terminal_view", command="ls " + str(abs_dir / "no_such_dir_xyz"))
check("terminal_view ls 不存在目录报 404", r["status"] == "404", r.get("message"))
r = run_agent(el_h, "math_calc", expression="2+2*10")
check("math_calc 正常计算", r["status"] == "SUCCESS" and r["data"]["result"] == 22, r)
r = run_agent(el_h, "math_calc", expression="9**9**9")
check("math_calc 大指数 DoS 拦截", r["status"] == "403", r.get("message"))
r = run_agent(el_h, "math_calc", expression="__import__('os')")
check("math_calc 代码执行拦截", r["status"] == "403", r.get("message"))
r = run_agent(el_h, "api_get", url="file:///etc/passwd")
check("api_get 协议校验拦截", r["status"] == "400", r.get("message"))

# —— 重复失败熔断（防小模型死循环） ——
el_f = ExecutionLayer(project_root=str(mktemp()), permission_level="write",
                      config={"bait": {"enabled": False}, "sandbox_base": str(TEST_TMP)})
_bad_perm = ("<INTERNAL>\n[INTERNAL_THINKING]\n[ACT] p\n[/INTERNAL_THINKING]\n</INTERNAL>\n"
             "<EXTERNAL>\nanswer.\n{\"tool\": \"request_permission\"}\n</EXTERNAL>")
_s1 = el_f.process_agent_output(_bad_perm, "熔断测试")
_s2 = el_f.process_agent_output(_bad_perm, "熔断测试")
_s3 = el_f.process_agent_output(_bad_perm, "熔断测试")
check("request_permission 连续失败触发熔断",
      "request_permission" in el_f.banned_tools
      and "熔断" in ((_s3.get("instruction") or "") + (_s3.get("message") or "")), _s3)
_s4 = el_f.process_agent_output(_bad_perm, "熔断测试")
check("熔断后 request_permission 直接拒绝", _s4["status"] == "TOOL_BANNED", _s4)
_good_perm = ("<INTERNAL>\n[INTERNAL_THINKING]\n[ACT] p\n[/INTERNAL_THINKING]\n</INTERNAL>\n"
              "<EXTERNAL>\nanswer.\n{\"tool\": \"request_permission\", "
              "\"target\": \"file_write\"}\n</EXTERNAL>")
el_f2 = ExecutionLayer(project_root=str(mktemp()), permission_level="write",
                       config={"bait": {"enabled": False}, "sandbox_base": str(TEST_TMP)})
_rp = el_f2.process_agent_output(_good_perm, "熔断测试")
check("write 权限下申请已允许工具 → 短路无需授权",
      _rp["status"] == "SUCCESS" and "无需申请" in _rp["message"], _rp)
_rd = ("<INTERNAL>\n[INTERNAL_THINKING]\n[ACT] r\n[/INTERNAL_THINKING]\n</INTERNAL>\n"
       "<EXTERNAL>\nanswer.\n{\"tool\": \"file_read\", \"path\": \"nope.txt\"}\n</EXTERNAL>")
for _i in range(3):
    _rf = el_f.process_agent_output(_rd, "熔断测试")
check("file_read 404 连续 3 次触发熔断", "file_read" in el_f.banned_tools, _rf)
_rf4 = el_f.process_agent_output(_rd, "熔断测试")
check("熔断后 file_read 直接拒绝", _rf4["status"] == "TOOL_BANNED", _rf4)
# 成功执行后计数重置
el_f.repeat_fail.clear()
el_f.banned_tools.discard("file_read")
_ok = ("<INTERNAL>\n[INTERNAL_THINKING]\n[ACT] m\n[/INTERNAL_THINKING]\n</INTERNAL>\n"
       "<EXTERNAL>\nanswer.\n{\"tool\": \"math_calc\", \"expression\": \"1+1\"}\n</EXTERNAL>")
el_f.process_agent_output(_ok, "熔断测试")
check("工具成功后失败计数清空", el_f.repeat_fail == {}, el_f.repeat_fail)
r = el_h.process_agent_output(
    "<INTERNAL>\n[INTERNAL_THINKING]\n[ACT] x\n[/INTERNAL_THINKING]\n</INTERNAL>\n"
    "<EXTERNAL>\nanswer.\n[1,2,3]\n</EXTERNAL>", "测试")
check("非对象 JSON 安全处理（作为最终回复）", r["status"] == "FINAL_REPLY", r)

# —— 安全审查修复验证 ——
r = run_agent(el_h, "terminal_view", command='python -v -c "print(1)"')
check("terminal_view 版本参数注入拦截", r["status"] == "403", r.get("message"))
r = run_agent(el_h, "terminal_view", command="find . -name x")
check("terminal_view find 已移出白名单", r["status"] == "403", r.get("message"))
r = run_agent(el_h, "code_execute", language="python",
              code="import os as x\nx.system('echo pwned')")
check("沙箱拦截 os 别名导入", r["status"] == "403", r.get("message"))
r = run_agent(el_h, "code_execute", language="python",
              code="().__class__.__bases__[0].__subclasses__()")
check("沙箱拦截类链逃逸", r["status"] == "403", r.get("message"))
r = run_agent(el_h, "code_execute", language="python",
              code="open('x.txt', mode='w').write('x')")
check("沙箱拦截关键字参数 open", r["status"] == "403", r.get("message"))
r = run_agent(el_h, "code_execute", language="python",
              code="import pickle\npickle.loads(b'x')")
check("沙箱拦截 pickle 导入", r["status"] == "403", r.get("message"))

# —— 快照 HMAC 签名（防伪造） ——
gproj = mktemp()
(gproj / "s.txt").write_text("v1", encoding="utf-8")
g_signed = Guardian(str(gproj), signing_key="test-sign-key-123456")
sid = g_signed.snapshot("signed")
check("签名快照创建并预检通过", g_signed.verify_snapshot(sid)[0] is True)
meta_f = g_signed.snap_dir / sid / "meta.json"
meta_f.write_text(meta_f.read_text(encoding="utf-8").replace('"tag": "signed"', '"tag": "hacked"'),
                  encoding="utf-8")
check("篡改元信息后签名校验失败", g_signed.verify_snapshot(sid)[0] is False)

# —— 逻辑审查修复验证 ——
r = el_h.process_agent_output(
    "<INTERNAL>\n[INTERNAL_THINKING]\n[PLAN] x\n[/INTERNAL_THINKING]\n</INTERNAL>\n"
    "<EXTERNAL>\nanswer.\n\n</EXTERNAL>", "测试")
check("空最终回复拦截（不再崩溃）", r["status"] == "FORMAT_ERROR", r)

res_direct = el_h.executor.execute({"tool": "datetime_now"})
check("elapsed 元数据正确附加", res_direct.metadata.get("elapsed", 0) > 0, res_direct.metadata)

r = run_agent(el_h, "search", query="测试")
check("联网搜索（无网/被拒时优雅报错）",
      r["status"] in ("SUCCESS", "500"),
      f"{r.get('status')}: {r.get('message')}")
if r["status"] == "SUCCESS":
    check("联网搜索结果结构完整",
          len(r["data"]["results"]) >= 1
          and all(k in r["data"]["results"][0] for k in ("title", "url")),
          r["data"])

# —— 联网搜索解析器（离线样本验证） ——
from execution_layer import ToolExecutor  # noqa: E402
sample_ddg = ('<a rel="nofollow" class="result__a" href="//duckduckgo.com/l/?'
              'uddg=https%3A%2F%2Fexample.com%2Fai&amp;rut=abc">Example <b>AI</b> result</a>'
              '<a class="result__snippet" href="//x">Some <b>snippet</b> text</a>')
ddg_results = ToolExecutor._parse_ddg(sample_ddg, 5)
check("DDG 解析器: 链接解码 + 标题",
      len(ddg_results) == 1
      and ddg_results[0]["url"] == "https://example.com/ai"
      and "Example AI result" in ddg_results[0]["title"], ddg_results)
check("DDG 解析器: 摘要提取",
      "snippet" in ddg_results[0] and "snippet" in ddg_results[0]["snippet"], ddg_results)

sample_bing = ('<li class="b_algo"><h2><a href="https://bing.example.com">'
               'Bing <b>Result</b></a></h2><p>Bing snippet here</p></li>')
bing_results = ToolExecutor._parse_bing(sample_bing, 5)
check("Bing 解析器: 标题/链接/摘要",
      len(bing_results) == 1
      and bing_results[0]["url"] == "https://bing.example.com"
      and "Bing Result" in bing_results[0]["title"]
      and "snippet" in bing_results[0]["snippet"], bing_results)

# —— 新落地的真实工具（SQLite / 浏览器 / 通知 / 图像） ——
r = run_agent(el_h, "db_write", query="CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)")
check("db_write 建表", r["status"] == "SUCCESS", r.get("message"))
r = run_agent(el_h, "db_write", query="INSERT INTO t (name) VALUES ('小明'), ('小红')")
check("db_write 插入数据", r["status"] == "SUCCESS" and r["data"]["affected_rows"] == 2, r)
r = run_agent(el_h, "db_query", query="SELECT name FROM t ORDER BY id")
check("db_query 查询结果", r["status"] == "SUCCESS"
      and r["data"]["columns"] == ["name"]
      and r["data"]["rows"] == [["小明"], ["小红"]], r)
r = run_agent(el_h, "db_query", query="UPDATE t SET name='x'")
check("db_query 拒绝写入语句", r["status"] == "403", r.get("message"))
r = run_agent(el_h, "db_write", query="DROP TABLE t")
check("db_write 拒绝 DROP", r["status"] == "403", r.get("message"))
r = run_agent(el_h, "db_write", query="SELECT 1")
check("db_write 拒绝 SELECT", r["status"] == "400", r.get("message"))

r = run_agent(el_h, "notify_send", channel="file", to="测试", content="这是一条测试通知")
check("notify_send 文件渠道落盘", r["status"] == "SUCCESS"
      and (el_h.project_root / "notifications.log").exists()
      and "测试通知" in (el_h.project_root / "notifications.log").read_text(encoding="utf-8"), r)
r = run_agent(el_h, "notify_send", channel="email", to="x@example.com", content="hi")
check("email 无 SMTP 配置返回 501", r["status"] == "501", r)

r = run_agent(el_h, "browser_open", url="file:///etc/passwd")
check("browser_open 协议校验", r["status"] == "400", r.get("message"))

r = run_agent(el_h, "browser_screenshot")
check("browser_screenshot 优雅降级（无 pillow 时 500）",
      r["status"] in ("SUCCESS", "500"), r.get("message"))

r = run_agent(el_h, "image_generate", prompt="test", size="bad")
check("image_generate 尺寸校验", r["status"] == "400", r.get("message"))
r = run_agent(el_h, "image_generate", prompt="一只猫")
check("image_generate 无网时优雅报错",
      r["status"] in ("SUCCESS", "500"), r.get("message"))

# —— 结果序列化兜底（防 Path 等对象导致 json 崩溃） ——
from agent_runner import render_result as _rr  # noqa: E402
el_srz = ExecutionLayer(project_root=str(mktemp()), permission_level="write",
                        config={"bait": {"enabled": False}, "sandbox_base": str(TEST_TMP)})
res_srz = el_srz.executor.execute({"tool": "datetime_now"})
check("render_result 可序列化（不因 Path 崩溃）",
      isinstance(_rr({"status": "SUCCESS", "data": res_srz.data, "tool": "datetime_now"}), str))

# —— 对话内打开文件（open_file / edit_file） ——
from execution_layer import READ_TOOLS as _READ_TOOLS  # noqa: E402
check("open_file/edit_file 已注册为只读工具",
      "open_file" in _READ_TOOLS and "edit_file" in _READ_TOOLS)
r = run_agent(el_h, "open_file", path="")
check("open_file 空路径报 400", r["status"] == "400", r.get("message"))
r = run_agent(el_h, "open_file", path="no_such_file_xyz.docx")
check("open_file 不存在文件报 404", r["status"] == "404", r.get("message"))
r = run_agent(el_h, "edit_file", path="no_such_file_xyz.py")
check("edit_file 不存在文件报 404", r["status"] == "404", r.get("message"))
r = run_agent(el_h, "open_file", path=str(FOLDER / "README.md"))
check("open_file 默认给链接不弹窗（点击才打开）",
      r["status"] == "SUCCESS" and r["data"]["opened"] is False
      and r["data"]["link"].startswith("file:///"), r)

buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    ai_code.AgentCLI._print_clickables(
        {"tool": "open_file",
         "data": {"path": "C:/x/报告.docx",
                  "link": "file:///C:/x/%E6%8A%A5%E5%91%8A.docx", "opened": False}})
out_text = buf.getvalue()
check("CLI 可点击链接渲染（默认收起）",
      "点击打开文件" in out_text and "file:///" in out_text, out_text[:200])

# —— 系统提示词包含用户桌面路径（"桌面有什么"不再答非所问） ——
_sp = cli_cmd._build_system_prompt()
check("系统提示词含用户桌面目录",
      "用户桌面目录" in _sp and "Desktop" in _sp and "工作目录" in _sp, _sp[:300])

# —— 残缺 </EXTERNAL / 裸 </ 标签清理 ——
_clean = ai_code._sanitize_display_text("你好！\n</")
check("裸 </ 残标签被清理", "</" not in _clean, repr(_clean))
_clean2 = ai_code._sanitize_display_text("你好！\n</EXTERNAL")
check("残缺 </EXTERNAL 标签被清理", "</EXTERNAL" not in _clean2, repr(_clean2))

# —— file_read 目录返回列表（"桌面有什么"不再 404 误判） ——
r = run_agent(el_h, "file_read", path=".")
check("file_read 项目内目录返回列表", r["status"] == "SUCCESS"
      and r["data"].get("is_dir") is True, r.get("message"))
r = run_agent(el_h, "file_read", path=str(FOLDER.parent))
check("file_read 越界目录仍可列出（桌面场景）", r["status"] == "SUCCESS"
      and r["data"].get("is_dir") is True and len(r["data"].get("listing", [])) >= 1,
      r.get("message"))

# —— tools 模式工具调用 JSON 不泄漏给用户 ——
_disp = ai_code.AgentCLI._make_display(tools_mode=True, spinner=None)
_buf = io.StringIO()
with contextlib.redirect_stdout(_buf):
    _disp["on_delta"](('```json\n{"name": "terminal_view", '
                       '"arguments": {"command": "ls -la ~/Desktop"}}\n```'))
_out = _buf.getvalue()
check("tools 模式工具调用 JSON 隐藏",
      '"name"' not in _out and "terminal_view" not in _out, _out[:200])
_disp2 = ai_code.AgentCLI._make_display(tools_mode=True, spinner=None)
_buf2 = io.StringIO()
with contextlib.redirect_stdout(_buf2):
    _disp2["on_delta"]("你的桌面上有这些文件")
_out2 = _buf2.getvalue()
check("tools 模式纯文本正常展示", "桌面上" in _out2, _out2[:200])
_disp3 = ai_code.AgentCLI._make_display(tools_mode=True, spinner=None)
_buf3 = io.StringIO()
with contextlib.redirect_stdout(_buf3):
    _disp3["on_delta"]('好的，请稍等。\n```json\n{"name": "plan_propose", '
                       '"arguments": {"steps": ["a"], "title": "t"}}\n```')
_out3 = _buf3.getvalue()
check("tools 模式'正文+json'混合输出隐藏 json",
      '"name"' not in _out3 and "plan_propose" not in _out3, _out3[:200])

# —— 嵌套 ``` 围栏的 JSON 仍能识别（模型把代码围栏嵌进 plan 步骤） ——
from agent_runner import content_to_tool_protocol as _cttp2  # noqa: E402
_nested = ('好的，请稍等。\n```json\n{"name": "plan_propose", "arguments": '
           '{"steps": ["打开文件管理器并导航到桌面目录 C:\\\\Users\\\\69215\\\\Desktop。", '
           '"使用编辑器打开文件并输入：\\n\\n```python\\nprint(\'1+1\')\\n```\\n保存。"], '
           '"title": "创建 Python 文件的计划"}}\n```')
_rn = _cttp2(_nested)
check("嵌套代码围栏的 plan JSON 仍被识别",
      '"plan_propose"' in _rn and "创建 Python 文件的计划" in _rn, _rn[:200])

fib_code = ("def fib(n: int) -> int:\n    if n < 2:\n        return n\n"
            "    return fib(n - 1) + fib(n - 2)\n\nprint(fib(8))")
rep_fib = ad.check_all(fib_code)
check("正常递归（fib）不再误报", rep_fib["infinite_recursion"] is True, rep_fib)

rep_sql_ok = ad.check_all('msg = f"update status"\nprint(msg)\n')
check("普通 f-string 不再误报 SQL", rep_sql_ok["sql_injection"] is True, rep_sql_ok)

el_b = ExecutionLayer(project_root=str(mktemp()), permission_level="write",
                      config={"bait": {"enabled": True, "frequency": 0},
                              "sandbox_base": str(TEST_TMP)})
code = "def add(a: int, b: int) -> int:\n    return a + b\n\nprint(add(1, 2))"
run_agent(el_b, "code_execute", language="python", code=code, user="任务A写加法函数")
r = run_agent(el_b, "code_execute", language="python", code=code, user="任务B换个任务")
check("新任务不携带旧任务诱饵", r["status"] == "BAIT_TRIGGERED", r)

am2 = MemoryArchive()
am2.add("帮我把订单数据导出成 Excel 报表")
am2.add("帮我写一篇关于夏天的旅行游记")
mem2 = am2.get_memory(query="订单数据报表进度", top_k=3, exclude_last=True)
check("记忆召回排除当前消息", all(m["text"] != "帮我写一篇关于夏天的旅行游记" for m in mem2))

g2 = Guardian(str(mktemp()))
(g2.project_root / "p.txt").write_text("x", encoding="utf-8")
g2.snapshot("s1")
g2.snapshot("s2")
removed = g2.prune(keep=0)
check("prune keep=0 删除全部快照", removed >= 2 and len(g2.list_snapshots()) == 0)

# —— 灰度期加固（4 个坑） ——
# 坑1：大文件 DoS 防线
import universal_document_parser as udp  # noqa: E402
old_limit = udp.MAX_FILE_SIZE
udp.MAX_FILE_SIZE = 10   # 调低阈值模拟：10 字节上限
small_file = mktemp() / "small.txt"
small_file.write_text("0123456789", encoding="utf-8")
big_file = mktemp() / "big.txt"
big_file.write_text("012345678901234567890", encoding="utf-8")
res_big = parse_document(big_file)
check("超大文件直接拒绝", (not res_big.success) and "文件过大" in res_big.error, res_big.error)
udp.MAX_FILE_SIZE = old_limit
res_small = parse_document(small_file)
check("阈值内文件正常解析", res_small.success, res_small.error)

# 坑2：多会话记忆隔离
am_s = MemoryArchive()
am_s.add("帮我把这个月的销售数据导出成 Excel 报表")
am_s.detect_topic_shift("帮我把这个月的销售数据导出成 Excel 报表")
am_s.set_session("novel")
check("新会话首次输入初始化自身锚点",
      am_s.detect_topic_shift("给我写一篇关于夏天的小说开头") == "stable")
check("会话间记忆互相隔离（novel 看不到 coding）",
      len(am_s.get_memory(query="销售数据报表导出进度", top_k=5)) == 0)
am_s.set_session("default")
check("切回原会话记忆可见",
      len(am_s.get_memory(query="销售数据报表导出进度", top_k=5)) >= 1)

# 坑3：快照自动清理（硬上限）+ 快照 id 不撞车
g3 = Guardian(str(mktemp()), max_snapshots=2)
(g3.project_root / "p.txt").write_text("x", encoding="utf-8")
g3.snapshot("a")
g3.snapshot("b")
g3.snapshot("c")
snaps3 = g3.list_snapshots()
check("快照自动清理至上限 2", len(snaps3) == 2, snaps3)
check("快照 id 唯一（含随机后缀）", len({s["id"] for s in snaps3}) == 2, snaps3)

# 坑4：盘符一致性检查（仅 Windows 有意义）
if os.name == "nt":
    r = run_agent(el_h, "file_read", path="Z:\\outside\\secret.txt")
    check("跨盘符路径拦截", r["status"] == "403", r.get("message"))

# ============================================================
print("[11] i18n —— 国际化（JSON 字典 + @lang 联动界面）")
# ============================================================
import i18n as i18n_mod  # noqa: E402

check("默认语言为中文", i18n_mod.current_lang() == "zh")
check("zh 翻译命中",
      i18n_mod.t("done", round=1, sec=2.5) == "  ✓ 完成（1 轮, 2.5s）",
      i18n_mod.t("done", round=1, sec=2.5))
i18n_mod.set_language("en")
check("en 翻译命中", "Done" in i18n_mod.t("done", round=1, sec=2.5),
      i18n_mod.t("done", round=1, sec=2.5))
check("缺失键原样返回", i18n_mod.t("no_such_key_xyz") == "no_such_key_xyz",
      i18n_mod.t("no_such_key_xyz"))

cli_i18n = ai_code.AgentCLI({"project_root": str(mktemp()), "permission": "write",
                             "bait": False, "base_url": "", "api_key": "", "model": "m1"},
                            mock=True)
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    cli_i18n._handle_at_command("@lang en")
check("@lang en 界面同步英文",
      "Reply language switched" in buf.getvalue(), buf.getvalue()[:100])
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    cli_i18n._handle_at_command("@")
check("@ 菜单英文显示", "shortcuts" in buf.getvalue(), buf.getvalue()[:200])
with contextlib.redirect_stdout(io.StringIO()):
    cli_i18n._handle_at_command("@lang zh")
check("切回中文后全局翻译复位", i18n_mod.current_lang() == "zh")

# ============================================================
print("=" * 60)
print(f"通过 {len(PASSED)} / {len(PASSED) + len(FAILED)}")
if FAILED:
    print("失败项:")
    for name in FAILED:
        print(f"  - {name}")
    sys.exit(1)
print("🎉 全部测试通过")
