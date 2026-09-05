## 改动摘要

<!— 一句话说明改了什么,关联 BACKLOG/CHANGELOG 条目 —>

## 类型
- [ ] 修复(fix) / 功能(feat) / 文档(docs) / 重构(refactor)
- [ ] 行为变化(改了旧行为的用例是否一并更新?)

## 本地验证(勾选已跑)
- [ ] `python test_all.py`(退出码 0)
- [ ] `python benchmarks/bench_core.py --quick`(正确性全过)
- [ ] `ruff check . --select E9,F63,F7,F82,F401,F841,E711,F811`
- [ ] 涉及用户可见输出:`python demo/record_demo.py --check`

## 安全影响
<!— 是否触碰路径/命令/网络/快照边界?是否已补回归测试? —>
