# 贡献指南

## 环境准备

- Python ≥ 3.10（建议 3.11/3.12）
- 核心零第三方依赖；跑测试不需要额外安装
- 真实模型对话需要 `requests`（`pip install requests`）
- 可选：`prompt_toolkit`（`/` 与 `@` 实时补全菜单，`ace --install-ui`）

## 跑测试

```bash
python test_all.py
```

所有改动必须保证 `test_all.py` 全绿（当前 1428 项，纯 stdlib，无 pytest 依赖）。
Go 执行器（`executor/`）另跑 `go vet ./... && go build ./... && go test ./...`；
`go test -race` 需要 cgo，开发机通常没有 C 编译器，那一项由 CI 覆盖。

## 代码风格

- 全项目补全 `typing` 类型注解（参数、返回值、dataclass 字段）。
- 用户可见输出用 `print` + ANSI 颜色（`c()`），内部诊断用 `logging.getLogger("ace")`。
- 错误策略：内部逻辑用异常（`raise RuntimeError`），对外边界统一返回 `ExecutionResult`。
- 新工具注册：在 `tools/` 下对应的 mixin（`file_tools` / `code_tools` / `web_tools` …）
  增加 `_exec_xxx`，并注册到 `tools/base.py` 的分发表；`ToolExecutor` 本身在
  `tools/__init__.py` 里由这些 mixin 组合而成，`execution_layer` 只做转发。
  同时在 `agent_runner.TOOLS`（原生工具 schema）与提示词工具清单同步。
- 网关新增逻辑按层放入 `gateway_v2/` 包对应模块（intent/model/guard/flywheel）。

## 提交流程

1. 从 `main` 切分支，命名 `feat/xxx` 或 `fix/xxx`。
2. 改动后本地跑 `python test_all.py` 全绿。
3. 提交信息用中文一句话概括 + 要点列表（参考现有 git log）。
4. 发起 PR 到 `main`，CI 会自动跑 3.10/3.11/3.12 测试与 ruff 安全子集。

## 目录结构

```
ai_code.py                     ACE CLI（登录页/REPL/斜杠命令/@ 快捷方式）
agent_runner.py                参考引擎（LLM + 执行层循环，支持 --tools）
execution_layer.py             执行层（协议解析/权限/工具执行/Plan Mode/权限申请）
gateway_v2/                    L1-L5 五层网关包
  intent.py                    L1 意图 + L2 技能推荐
  model.py                     L3 模型适配
  guard.py                     L4 本能守门
  flywheel.py                  L5 反馈飞轮
work.py                        诱饵工厂 + AST 检测
guardian.py                    物理快照回滚
Archive.py                     SimHash 记忆
Nuwa.py                        POC 报告
universal_document_parser.py   N 合一文档解析
test_all.py                    端到端测试（1428 项）
docs/ADR.md                    架构决策记录
```
