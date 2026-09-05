# P2 结构重构立项卡(新会话按卡执行)

> 目标:在**新会话**中逐项完成 R-01~R-05,每项独立提交并保持
> 本机 `test_all.py` **0 失败**(受限环境允许 ⏭ 跳过、`--strict` 时须全绿)与 CI 全绿。
> 执行纪律:先读 `docs/DEVELOPMENT.md`(流程)、`docs/INTERFACES.md`(契约)、`docs/ADR.md`;
> 改行为必改旧用例;每步本地 `ruff + py_compile + test_all + bench --quick`。
> 完成一项 → CHANGELOG/README 登记 → push → 再开下一项。

## R-01 · `process_agent_output` 状态机化(execution_layer.py:560-849,约 288 行)

> ✅ 完成(2026-09-05):两小步提交 `aa4f472`(纯抽取 `_stage_*` 阶段编排,行为不变)+
> `d66bf39`(轮内临时标志收敛 `RoundCtx` + 顶部 docstring 阶段流程图 + 验收断言);
> 回归 test_all full-access `945/945 · 跳过 8`(0 失败)、bench --quick 24/24;
> 受限环境与基线同为 9 项 Go 沙箱环境失败(非本次引入)。

- 现状:单函数串 解析→记忆→熔断→权限→快照→守门→回滚→返回,并穿插
  `pending_permission` / `current_snapshot_id` / `_round_confirmed` 等临时实例标志,状态易漂移、难单测。
- 范围:把每轮拆成显式阶段对象或至少一组私有方法(如 `_stage_parse/_stage_guard/…`),
  每个阶段只读写明确入参/返回值;临时标志收敛到“本轮上下文”对象(如 `dataclass RoundCtx`)。
- 验收:
  1) `test_all` 0 失败(回归即行为不变);新增阶段顺序/上下文不泄漏断言若干;
  2) 函数体明显缩短,阶段可在不执行整轮的情况下单测;
  3) `execution_layer.py` 顶层 docstring 画出阶段流程图(与 README 架构图对应)。
- 风险:高(核心路径);建议切分按“先抽纯函数/后合并状态”两小步各提交一次。

## R-02 · `FileTools`(tools/file_tools.py,约 1237 行)拆分

- 现状:FileOps 读改写 / TerminalView 白名单内建(ls/cat/echo…)/ TerminalExec+Go 三条执行路径挤一文件。
- 范围:拆为 `FileOps` / `TerminalView` / `TerminalExec` 三个执行器类(仍作为 ToolExecutor 的 mixin),
  分发/错误语义(400/403/404/409/500)不变。
- 验收:`test_all` 0 失败;每个新文件 ≤ ~450 行;tools/registry handler 名无需改动;
  `docs/DEVELOPMENT.md` §2 的“加工具”步骤仍适用。
- 风险:中高(路径与命令语义多,依赖 base.execute 收口与 `tools/status.py`)。

## R-03 · 双前端模型客户端合并(ai_code.py ModelClient vs agent_runner.py ModelProvider)

- 现状:两套 OpenAI/Anthropic 兼容对话引擎(流式/工具/降级)并存,行为差异是漂移源。
- 范围:统一到单一客户端(建议迁到独立 `ace_model.py` 或并入 ai_code 后由双方 import),
  URL 组装/重试(ace_http)/tools 降级/文本协议封装只留一份。
- 验收:两条 CLI(ai_code、agent_runner)行为不变;mock 与真实端点 smoke 均绿;
  `test_all` 0 失败;无第二份 `/chat/completions` 实现残留。
- 风险:高(涉及流式渲染/错误文案/提供商切换);若与 R-04 冲突,优先 R-04 后再合并。

## R-04 · ai_code.py(约 2900 行)slash/`@` 命令表驱动化

- 现状:`run_command`/`converse`/`repl` 大量 if/elif;命令与 UI mixin 桶耦合。
- 范围:slash(`/`)、`@` 命令改为声明表(名/匹配/参数/处理函数/补全描述,i18n 键),
  状态(会话/权限/引用)收敛为独立对象。
- 验收:命令集与现有帮助文案一致(`COMMANDS`/locales 测试通过);`test_all` 0 失败;
  新命令=加一行表项,不再加 if。
- 风险:高(交互路径多,依赖终端 mock 用例);建议与 i18n 键表联动迁移。

## R-05 · test_all.py(≈4500 行)拆分 runner

- 现状:单文件线性执行、段间共享顶层符号(不能单段跑),临时目录已统一 `.test_tmp/`。
- 范围:按 [N] 段拆为 `tests/` 模块(共享 fixtures/helper),配 `tests/runner.py`
  汇总 ✅/❌/⏭ 三态,支持 `--only/--skip`;`python test_all.py` 保留为入口兼容。
- 验收:入口行为与现一致(退出码语义、跳过计数);单段可跑;CI 命令不变;0 失败。
- 风险:中(机械拆分+符号导出调整);拆完后 `CONTRIBUTING` 的“用例数随平台浮动”说明仍成立。

## 推荐顺序

R-01 →(停,回归)→ R-04 → R-03 → R-02 → R-05;每项单独提交、单独回归,
不跨项共用工作区脏状态。任何一项若发现“行为必须变”,先在 BACKLOG 追加决策记录再动手。
