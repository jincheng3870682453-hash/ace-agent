# 贡献指南(Contributing)

> 开发流程、接口契约、待办见:`docs/DEVELOPMENT.md`(标准化八步与新增工具清单)、
> `docs/INTERFACES.md`(接口与类型契约)、`docs/BACKLOG.md`(待办)、`README.md`(总览)。
> 本文件只留环境与最简纪律。

## 环境准备

- Python ≥ 3.10(建议 3.11/3.12);核心零第三方依赖,跑测试不需要额外安装
- 真实模型对话需要 `requests`(`pip install requests`)
- 可选:`prompt_toolkit`(`/` 与 `@` 实时补全菜单,`ace --install-ui`)
- 本机无系统 Python 时可用 `uv`(`uv python install 3.12` 后以该解释器运行)

## 跑测试与校验(提交前本地全过)

```bash
python test_all.py                          # 全量端到端测试;退出码非 0 即失败
python test_all.py --strict                   # 把“能力不足跳过”当失败(CI/严格复现)
python benchmarks/bench_core.py --quick     # 基准健康;正确性 check 失败退出码非 0
ruff check . --select E9,F63,F7,F82,F401,F841,E711,F811   # CI 同款;F401/F841 用 ruff --fix
python -m compileall -q <改动的模块>          # 编译检查
python e2e/real_model_smoke.py              # 真实模型冒烟(需 ACE_E2E_* env,缺省跳过)
```

- 用例总数**随平台浮动**,不写死数字——看退出码与失败列表。
- 受限环境(无 Go Job Object / 禁联网 / 系统临时区只读)下,测试应优雅跳过并如实标注,
  不许假绿、不许整脚本 traceback;临时目录统一落 `.test_tmp/`。
- 改了行为就把断言旧行为的用例一起改,不要只加新用例。

## 代码纪律(摘要;细节见 docs/)

- **工具唯一真相源 = `tools/registry.py` 的 `TOOL_SPECS`**:新增工具在 registry 加一条 +
  实现 handler(八步清单见 `docs/DEVELOPMENT.md` §2)。禁止手写第二份
  function schema / 权限集合 / 提示词工具清单。
- 对外边界返回 `tools.result.ExecutionResult`;内部逻辑用异常。
- 类型注解补全;用户可见文案走 i18n,不许用中文 message 子串承载错误语义。
- 读/检索类工具必须过与 `file_read` 同口径的路径闸门;执行类工具不许只靠 AST 精确名
  拦截,要叠 Go 执行器/job/docker 边界或引用级白名单(历史教训见 BACKLOG SEC-01/02)。
- 新模块用 `ace_` 前缀、小写下划线;旧名(`Archive/Nuwa/work/...`)不再新增同类。

## 提交流程

1. 从 `main` 切分支,命名 `feat/xxx` / `fix/xxx` / `docs/xxx`。
2. 改动后本地跑完上面"跑测试与校验"一段,全绿。
3. 提交信息 = 中文一句话主题(带前缀)+ 要点列表(参考 git log)。
4. push 后等 GitHub Actions:Python 3.10/3.11/3.12 全量测试 + ruff + Go×2 +
   bench + 真实模型 e2e(secrets 门控),8 个 job 全绿才算完。

## 结构速览

完整目录树见 `README.md`「项目结构」(以它为准,这里不重复抄以免漂移)。
关键入口:执行层 `execution_layer.py` · 工具注册表 `tools/registry.py` ·
交互循环 `agent_runner.py` · 前端 `ai_code.py` · 全量测试 `test_all.py`。
