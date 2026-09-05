# 开发者标准化流程(改代码从哪开始,到哪算完)

> 适用:任何人(含 AI 助手)往 ace 仓库提交代码。目标:**提交前在本地完成 CI 能做的全部校验**,让 main 永远可发布。
> 配套文档:`INTERFACES.md`(接口契约)、`BACKLOG.md`(待办)、`CONTRIBUTING.md`(环境)。

## 0. 唯一真相源(Single Source of Truth)——先读这些,别改它们的“影子”

| 事实 | 唯一真相源 | 禁止另起炉灶 |
|---|---|---|
| 工具有哪些 / 权限 / schema / 示例 | `tools/registry.py` 的 `TOOL_SPECS` | ❌ 手写 function schema、权限集合、提示词工具清单 |
| 会话与格式协议 | `docs/INTERFACES.md` + `execution_layer.py` | ❌ 私自发明第二套输出格式 |
| 设计取舍 | `docs/ADR.md` | ❌ 无记录地推翻既有决策 |
| 版本事实 | `CHANGELOG.md` 首条 + README 徽章 | ❌ 双份手抄、只改一边 |

> ⚠️ 现状负债(BACKLOG Q-04/Q-07/Q-12):README 里的“工具数/只读数/断言数”、提示词工具清单、版本号仍有多处手抄漂移——**改完本流程文档后,凡触及数字一律改为“以源码为准”或由 CI 生成**,不许再写死。

## 1. 标准提交流程

```text
① 读: docs/BACKLOG.md 认领条目(或提 Issue) → CONTRIBUTING.md → 相关 docs/ADR
② 基线: python test_all.py(确认改动前绿/或已知环境跳过项) 
③ 实现: 遵守 INTERFACES.md 契约;小步提交,不要一个巨型 diff
④ 测试: 为新行为加断言(test_all.py 对应 [N] 段,不要只改不测)
⑤ 本地验证(全绿才推):
     python test_all.py                       # 全量,退出码非 0 即失败
     python benchmarks/bench_core.py --quick  # 基准健康;功能 check 失败即红
     ruff check . --select E9,F63,F7,F82      # 硬错误集(计划扩 F401/F841)
     python demo/record_demo.py --check       # 改了用户可见输出才需要
⑥ 文档: 动了行为/数字 → 同步 CHANGELOG(新增条目)、README(如涉及)、docstring
⑦ 提交: 信息 = 中文一句主题(前缀 feat/fix/docs/style/refactor)+ 要点列表(参考 git log)
⑧ 推送: push → GitHub Actions 核对 8 个 job 全绿(Python 3.10/3.11/3.12、Go×2、ruff、bench、e2e)
```

分支命名 `feat/xxx` / `fix/xxx`;改行为时把断言旧行为的用例一起改,不许只加新用例。

## 2. 新增一个工具:八步清单(唯一入口 = registry)

1. 在 `tools/registry.py` 的 `TOOL_SPECS` 加一条 `ToolSpec`(字段契约见 INTERFACES §7)。
2. 决定 `permission`:只读 `PERM_READ` / 写 `PERM_WRITE` / 高危 `PERM_HIGH_RISK`;
   会写盘、会出网、会截图、会执行的一律**不许只读**。
3. 实现 handler:`tools/<域>_tools.py` 里 `ToolExecutor` 的方法;
   普通签名 `(params)`;需要工具名时 `pass_tool_name=True` 用 `(tool_name, params)`。
4. 需要人确认才安全的设 `confirm=True`(如执行任意命令)。**默认不要设**。
5. 读/检索类工具:必须过与 `file_read` 同口径的路径 confinement + 敏感目标判定
   (当前 `parse_document` 越界是已知 P0 缺陷 SEC-02,新增工具不许再犯)。
6. 执行代码/命令的工具:不许只靠 AST 精确名拦截(见 P0 SEC-01),必须叠
   Go 执行器/job/docker 边界或引用级白名单。
7. 补断言(test_all 相应段):可用性 / 权限档位 / 错误语义(400 参数 / 403 权限 / 404 不存在 / 409 歧义)/
   熔断与守门;涉及出网工具补 SSRF/白名单用例。
8. 提示词工具清单与 function schema 由 registry **生成或由 CI diff 守卫**(BACKLOG Q-07 落地前,手动同步并注明)。

## 3. 代码风格与命名

- 类型注解:参数/返回值/dataclass 字段**全注解**;`from __future__ import annotations` 全仓统一(见 BACKLOG Q-10)。
- 错误策略:内部逻辑用异常;对外边界统一 `ExecutionResult`(字段见 INTERFACES §6)。
- 文案:用户可见输出经 `i18n`(`locales/*.json`)或至少不与错误语义耦合;
  **禁止用中文 message 子串当 error_code**(现状已记 BACKLOG)。
- 日志:内部诊断 `logging.getLogger("ace")`;**禁止宽 except + pass 吞掉 L5/会话日志写入失败**。
- 新模块命名 `ace_` 前缀小写下划线;`Archive.py/Nuwa.py` 等旧名不再新增同类。

## 4. 安全红线(写代码时默认遵守)

- 路径:文件内容读取**一律限项目内**;绝对路径写只对“明确意图”放行;敏感目标(`~/.ssh`、`.pem/.key`、`.guardian`)任何档位都不给。
- 外发:默认按 `egress_allowlist` 判定;出站工具都要过 `safe_request`(SSRF pin-IP/逐跳)。
- 非 tty:一切授权/计划审批 fail-close。
- 快照:写工具由执行层自动快照;不得让 Agent 可写 `.guardian/`。
- 越权假设:不要假设“模型不会…”;安全以执行层与沙箱为界,不靠提示词。

## 5. 验证命令速查

```bash
python test_all.py                          # 全量测试
python test_all.py --strict                   # 把“能力不足跳过”当失败(严格复现)(≤2 分钟)
python benchmarks/bench_core.py --quick     # 基准健康
ruff check . --select E9,F63,F7,F82         # 硬错误(计划扩 F401/F841)
python -m compileall -q <改动的文件>         # 编译检查
python e2e/real_model_smoke.py              # 真实模型冒烟(需 ACE_E2E_* env,缺省跳过)
python demo/record_demo.py --check          # 演示动画一致性
```

受限环境(无 Go Job Object/禁联网/系统临时区只读)下的测试应走 SKIPPED 通道如实标注(BACKLOG Q-03),不许假绿、不许整脚本崩。
