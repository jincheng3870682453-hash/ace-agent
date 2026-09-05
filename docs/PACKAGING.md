# 打包与分发评估(Q-13 结论)

> 状态:**结论已定,暂不产出 wheel/pyproject 入口**。原因如下;实施条件见文末。

## 结论

**维持“源码运行”作为唯一分发形态**(`git clone` + `python test_all.py` / `ace.cmd` / `uv run`),
在完成 P2 布局重构(见下)之前**不**发布 `pyproject.toml` 的 console 入口或 wheel。

## 为什么不能现在打包

运行时代码把资源相对自身模块解析,扁平布局安装后必然“装得上跑不动”:

| 资源 | 解析方式 | 扁平 wheel 后 |
|---|---|---|
| 系统提示词 `prompts/*.md` | `agent_runner.py: FOLDER / "prompts"`(`__file__.parent`) | ✗ 落在 site-packages 根,相对路径失效 |
| 国际化 `locales/*.json` | `i18n.py: __file__.parent / "locales"` | ✗ 同上 |
| CLI 数据/桌面目录注入 | `ai_code.py: FOLDER` | ✗ 同上 |
| Go 执行器二进制 | `ace_executor.py: __file__.parent / "executor" / <name>` | ✗ 需另行分发/就地 go build |
| 顶层扁平模块 | `import ai_code` 等 21 个根级 .py | wheel 会散落 site-packages 污染命名空间 |

若强行给 `console_scripts: ace = ai_code:main`,安装后第一次读取提示词即失败——比“没有入口”更糟。

## 实施条件(与 P2 布局重构绑定)

1. **R-03/R-04(或独立“布局迁移”项)完成后再做**:
   - 把根级模块收进包目录 `ace/`(`ace/ai_code.py` …),`py-modules` 从 21 降为 1,命名空间干净;
   - 资源路径改用 `importlib.resources`(或包内相对 `Path(__file__).parent`)并加 package-data;
   - console 入口 `ace = "ace.ai_code:main"`;
   - Go 执行器保持“部署方就地 `go build`”,wheel 不含二进制(与现状一致,README 已说明)。
2. **安装冒烟门槛**:`pip install -e .` + `ace --input "hi"`(mock 档)能跑通,
   且 `test_all.py` 在安装态(非仓库根运行)下仍绿,才允许声称“可安装”。

## 现状对用户已足够

- `README` 明示源码运行;`ace.cmd`(Windows PATH 探测)与 `uv` 均可启动。
- 未来如要 PyPI 分发,按“实施条件”迭代,并在 CHANGELOG/README 发布说明中声明安装形态。
