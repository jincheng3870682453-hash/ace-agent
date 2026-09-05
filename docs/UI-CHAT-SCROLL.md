# 立项卡:ACE 聊天内置滚动(方案 C)

> 目标:滚轮/翻页**只滚动 ACE 自己管理的对话缓冲**,上滑**永远到不了首页/菜单/其他界面**。
> 与 alt-screen(全锁)不同:对话区内仍可滚动历史。
> 状态:引擎(ace_chatscroll.py)已实现并有单测;REPL 接线两处为待办(见 §5)。

## 1. 目标行为
- 对话每次刷新只画"屏幕底部 H 行"的视口(视口内容 = 会话历史最后一段);
- ↑ 上滚/↓ 下滚/PgUp/PgDn/滚轮:只在**会话行缓冲**里平移,`scroll=0`(贴底)为默认;
- 缓冲只含本会话行(用户行、助手回复、状态完成行),**不含登录页/菜单** → 滚不出会话;
- 输入提示固定在视口下方一行,不随内容滚走。

## 2. 已交付:ace_chatscroll.py(纯逻辑,可单测)
- `ChatScroll`:append(line) 入缓冲(上限 e.g. 2000 行裁旧)、`scroll_line(delta)`、`view()` -> (start,end,lines)。
- `decode_wheel(seq) -> -1/0/+1`:解析 SGR 鼠标滚轮序列 `ESC[<64;col;rowM`(上)/`<65…`(下),
  兼容无 SGR 的 `ESC[M` 前缀容错(返回 None 当非滚轮)。
- 键位映射表 `KEY_ROLL:{向上/PageUp/小键盘8…}` 供接线方翻译成 delta(实现在 ai_code 键循环内)。

## 3. 接线待办(需真机逐帧调,不建议盲合)
- T1 `ai_code.repl` 输入侧:prompt_toolkit 加 PgUp/PgDn 绑定(PromptSession key_bindings 已存在 kb,再加两键)→ 修改 `scroll` 并重绘视口;普通 input() 降级路径:开启鼠标上报后无法用 input() 接滚轮,需切原始读取——该路径暂保持"每轮追加打印"。
- T2 流式打印(`on_delta`/`converse`):把每轮产出行 append 进 ChatScroll 并改为**底部视口重绘**,`spinner` 状态行移入视口外固定行。
- T3 滚轮:会话内发送 `ESC[?1000h ESC[?1006h`,退出还原 `…l`;stdin 读取轮询(与输入共存)在 T1 路径内解。
- 验收(真机):聊天 30+ 轮后 PgUp 能翻回第 1 轮但**永远看不到启动菜单**;滚轮上下同;退出会话后还原终端状态。
- 回归门槛:`test_all` 0 失败;`python ai_code.py --mock --input …` 行为不变(非交互不启用视口)。

## 4. 已做的最小改动
- alt-screen 默认关(`ACE_ALTSCREEN=1` 才开)——避免"完全锁滚"堵死体验。

## 5. 风险
- cmd 鼠标 SGR 支持随 conhost 版本波动;若探测失败 → 回退 PgUp/PgDn/方向键滚动(键盘路径恒可用),并在启动提示里说明。
