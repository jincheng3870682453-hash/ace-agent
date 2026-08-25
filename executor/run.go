package main

// run.go —— exec.command / exec.python 的实际执行路径。
//
// 这里承担的是宿主 Python 侧 subprocess.run(shell=True) 原来干的事，区别在三点：
//   1. 只接受 argv 数组，没有任何 shell 解释——命令注入在协议层就不可表达
//   2. 环境变量按白名单重建，不继承宿主的全部环境
//   3. 进程树、内存、进程数、超时都有硬上限，且终止走整树回收

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type envPolicy struct {
	// Mode: allowlist（默认）| inherit | none
	Mode  string            `json:"mode"`
	Allow []string          `json:"allow"`
	Set   map[string]string `json:"set"`
}

// sandboxSpec 是宿主请求的沙箱形态。
//
// 注意这里分成两类字段：Tier / AllowWeakerTier 是**已实现**的，其余四个
// （Policy / WritableRoots / NetworkAccess / ScratchDir）描述的是**文件系统与网络边界**，
// 而 Tier-0 和 Tier-1 都不提供这两种边界 —— Job Object 限的是资源与进程树，
// 受限令牌刻意不加 restricting SID（见 sandbox_windows.go 常量处的说明）。
//
// 它们仍然留在结构体里，因为 Tier-2 会用到；但收到时必须**报错而不是静默忽略**。
// 静默忽略是这一类字段最危险的处理方式：调用方写下 `network_access: false` 之后
// 会以为子进程没有网络，然后在这个假设上做别的决定。宁可让请求失败。
type sandboxSpec struct {
	Policy        string   `json:"policy"`
	WritableRoots []string `json:"writable_roots"`
	// NetworkAccess 是指针：bool 的零值就是 false，值类型无法区分"没传"和
	// "显式要求断网"，而这两者的正确处理恰好相反。
	NetworkAccess   *bool  `json:"network_access"`
	Tier            string `json:"tier"`
	AllowWeakerTier bool   `json:"allow_weaker_tier"`
	ScratchDir      string `json:"scratch_dir"`
}

// unenforceable 列出请求里"要求了但本执行器保证不了"的边界。
//
// 返回值是给宿主看的字段名清单，空切片表示这次请求没越界。
func (s sandboxSpec) unenforceable() []string {
	var out []string
	if s.Policy != "" && s.Policy != "unrestricted" {
		out = append(out, "policy="+s.Policy)
	}
	if len(s.WritableRoots) > 0 {
		out = append(out, "writable_roots")
	}
	if s.NetworkAccess != nil && !*s.NetworkAccess {
		out = append(out, "network_access=false")
	}
	if s.ScratchDir != "" {
		out = append(out, "scratch_dir")
	}
	return out
}

type execLimits struct {
	MaxOutputBytes    int64  `json:"max_output_bytes"`
	MaxMemoryBytes    uint64 `json:"max_memory_bytes"`
	MaxChildProcesses uint32 `json:"max_child_processes"`
}

type policyDecision struct {
	Decision string `json:"decision"`
	RuleID   string `json:"rule_id"`
	Approved bool   `json:"approved"`
}

type execParams struct {
	// exec.command
	Argv []string `json:"argv"`
	// exec.python
	Source   string `json:"source"`
	Filename string `json:"filename"`
	Python   string `json:"python"`

	CWD       *string         `json:"cwd"`
	TimeoutMS int             `json:"timeout_ms"`
	Stdin     *string         `json:"stdin"`
	Stream    bool            `json:"stream"`
	EnvPolicy envPolicy       `json:"env_policy"`
	Sandbox   sandboxSpec     `json:"sandbox"`
	Limits    execLimits      `json:"limits"`
	Policy    *policyDecision `json:"policy_decision"`
}

// defaultEnvAllow 是没给 allow 列表时的兜底。少了这些 Windows 上很多程序直接起不来
// （COMSPEC 缺失会让部分工具链退化，SystemRoot 缺失会让 DLL 解析失败）。
//
// SystemDrive / ProgramData / ALLUSERSPROFILE 不是为了"起得来"，是为了**别拉屎**：
// Windows shell 层（shell32 的缓存等）里有一批路径写成 `%SystemDrive%\ProgramData\...`
// 的字面量，要靠环境变量展开。变量不在环境里时展开留下原文，于是那条路径变成**相对路径**，
// 子进程就在自己的 cwd（= 用户的项目目录）里造出一棵名字叫 `%SystemDrive%` 的垃圾目录树。
// 这是真实踩到的：`executor/%SystemDrive%/ProgramData/Microsoft/Windows/Caches/` 就这么来的。
// 这三个变量的值是机器级公共路径（`C:` / `C:\ProgramData`），本身不含机密，
// 从已经放行的 SystemRoot 也能推出来，放行它们没有额外泄漏面。
// 故意**不**放行 APPDATA / LOCALAPPDATA：那是当前用户可写的状态目录，
// 把它交给沙箱里的子进程等于白送一块持久化落脚点。
var defaultEnvAllow = []string{
	"PATH", "PATHEXT", "SystemRoot", "WINDIR", "COMSPEC",
	"SystemDrive", "ProgramData", "ALLUSERSPROFILE",
	"TEMP", "TMP", "HOME", "USERPROFILE", "LANG", "LC_ALL",
	"PYTHONIOENCODING",
}

func (p *execParams) buildEnv() []string {
	var out []string
	switch strings.ToLower(p.EnvPolicy.Mode) {
	case "inherit":
		out = append(out, os.Environ()...)
	case "none":
		// 空环境。
	default: // allowlist
		allow := p.EnvPolicy.Allow
		if len(allow) == 0 {
			allow = defaultEnvAllow
		}
		// Windows 环境变量名大小写不敏感，白名单匹配也必须不敏感，
		// 否则宿主写 "Path" 而系统里是 "PATH" 就会静默丢掉 PATH。
		want := map[string]bool{}
		for _, k := range allow {
			want[strings.ToUpper(k)] = true
		}
		for _, kv := range os.Environ() {
			if i := strings.IndexByte(kv, '='); i > 0 && want[strings.ToUpper(kv[:i])] {
				out = append(out, kv)
			}
		}
	}
	for k, v := range p.EnvPolicy.Set {
		out = append(out, k+"="+v)
	}
	return out
}

// outcome 是一次执行的终态。error 非空表示未能正常跑完（超时/取消/起不来）。
type outcome struct {
	ExitCode  int            `json:"exit_code"`
	Signal    *string        `json:"signal"`
	DurationM int64          `json:"duration_ms"`
	Truncated bool           `json:"truncated"`
	Bytes     map[string]int `json:"bytes"`
	// Captured 是上限之内实际留下的字节数；Bytes 是子进程写出的总量。两者不同时
	// 说明发生了截断，宿主据此判断"少的那部分是被限额挡了"而不是"传输丢了"。
	Captured map[string]int `json:"captured_bytes"`
	// Digest 是 captured 字节的 sha256（hex）。开流时宿主把收到的事件拼起来核对这个
	// 摘要 —— 只有这样"我拿到的就是执行器留下的那些字节"才是可验证的，而不是靠信任。
	Digest    map[string]string `json:"digest"`
	Sandbox   sandboxApplied    `json:"sandbox_applied"`
	StdoutB64 string            `json:"stdout_b64,omitempty"`
	StderrB64 string            `json:"stderr_b64,omitempty"`
}

// capturedStream 边收集边（可选）推流，并在累计字节超限时停止收集但继续排空管道。
//
// 继续排空是必须的：如果超限后直接不读，子进程写满管道缓冲会永久阻塞在 write 上，
// 于是超时到点才被杀掉——一个本该立刻返回"输出过大"的请求变成必然超时。
type capturedStream struct {
	name       string
	buf        strings.Builder
	sum        hash.Hash
	total      int64
	cap        int64
	truncated  bool
	cappedSent bool
}

func newCapturedStream(name string, capBytes int64) *capturedStream {
	return &capturedStream{name: name, cap: capBytes, sum: sha256.New()}
}

// captured 是**实际留下的**字节数（等于 resp 里带回的内容长度），与 total 不同：
// total 是子进程写了多少，captured 是上限之内收了多少。
func (c *capturedStream) captured() int { return c.buf.Len() }

func (c *capturedStream) digest() string {
	return hex.EncodeToString(c.sum.Sum(nil))
}

// pump 的 onChunk 签名带 offset 与 capped：宿主要能把乱序/丢帧的事件拼回原位，
// 也要知道"从这里开始不再有内容了"，而不是把截断当成子进程自己停了。
func (c *capturedStream) pump(r io.Reader, onChunk func(b []byte, offset int64, capped bool)) {
	b := make([]byte, MaxChunkBytes)
	for {
		n, err := r.Read(b)
		if n > 0 {
			chunk := b[:n]
			offset := c.total
			// **先按上限裁剪，再推流。** 反过来写（原实现）的话，max_output_bytes
			// 只约束了 resp 里的缓冲，事件流仍按子进程的实际输出量无限往宿主推 ——
			// 一个 `yes` 循环能把宿主内存吃光，而限额看起来是设过的。
			emit := chunk
			capped := false
			switch {
			case c.total >= c.cap:
				emit, capped = nil, true
			case int64(n) > c.cap-c.total:
				emit, capped = chunk[:c.cap-c.total], true
			}
			if len(emit) > 0 {
				c.buf.Write(emit)
				c.sum.Write(emit)
			}
			if capped {
				c.truncated = true
			}
			c.total += int64(n)
			// 截断后只发一次"到顶了"的标记帧，之后彻底安静：每次读都发一个空帧
			// 等于把限额换成了另一种刷屏。
			if onChunk != nil && (len(emit) > 0 || (capped && !c.cappedSent)) {
				onChunk(emit, offset, capped)
			}
			if capped {
				c.cappedSent = true
			}
		}
		if err != nil {
			return
		}
	}
}

// runExec 是 exec.command 与 exec.python 的公共执行体。
//
// cancelReason 由外部（cancel 方法或超时）写入后再触发 ctx 取消，这样 Wait 返回时
// 能区分"宿主主动取消"和"超时"——两者的错误码不同，用户看到的解释也不同。
func runExec(
	ctx context.Context,
	id string,
	fw *frameWriter,
	seq *seqCounter,
	p *execParams,
	argv []string,
	cancelReason *atomic.Value,
) (*outcome, *rpcError) {

	if len(argv) == 0 {
		return nil, newError(ErrBadRequest, "argv is empty", nil)
	}

	// 执行器不信任宿主已经判过闸。宿主自己标成 forbidden 的东西绝不执行；
	// 标成 prompt 但没带批准的同样不执行（失败方向朝安全）。
	if p.Policy != nil {
		switch p.Policy.Decision {
		case "forbidden":
			return nil, newError(ErrPolicyDenied, "host declared this command forbidden",
				map[string]any{"rule_id": p.Policy.RuleID, "approvable": false})
		case "prompt":
			if !p.Policy.Approved {
				return nil, newError(ErrPolicyDenied, "command requires approval but none was granted",
					map[string]any{"rule_id": p.Policy.RuleID, "approvable": true})
			}
		}
	}

	lim := p.Limits
	if lim.MaxOutputBytes <= 0 || lim.MaxOutputBytes > MaxOutputBytes {
		lim.MaxOutputBytes = MaxOutputBytes
	}
	if lim.MaxChildProcesses == 0 {
		lim.MaxChildProcesses = 32
	}

	// 要求了本执行器给不了的边界时直接拒绝，理由与 tier2 报 unavailable 同源：
	// 声明可用却不生效，比明确失败危险得多。
	if bad := p.Sandbox.unenforceable(); len(bad) > 0 {
		return nil, newError(ErrSandboxUnavailable,
			"requested boundaries are not enforced by any implemented tier",
			map[string]any{
				"unenforceable": bad,
				"needs":         tierDocker,
				"reason":        "tier0/tier1 只提供进程、资源与身份边界；文件系统与网络边界要等 tier2_docker",
			})
	}

	conf, unavailReason := resolveConfinement(p.Sandbox.Tier, p.Sandbox.AllowWeakerTier, lim)
	if conf == nil {
		avail, _ := sandboxInventory()
		return nil, newError(ErrSandboxUnavailable, "requested sandbox tier is not available",
			map[string]any{
				"requested":         p.Sandbox.Tier,
				"available":         avail,
				"reason":            unavailReason,
				"allow_weaker_tier": false,
			})
	}
	defer conf.release()

	// buildCmd 每次都造一个全新的 exec.Cmd。
	// 为什么不复用：Start 失败后 exec.Cmd 已经关掉了自己的管道，不能再 Start 一次；
	// 而受限令牌可能导致首次 Start 失败并需要放弃令牌重试（见下面的 relaxAfterSpawnFailure）。
	buildCmd := func() (*exec.Cmd, io.ReadCloser, io.ReadCloser, *rpcError) {
		c := exec.Command(argv[0], argv[1:]...)
		c.Env = p.buildEnv()
		if p.CWD != nil && *p.CWD != "" {
			c.Dir = *p.CWD
		}
		if p.Stdin != nil {
			c.Stdin = strings.NewReader(*p.Stdin)
		}
		so, err := c.StdoutPipe()
		if err != nil {
			return nil, nil, nil, newError(ErrInternal, "stdout pipe: "+err.Error(), nil)
		}
		se, err := c.StderrPipe()
		if err != nil {
			return nil, nil, nil, newError(ErrInternal, "stderr pipe: "+err.Error(), nil)
		}
		if err := conf.prepare(c); err != nil {
			return nil, nil, nil, newError(ErrInternal, "sandbox prepare: "+err.Error(), nil)
		}
		return c, so, se, nil
	}

	cmd, stdout, stderr, rerr := buildCmd()
	if rerr != nil {
		return nil, rerr
	}

	started := time.Now()
	if err := cmd.Start(); err != nil {
		// 受限令牌会让某些可执行文件根本起不来。已实测的例子：Microsoft Store 版
		// python.exe 是"应用执行别名"（一个 reparse point），受限令牌解析不了它，
		// Windows 返回 ERROR_CANT_ACCESS_FILE。
		//
		// 这时放弃令牌重试一次，而不是让请求失败：Job Object 的进程树/资源边界还在，
		// 丢掉的只是身份边界，且会如实写进 sandbox_applied。反过来若坚持失败，
		// 装了 Store Python 的机器上 code_execute 会直接不可用 —— 拿"完全不能用"
		// 换"少一层纵深"，不是划算的交易。
		relaxed := false
		if r, ok := conf.(spawnRelaxer); ok {
			relaxed = r.relaxAfterSpawnFailure(err)
		}
		if !relaxed {
			return nil, newError(ErrSpawnFailed, err.Error(),
				map[string]any{"argv0": argv[0]})
		}
		_, _ = stdout.Close(), stderr.Close()
		cmd, stdout, stderr, rerr = buildCmd()
		if rerr != nil {
			return nil, rerr
		}
		started = time.Now()
		if err2 := cmd.Start(); err2 != nil {
			return nil, newError(ErrSpawnFailed, err2.Error(),
				map[string]any{"argv0": argv[0]})
		}
	}
	if err := conf.afterStart(cmd); err != nil {
		// afterStart 失败时进程已被它自己杀掉，这里只需要把 Wait 收尾以免留下 zombie。
		_ = cmd.Wait()
		return nil, newError(ErrSpawnFailed, "sandbox attach: "+err.Error(),
			map[string]any{"tier": p.Sandbox.Tier})
	}

	applied := conf.applied()
	fw.emitEvent(id, seq, "started", map[string]any{
		"pid":             cmd.Process.Pid,
		"sandbox_applied": applied,
	})

	outS := newCapturedStream("stdout", lim.MaxOutputBytes)
	errS := newCapturedStream("stderr", lim.MaxOutputBytes)
	var wg sync.WaitGroup
	wg.Add(2)
	mkChunk := func(stream string) func([]byte, int64, bool) {
		if !p.Stream {
			return nil
		}
		return func(b []byte, offset int64, capped bool) {
			data := map[string]any{
				"stream":   stream,
				"offset":   offset,
				"data_b64": base64.StdEncoding.EncodeToString(b),
			}
			if capped {
				// 只在到顶那一帧带上：宿主看到它就知道后面不会再有这条流的内容，
				// 而不是把"限额挡住了"误判成"子进程自己不写了"。
				data["capped"] = true
			}
			fw.emitEvent(id, seq, "output", data)
		}
	}
	go func() { defer wg.Done(); outS.pump(stdout, mkChunk("stdout")) }()
	go func() { defer wg.Done(); errS.pump(stderr, mkChunk("stderr")) }()

	waitDone := make(chan error, 1)
	go func() {
		// 必须先等管道读完再 Wait：Wait 会关闭管道，抢在 pump 之前关掉就会丢尾部输出。
		wg.Wait()
		waitDone <- cmd.Wait()
	}()

	killMethod := ""
	killed := false
	var waitErr error
	select {
	case waitErr = <-waitDone:
	case <-ctx.Done():
		killed = true
		killMethod, _ = conf.killTree(cmd)
		// 杀完仍要等 Wait 返回，否则 pump goroutine 和进程句柄都泄漏。
		// 但这个等待必须有界，见 reapAfterKill 的说明。
		var reaped bool
		waitErr, reaped = reapAfterKill(waitDone, reapGrace, func() {
			// killTree 没能收掉整棵树时，至少把直接子进程按死：Wait 只等它。
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
		})
		if !reaped {
			// 注意这里**不能**去读 outS/errS：pump goroutine 还在往里写，
			// 读 total/buf 就是数据竞争（-race 会直接抓到）。所以这条路径上
			// 一个字节的输出都不报，只报"没收干净"这个事实。
			return nil, newError(ErrInternal,
				"child did not exit after kill; output pipes still held by a survivor",
				map[string]any{
					"duration_ms": time.Since(started).Milliseconds(),
					"killed":      true,
					"kill_method": killMethod,
					"reaped":      false,
				})
		}
	}

	dur := time.Since(started).Milliseconds()
	bytesMap := map[string]int{"stdout": int(outS.total), "stderr": int(errS.total)}
	truncated := outS.truncated || errS.truncated

	if killed {
		reason := ErrTimeout
		msg := fmt.Sprintf("execution exceeded timeout_ms=%d", p.TimeoutMS)
		if v, ok := cancelReason.Load().(string); ok && v == "canceled" {
			reason = ErrCanceled
			msg = "canceled by host"
		}
		return nil, newError(reason, msg, map[string]any{
			"duration_ms": dur,
			"killed":      true,
			"kill_method": killMethod,
			"bytes":       bytesMap,
			"truncated":   truncated,
		})
	}

	exitCode := 0
	if waitErr != nil {
		var ee *exec.ExitError
		if errors.As(waitErr, &ee) {
			exitCode = ee.ExitCode()
		} else {
			return nil, newError(ErrInternal, "wait: "+waitErr.Error(), map[string]any{
				"duration_ms": dur, "bytes": bytesMap,
			})
		}
	}

	oc := &outcome{
		ExitCode:  exitCode,
		DurationM: dur,
		Truncated: truncated,
		Bytes:     bytesMap,
		Captured:  map[string]int{"stdout": outS.captured(), "stderr": errS.captured()},
		Digest:    map[string]string{"stdout": outS.digest(), "stderr": errS.digest()},
		Sandbox:   applied,
	}
	// stream=false 时事件流里什么都没有，输出只能靠 resp 带回，否则宿主拿不到结果。
	if !p.Stream {
		oc.StdoutB64 = base64.StdEncoding.EncodeToString([]byte(outS.buf.String()))
		oc.StderrB64 = base64.StdEncoding.EncodeToString([]byte(errS.buf.String()))
	}
	return oc, nil
}

// reapGrace 是 killTree 之后允许 Wait 返回的时间。
//
// 5s 的依据：这段等待里唯一该发生的事是内核回收进程与关掉管道，正常情况是毫秒级；
// 拖到秒级只可能是还有存活者攥着继承来的 stdout 句柄。等更久不会改变结论。
const reapGrace = 5 * time.Second

// reapAfterKill 在杀完进程树之后有界地等 Wait 返回。
//
// 为什么必须有界：原来这里是裸的 `waitErr = <-waitDone`。waitDone 由
// 「wg.Wait() 然后 cmd.Wait()」的 goroutine 供给，而 wg.Wait() 要等两条 pump 读到
// EOF。EOF 的条件是管道**所有**写端都关闭 —— 不只是直接子进程，还包括它派生出去、
// 继承了同一个句柄的孙子进程。killTree 在 Tier-0 上只能尽力而为（Tier-1 的 Job
// Object 才有整树保证），一个逃出去的孙子进程就足以让 EOF 永不到来。
//
// 后果不是"这次执行慢"，而是执行器这一侧的 goroutine + 进程句柄 + 两个管道永久泄漏，
// 而且请求永远拿不到 resp —— 宿主只能等满自己的超时，然后把原因误报成传输超时。
// 长驻会话里这种泄漏会累积。
//
// 返回 reaped=false 表示放弃等待。调用方在这条路径上必须视 pump 仍在运行：
// 任何对捕获缓冲区的读取都是数据竞争。
func reapAfterKill(waitDone <-chan error, grace time.Duration,
	hardKill func()) (err error, reaped bool) {
	select {
	case err = <-waitDone:
		return err, true
	case <-time.After(grace):
	}
	if hardKill != nil {
		hardKill()
	}
	select {
	case err = <-waitDone:
		return err, true
	case <-time.After(grace):
		return nil, false
	}
}

// pythonArgv 把源码落到临时文件再执行，而不是 `python -c <source>`。
//
// 走 -c 的话源码要经过命令行，Windows 命令行长度上限约 32K，且换行与引号在
// CreateProcess 的解析规则下极易被改写；落文件把源码彻底移出命令行语法。
// -I（isolated）连带关掉 PYTHONPATH、用户 site-packages 和 sys.path[0] 注入，
// -B 不写 __pycache__，避免在只读目录里因写字节码失败。
func pythonArgv(p *execParams) (argv []string, cleanup func(), rerr error) {
	py := p.Python
	if py == "" {
		py = os.Getenv("ACE_PYTHON")
	}
	if py == "" {
		if runtime.GOOS == "windows" {
			py = "python"
		} else {
			py = "python3"
		}
	}
	name := p.Filename
	if name == "" {
		name = "snippet.py"
	}
	// 只取基名，防止 filename 里带路径穿越写到别处。
	name = filepath.Base(filepath.FromSlash(name))
	if !strings.HasSuffix(strings.ToLower(name), ".py") {
		name += ".py"
	}

	dir, err := os.MkdirTemp("", "ace-exec-")
	if err != nil {
		return nil, nil, err
	}
	cleanup = func() { os.RemoveAll(dir) }
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(p.Source), 0o600); err != nil {
		cleanup()
		return nil, nil, err
	}
	return []string{py, "-I", "-B", path}, cleanup, nil
}
