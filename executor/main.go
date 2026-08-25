package main

// main.go —— 会话循环与方法分发。
//
// 单进程长驻，一条 stdin 一条 stdout。读循环是单线程的（保证 initialize 的"必须最先"
// 判定不需要加锁），每个 exec 请求各自开 goroutine，因此 cancel 才能在目标还在跑的
// 时候被处理——如果读循环阻塞在执行上，cancel 帧永远读不到，整个取消机制形同虚设。

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	serverName    = "ace-executor"
	serverVersion = "0.1.0"
)

// stderrLog 是唯一允许的日志出口。stdout 属于协议，写一个字节的非协议内容就会毁掉会话。
var stderrLog = os.Stderr

type task struct {
	cancel context.CancelFunc
	// reason 在触发 cancel 之前写入，用来区分超时与主动取消。
	reason *atomic.Value
}

type session struct {
	fw          *frameWriter
	initialized bool

	mu    sync.Mutex
	tasks map[string]*task
	// seen 记录所有见过的 req id，用于拒绝重复 id。
	// 重复 id 会让"一个 req 恰好一个 resp"的不变量失效，宿主的等待表会错配。
	seen map[string]bool
}

func newSession(fw *frameWriter) *session {
	return &session{fw: fw, tasks: map[string]*task{}, seen: map[string]bool{}}
}

func (s *session) register(id string, t *task) {
	s.mu.Lock()
	s.tasks[id] = t
	s.mu.Unlock()
}

func (s *session) unregister(id string) {
	s.mu.Lock()
	delete(s.tasks, id)
	s.mu.Unlock()
}

func (s *session) lookup(id string) *task {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tasks[id]
}

// claimID 原子地判重并登记。返回 false 表示这个 id 用过了。
func (s *session) claimID(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen[id] {
		return false
	}
	s.seen[id] = true
	return true
}

func main() {
	fw := newFrameWriter(os.Stdout)
	s := newSession(fw)

	sc := bufio.NewScanner(os.Stdin)
	// Scanner 默认单行上限 64KB，命令行加上 base64 的 stdin 很容易超过，
	// 超了会直接结束扫描且不报错——表现是会话莫名静默中断。必须显式放大到协议上限。
	sc.Buffer(make([]byte, 0, 64<<10), MaxLineBytes)

	var wg sync.WaitGroup
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var f inFrame
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			// 解析不出 id 就无从回帧，只能记 stderr。不终止会话——一行坏数据
			// 不该让整个执行器退出，否则宿主侧一次编码 bug 就变成服务中断。
			fmt.Fprintf(stderrLog, "malformed frame dropped: %v\n", err)
			continue
		}
		s.handle(&f, &wg)
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintf(stderrLog, "stdin read error: %v\n", err)
	}

	// stdin 关闭意味着宿主走了。先把在跑的任务全取消，再等它们收尾，
	// 保证 Job 句柄被 release、子进程不留孤儿。
	s.mu.Lock()
	for _, t := range s.tasks {
		t.reason.Store("canceled")
		t.cancel()
	}
	s.mu.Unlock()
	wg.Wait()
}

func (s *session) handle(f *inFrame, wg *sync.WaitGroup) {
	if f.Type != "req" {
		fmt.Fprintf(stderrLog, "ignoring non-req frame type=%q\n", f.Type)
		return
	}
	if f.ID == "" {
		fmt.Fprintf(stderrLog, "ignoring req with empty id\n")
		return
	}
	if !s.claimID(f.ID) {
		s.fw.respondError(f.ID, newError(ErrDuplicateID,
			"this id was already used in this session", map[string]any{"id": f.ID}))
		return
	}

	if f.Method != "initialize" && !s.initialized {
		s.fw.respondError(f.ID, newError(ErrNotInitialized,
			"initialize must be the first request of the session", nil))
		return
	}

	switch f.Method {
	case "initialize":
		s.handleInitialize(f)
	case "cancel":
		s.handleCancel(f)
	case "shutdown":
		s.fw.respondResult(f.ID, map[string]any{"ok": true})
		os.Stdin.Close()
	case "exec.command", "exec.python":
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handleExec(f)
		}()
	default:
		s.fw.respondError(f.ID, newError(ErrUnknownMethod,
			"unknown method: "+f.Method, map[string]any{"method": f.Method}))
	}
}

func (s *session) handleInitialize(f *inFrame) {
	if s.initialized {
		s.fw.respondError(f.ID, newError(ErrAlreadyInitialized, "session already initialized", nil))
		return
	}
	var p struct {
		ProtocolVersions []int `json:"protocol_versions"`
	}
	_ = json.Unmarshal(f.Params, &p)
	if len(p.ProtocolVersions) > 0 {
		ok := false
		for _, v := range p.ProtocolVersions {
			if v == ProtocolVersion {
				ok = true
			}
		}
		if !ok {
			s.fw.respondError(f.ID, newError(ErrUnsupportedVersion,
				"no mutually supported protocol version",
				map[string]any{"client": p.ProtocolVersions, "server": []int{ProtocolVersion}}))
			return
		}
	}

	avail, unavail := sandboxInventory()
	features := []string{
		"exec.command", "exec.python", "stream.stdout", "cancel.graceful", "shutdown",
	}
	if len(avail) > 1 {
		features = append(features, "sandbox.job_object")
	}

	s.initialized = true
	s.fw.respondResult(f.ID, map[string]any{
		"server": map[string]any{
			"name": serverName, "version": serverVersion,
			"language": "go", "language_version": runtime.Version(),
			"goos": runtime.GOOS, "goarch": runtime.GOARCH,
		},
		"protocol_version": ProtocolVersion,
		"features":         features,
		"sandbox": map[string]any{
			"available":   avail,
			"unavailable": unavail,
		},
		"limits": map[string]any{
			"max_line_bytes":   MaxLineBytes,
			"max_chunk_bytes":  MaxChunkBytes,
			"max_output_bytes": MaxOutputBytes,
			"max_timeout_ms":   MaxTimeoutMS,
		},
	})
}

func (s *session) handleCancel(f *inFrame) {
	var p struct {
		TargetID string `json:"target_id"`
		Mode     string `json:"mode"`
		GraceMS  int    `json:"grace_ms"`
	}
	if err := json.Unmarshal(f.Params, &p); err != nil || p.TargetID == "" {
		s.fw.respondError(f.ID, newError(ErrBadRequest, "cancel requires target_id", nil))
		return
	}
	t := s.lookup(p.TargetID)
	if t == nil {
		// 目标已经结束是常态（宿主发 cancel 与任务自然结束天生存在竞态），
		// 因此这不是错误，回 accepted=false 让宿主知道无事可做即可。
		s.fw.respondResult(f.ID, map[string]any{"accepted": false, "target_id": p.TargetID,
			"reason": "target not running"})
		return
	}
	// 先落 reason 再 cancel。顺序颠倒的话执行侧可能在 reason 写入前就读到空值，
	// 于是一次主动取消被上报成超时。
	t.reason.Store("canceled")
	s.fw.respondResult(f.ID, map[string]any{"accepted": true, "target_id": p.TargetID})
	t.cancel()
}

func (s *session) handleExec(f *inFrame) {
	var p execParams
	if err := json.Unmarshal(f.Params, &p); err != nil {
		s.fw.respondError(f.ID, newError(ErrBadRequest, "bad params: "+err.Error(), nil))
		return
	}
	if p.TimeoutMS <= 0 || p.TimeoutMS > MaxTimeoutMS {
		p.TimeoutMS = 30_000
	}

	argv := p.Argv
	if f.Method == "exec.python" {
		if strings.TrimSpace(p.Source) == "" {
			s.fw.respondError(f.ID, newError(ErrBadRequest, "exec.python requires source", nil))
			return
		}
		a, cleanup, err := pythonArgv(&p)
		if err != nil {
			s.fw.respondError(f.ID, newError(ErrInternal, "scratch file: "+err.Error(), nil))
			return
		}
		defer cleanup()
		argv = a
	}

	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(p.TimeoutMS)*time.Millisecond)
	defer cancel()

	reason := &atomic.Value{}
	reason.Store("timeout")
	s.register(f.ID, &task{cancel: cancel, reason: reason})
	defer s.unregister(f.ID)

	seq := &seqCounter{}
	oc, rerr := runExec(ctx, f.ID, s.fw, seq, &p, argv, reason)
	if rerr != nil {
		s.fw.respondError(f.ID, rerr)
		return
	}
	s.fw.respondResult(f.ID, oc)
}
