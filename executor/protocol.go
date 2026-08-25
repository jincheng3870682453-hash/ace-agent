package main

// protocol.go —— ADR-002 NDJSON 协议的帧定义与写出端。
//
// 唯一的硬约束：stdout 只允许出现协议帧，一帧一行。任何日志、告警、调试信息一律走
// stderr。宿主按行解析 stdout，一旦混入非协议内容，整个会话不可恢复。

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
)

const (
	ProtocolVersion = 1

	// MaxLineBytes 单行帧上限。宿主与执行器必须用同一个值，否则长命令会在一侧静默截断。
	MaxLineBytes = 1 << 20 // 1 MiB
	// MaxChunkBytes 单个 output 事件携带的原始字节上限（base64 前）。
	MaxChunkBytes = 64 << 10
	// MaxOutputBytes 单次执行累计输出上限的**协议上限**，请求可以更小但不能更大。
	MaxOutputBytes = 5 << 20
	// MaxTimeoutMS 单次执行超时的协议上限。
	MaxTimeoutMS = 600_000
)

// 错误码。http_like 只是给宿主复用既有 ExecutionResult 状态码用的便利映射，
// 不代表这里有 HTTP 语义。
const (
	ErrNotInitialized     = "E_NOT_INITIALIZED"
	ErrAlreadyInitialized = "E_ALREADY_INITIALIZED"
	ErrBadRequest         = "E_BAD_REQUEST"
	ErrUnknownMethod      = "E_UNKNOWN_METHOD"
	ErrUnknownType        = "E_UNKNOWN_TYPE"
	ErrUnsupportedVersion = "E_UNSUPPORTED_VERSION"
	ErrDuplicateID        = "E_DUPLICATE_ID"
	ErrTimeout            = "E_TIMEOUT"
	ErrCanceled           = "E_CANCELED"
	ErrPolicyDenied       = "E_POLICY_DENIED"
	ErrSandboxUnavailable = "E_SANDBOX_UNAVAILABLE"
	ErrSpawnFailed        = "E_SPAWN_FAILED"
	ErrNotFound           = "E_NOT_FOUND"
	ErrInternal           = "E_INTERNAL"
)

var httpLikeByCode = map[string]string{
	ErrNotInitialized:     "409",
	ErrAlreadyInitialized: "409",
	ErrBadRequest:         "400",
	ErrUnknownMethod:      "400",
	ErrUnknownType:        "400",
	ErrUnsupportedVersion: "505",
	ErrDuplicateID:        "409",
	ErrTimeout:            "504",
	ErrCanceled:           "499",
	ErrPolicyDenied:       "403",
	ErrSandboxUnavailable: "501",
	ErrSpawnFailed:        "500",
	ErrNotFound:           "404",
	ErrInternal:           "500",
}

// inFrame 是宿主发来的帧。未知字段被 json 包自然忽略——这正是前向兼容要的行为。
type inFrame struct {
	V      int             `json:"v"`
	Type   string          `json:"type"`
	ID     string          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

type rpcError struct {
	Code     string         `json:"code"`
	HTTPLike string         `json:"http_like"`
	Message  string         `json:"message"`
	Data     map[string]any `json:"data,omitempty"`
}

func newError(code, message string, data map[string]any) *rpcError {
	h, ok := httpLikeByCode[code]
	if !ok {
		h = "500"
	}
	return &rpcError{Code: code, HTTPLike: h, Message: message, Data: data}
}

// outFrame 同时承载 resp 与 event。用一个结构体是为了让写出端只有一条路径，
// 从而只有一处需要保证"一帧一行且不交错"。
type outFrame struct {
	V      int       `json:"v"`
	Type   string    `json:"type"`
	ID     string    `json:"id"`
	Result any       `json:"result,omitempty"`
	Error  *rpcError `json:"error,omitempty"`
	Event  string    `json:"event,omitempty"`
	Seq    *uint64   `json:"seq,omitempty"`
	Data   any       `json:"data,omitempty"`
}

// frameWriter 串行化所有出站帧。
//
// 为什么必须加锁：exec 请求各自跑在自己的 goroutine 里并发产出 output 事件，
// 而 bufio.Writer 不是并发安全的。没有这把锁，两个任务的 JSON 会字节级交织，
// 宿主拿到的是永久损坏的流——这类 bug 只在高并发下偶发，极难复现。
type frameWriter struct {
	mu  sync.Mutex
	w   *bufio.Writer
	enc *json.Encoder
}

func newFrameWriter(w io.Writer) *frameWriter {
	bw := bufio.NewWriterSize(w, 64<<10)
	enc := json.NewEncoder(bw)
	// 关掉 HTML 转义：命令行里的 & < > 被转成 \u0026 只会让日志难读，且宿主无需 HTML 安全。
	enc.SetEscapeHTML(false)
	return &frameWriter{w: bw, enc: enc}
}

func (fw *frameWriter) send(f outFrame) {
	fw.sendSeq(f, nil)
}

// sendSeq 在**持锁期间**分配序号，然后写出。
//
// 为什么序号不能在锁外分配：stdout / stderr 两个 pump goroutine 并发发 output 事件，
// 若先各自取到 5、6 再去抢锁，写出顺序可能是 6、5 —— 宿主按序号检测丢帧，看到的是
// "跳变 + 回退"，于是把一次正常执行判成流损坏。分配与写出必须是同一个临界区，
// 序号才真正等于"这一帧在流里的位置"。
func (fw *frameWriter) sendSeq(f outFrame, seq *seqCounter) {
	f.V = ProtocolVersion
	fw.mu.Lock()
	defer fw.mu.Unlock()
	if seq != nil {
		f.Seq = seq.nextLocked()
	}
	// Encode 自带换行，正好是 NDJSON 的分隔符。
	if err := fw.enc.Encode(&f); err != nil {
		// stdout 写不出去意味着宿主已经不在了，此时唯一还能做的是喊一声 stderr。
		fmt.Fprintf(stderrLog, "frame encode failed: %v\n", err)
		return
	}
	// 必须每帧 flush。宿主是阻塞读行的，缓冲住不发就是死锁。
	if err := fw.w.Flush(); err != nil {
		fmt.Fprintf(stderrLog, "frame flush failed: %v\n", err)
	}
}

func (fw *frameWriter) respondResult(id string, result any) {
	fw.send(outFrame{Type: "resp", ID: id, Result: result})
}

func (fw *frameWriter) respondError(id string, e *rpcError) {
	fw.send(outFrame{Type: "resp", ID: id, Error: e})
}

// seqCounter 为单个 id 的事件流生成从 0 开始、无空洞的递增序号，宿主据此检测丢帧。
// nextLocked 只允许在 frameWriter 的锁内调用（见 sendSeq 的说明）。
type seqCounter struct {
	n uint64
}

func (s *seqCounter) nextLocked() *uint64 {
	v := atomic.AddUint64(&s.n, 1) - 1
	return &v
}

func (fw *frameWriter) emitEvent(id string, seq *seqCounter, name string, data any) {
	fw.sendSeq(outFrame{Type: "event", ID: id, Event: name, Data: data}, seq)
}
