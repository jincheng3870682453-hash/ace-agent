package main

// executor_test.go —— 协议与执行语义的回归测试。
//
// 子进程用的是**测试二进制自己**（TestMain 里通过 ACE_TEST_HELPER 分流），
// 好处是不依赖机器上有没有 python / bash / cmd 内建，测试在任何平台都能跑；
// 坏处是要小心 helper 分支必须在 m.Run 之前 return，否则会递归跑整个测试集。

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if os.Getenv("ACE_TEST_HELPER") == "1" {
		helperMain()
		return
	}
	os.Exit(m.Run())
}

func helperMain() {
	switch os.Getenv("ACE_HELPER_MODE") {
	case "echo":
		fmt.Print(os.Getenv("ACE_HELPER_TEXT"))
	case "echo_err":
		fmt.Fprint(os.Stderr, os.Getenv("ACE_HELPER_TEXT"))
	case "exit7":
		os.Exit(7)
	case "sleep":
		time.Sleep(60 * time.Second)
	case "spew":
		chunk := strings.Repeat("x", 4096)
		for i := 0; i < 50; i++ {
			fmt.Print(chunk)
		}
	case "dump_env":
		// 只打印我们关心的两个键，避免把真实环境写进测试输出。
		fmt.Printf("PATH_SET=%v;SECRET=%q\n",
			os.Getenv("PATH") != "", os.Getenv("ACE_TEST_SECRET"))
	case "token_privs":
		// 报出自己令牌里的特权条数，供受限令牌测试和父进程对比。
		fmt.Printf("PRIVS=%d", probeTokenPrivilegeCount())
	}
	os.Exit(0)
}

// ---- 测试脚手架 ----

type harness struct {
	buf *bytes.Buffer
	s   *session
	wg  sync.WaitGroup
}

func newHarness() *harness {
	buf := &bytes.Buffer{}
	return &harness{buf: buf, s: newSession(newFrameWriter(buf))}
}

func (h *harness) req(t *testing.T, id, method string, params any) {
	t.Helper()
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	h.s.handle(&inFrame{V: 1, Type: "req", ID: id, Method: method, Params: raw}, &h.wg)
}

func (h *harness) init(t *testing.T) {
	t.Helper()
	h.req(t, "init-1", "initialize", map[string]any{"protocol_versions": []int{1}})
	h.wg.Wait()
	if f := h.frame(t, "init-1", "resp"); f.Error != nil {
		t.Fatalf("initialize failed: %+v", f.Error)
	}
}

func (h *harness) frames(t *testing.T) []outFrame {
	t.Helper()
	var out []outFrame
	for _, line := range strings.Split(strings.TrimSpace(h.buf.String()), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var f outFrame
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			t.Fatalf("unparsable frame %q: %v", line, err)
		}
		out = append(out, f)
	}
	return out
}

func (h *harness) frame(t *testing.T, id, typ string) outFrame {
	t.Helper()
	for _, f := range h.frames(t) {
		if f.ID == id && f.Type == typ {
			return f
		}
	}
	t.Fatalf("no %s frame for id=%s in:\n%s", typ, id, h.buf.String())
	return outFrame{}
}

// resultMap 把 resp.result 转回 map。session 写出的是具体结构体，
// 但测试侧统一按 map 读，避免为断言再维护一份镜像结构。
func (h *harness) resultMap(t *testing.T, id string) map[string]any {
	t.Helper()
	f := h.frame(t, id, "resp")
	if f.Error != nil {
		t.Fatalf("expected result for %s, got error %+v", id, f.Error)
	}
	raw, _ := json.Marshal(f.Result)
	m := map[string]any{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("result not an object: %v", err)
	}
	return m
}

func helperParams(mode string, extra map[string]string) map[string]any {
	set := map[string]string{"ACE_TEST_HELPER": "1", "ACE_HELPER_MODE": mode}
	for k, v := range extra {
		set[k] = v
	}
	return map[string]any{
		"argv":       []string{os.Args[0]},
		"timeout_ms": 20000,
		"stream":     false,
		"env_policy": map[string]any{"mode": "allowlist", "set": set},
		"sandbox":    map[string]any{"tier": tierProcess},
	}
}

func decodeB64(t *testing.T, m map[string]any, key string) string {
	t.Helper()
	s, _ := m[key].(string)
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("%s is not valid base64: %v", key, err)
	}
	return string(b)
}

// ---- 协议关口 ----

func TestInitializeMustComeFirst(t *testing.T) {
	h := newHarness()
	h.req(t, "x1", "exec.command", helperParams("echo", nil))
	h.wg.Wait()
	f := h.frame(t, "x1", "resp")
	if f.Error == nil || f.Error.Code != ErrNotInitialized {
		t.Fatalf("want %s, got %+v", ErrNotInitialized, f.Error)
	}
}

func TestInitializeAdvertisesSandboxInventory(t *testing.T) {
	h := newHarness()
	h.init(t)
	m := h.resultMap(t, "init-1")
	sb, ok := m["sandbox"].(map[string]any)
	if !ok {
		t.Fatalf("no sandbox block: %v", m)
	}
	avail, _ := sb["available"].([]any)
	if len(avail) == 0 || avail[0] != tierProcess {
		t.Fatalf("tier0 must always be available, got %v", avail)
	}
	// Docker 档位没实现执行路径，必须出现在 unavailable 里。声明可用却跑不了
	// 会让宿主误以为拿到了强隔离，这条断言就是防这个。
	unavail, _ := sb["unavailable"].(map[string]any)
	if _, ok := unavail[tierDocker]; !ok {
		t.Fatalf("tier2_docker must be reported unavailable, got %v", unavail)
	}
}

func TestDuplicateIDRejected(t *testing.T) {
	h := newHarness()
	h.init(t)
	h.req(t, "dup", "exec.command", helperParams("echo", nil))
	h.wg.Wait()
	h.req(t, "dup", "exec.command", helperParams("echo", nil))
	h.wg.Wait()
	var got string
	for _, f := range h.frames(t) {
		if f.ID == "dup" && f.Error != nil {
			got = f.Error.Code
		}
	}
	if got != ErrDuplicateID {
		t.Fatalf("want %s, got %q", ErrDuplicateID, got)
	}
}

func TestUnknownMethod(t *testing.T) {
	h := newHarness()
	h.init(t)
	h.req(t, "u1", "exec.telepathy", map[string]any{})
	h.wg.Wait()
	f := h.frame(t, "u1", "resp")
	if f.Error == nil || f.Error.Code != ErrUnknownMethod {
		t.Fatalf("want %s, got %+v", ErrUnknownMethod, f.Error)
	}
}

// ---- 执行语义 ----

func TestExecCapturesStdoutAndExitCode(t *testing.T) {
	h := newHarness()
	h.init(t)
	p := helperParams("echo", map[string]string{"ACE_HELPER_TEXT": "hello-executor"})
	h.req(t, "e1", "exec.command", p)
	h.wg.Wait()
	m := h.resultMap(t, "e1")
	if m["exit_code"].(float64) != 0 {
		t.Fatalf("exit_code = %v", m["exit_code"])
	}
	if got := decodeB64(t, m, "stdout_b64"); got != "hello-executor" {
		t.Fatalf("stdout = %q", got)
	}
}

func TestExecPropagatesNonZeroExit(t *testing.T) {
	h := newHarness()
	h.init(t)
	h.req(t, "e2", "exec.command", helperParams("exit7", nil))
	h.wg.Wait()
	m := h.resultMap(t, "e2")
	if m["exit_code"].(float64) != 7 {
		t.Fatalf("exit_code = %v, want 7", m["exit_code"])
	}
}

func TestExecSpawnFailureIsNotAPanic(t *testing.T) {
	h := newHarness()
	h.init(t)
	p := helperParams("echo", nil)
	p["argv"] = []string{"definitely-not-a-real-binary-9f3a"}
	h.req(t, "e3", "exec.command", p)
	h.wg.Wait()
	f := h.frame(t, "e3", "resp")
	if f.Error == nil || f.Error.Code != ErrSpawnFailed {
		t.Fatalf("want %s, got %+v", ErrSpawnFailed, f.Error)
	}
}

func TestTimeoutKillsAndReportsTimeout(t *testing.T) {
	h := newHarness()
	h.init(t)
	p := helperParams("sleep", nil)
	p["timeout_ms"] = 300
	h.req(t, "t1", "exec.command", p)
	h.wg.Wait()
	f := h.frame(t, "t1", "resp")
	if f.Error == nil || f.Error.Code != ErrTimeout {
		t.Fatalf("want %s, got %+v", ErrTimeout, f.Error)
	}
	if killed, _ := f.Error.Data["killed"].(bool); !killed {
		t.Fatalf("timeout must report killed=true, got %v", f.Error.Data)
	}
}

func TestCancelReportsCanceledNotTimeout(t *testing.T) {
	h := newHarness()
	h.init(t)
	p := helperParams("sleep", nil)
	p["timeout_ms"] = 30000
	h.req(t, "c1", "exec.command", p)

	// 等任务真正登记进 tasks 表再发 cancel。直接发会撞上"目标尚未注册"，
	// 那测的就是竞态而不是取消语义了。
	deadline := time.Now().Add(5 * time.Second)
	for h.s.lookup("c1") == nil {
		if time.Now().After(deadline) {
			t.Fatal("task c1 never registered")
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.req(t, "c2", "cancel", map[string]any{"target_id": "c1", "mode": "graceful"})
	h.wg.Wait()

	if m := h.resultMap(t, "c2"); m["accepted"] != true {
		t.Fatalf("cancel not accepted: %v", m)
	}
	f := h.frame(t, "c1", "resp")
	if f.Error == nil || f.Error.Code != ErrCanceled {
		t.Fatalf("want %s, got %+v", ErrCanceled, f.Error)
	}
}

func TestCancelUnknownTargetIsNotAnError(t *testing.T) {
	h := newHarness()
	h.init(t)
	h.req(t, "c9", "cancel", map[string]any{"target_id": "nope"})
	h.wg.Wait()
	m := h.resultMap(t, "c9")
	if m["accepted"] != false {
		t.Fatalf("want accepted=false for a finished target, got %v", m)
	}
}

func TestOutputTruncationDoesNotHang(t *testing.T) {
	h := newHarness()
	h.init(t)
	p := helperParams("spew", nil)
	p["limits"] = map[string]any{"max_output_bytes": 1000}
	p["timeout_ms"] = 10000
	h.req(t, "tr1", "exec.command", p)
	h.wg.Wait()
	m := h.resultMap(t, "tr1")
	if m["truncated"] != true {
		t.Fatalf("want truncated=true, got %v", m)
	}
	// 关键断言：超限后仍必须**正常结束**而不是被超时杀掉。
	// 如果超限后停止读管道，子进程会阻塞在 write 上直到超时，exit_code 就拿不到 0。
	if m["exit_code"].(float64) != 0 {
		t.Fatalf("exit_code = %v; 超限后应继续排空管道让子进程正常退出", m["exit_code"])
	}
	if got := len(decodeB64(t, m, "stdout_b64")); got != 1000 {
		t.Fatalf("captured %d bytes, want exactly the 1000-byte cap", got)
	}
}

func TestEnvAllowlistDropsUnlistedVariables(t *testing.T) {
	// 宿主环境里放一个"机密"，白名单没列它，就必须传不进子进程。
	t.Setenv("ACE_TEST_SECRET", "s3cr3t")
	h := newHarness()
	h.init(t)
	p := helperParams("dump_env", nil)
	p["env_policy"] = map[string]any{
		"mode":  "allowlist",
		"allow": []string{"PATH", "SystemRoot", "WINDIR", "COMSPEC", "TEMP", "TMP"},
		"set":   map[string]string{"ACE_TEST_HELPER": "1", "ACE_HELPER_MODE": "dump_env"},
	}
	// 这条用例故意把 allow 列表收窄到不含 SystemDrive，于是子进程里
	// `%SystemDrive%\ProgramData\...` 这类字面量路径展开不了、退化成相对路径，
	// Windows shell 层会就地造一棵 `%SystemDrive%` 垃圾目录。
	// 不给 cwd 的话那棵树就落在包目录里，跑一次测试污染一次工作区 —— 扔进 TempDir。
	p["cwd"] = t.TempDir()
	h.req(t, "env1", "exec.command", p)
	h.wg.Wait()
	out := decodeB64(t, h.resultMap(t, "env1"), "stdout_b64")
	if !strings.Contains(out, `SECRET=""`) {
		t.Fatalf("未列入白名单的环境变量泄漏到了子进程: %q", out)
	}
	if !strings.Contains(out, "PATH_SET=true") {
		t.Fatalf("白名单里的 PATH 应当保留: %q", out)
	}
}

func TestStreamingEventsAreOrderedAndTerminateBeforeResp(t *testing.T) {
	h := newHarness()
	h.init(t)
	p := helperParams("echo", map[string]string{"ACE_HELPER_TEXT": "streamed"})
	p["stream"] = true
	h.req(t, "s1", "exec.command", p)
	h.wg.Wait()

	var seqs []uint64
	sawResp := false
	for _, f := range h.frames(t) {
		if f.ID != "s1" {
			continue
		}
		switch f.Type {
		case "event":
			if sawResp {
				t.Fatal("resp 之后不允许再出现同 id 的 event（终态不变量）")
			}
			if f.Seq == nil {
				t.Fatal("event 必须带 seq")
			}
			seqs = append(seqs, *f.Seq)
		case "resp":
			sawResp = true
		}
	}
	if len(seqs) == 0 {
		t.Fatal("stream=true 至少应有 started 事件")
	}
	for i, v := range seqs {
		if v != uint64(i) {
			t.Fatalf("seq 必须从 0 起无空洞递增，得到 %v", seqs)
		}
	}
}

// ---- 双闸门与沙箱档位 ----

func TestForbiddenDecisionIsNeverExecuted(t *testing.T) {
	h := newHarness()
	h.init(t)
	p := helperParams("echo", map[string]string{"ACE_HELPER_TEXT": "should-not-run"})
	p["policy_decision"] = map[string]any{"decision": "forbidden", "rule_id": "test-rule"}
	h.req(t, "p1", "exec.command", p)
	h.wg.Wait()
	f := h.frame(t, "p1", "resp")
	if f.Error == nil || f.Error.Code != ErrPolicyDenied {
		t.Fatalf("want %s, got %+v", ErrPolicyDenied, f.Error)
	}
	if f.Error.Data["approvable"] != false {
		t.Fatalf("forbidden 不可通过审批解除，approvable 必须为 false: %v", f.Error.Data)
	}
}

func TestPromptWithoutApprovalIsDenied(t *testing.T) {
	h := newHarness()
	h.init(t)
	p := helperParams("echo", nil)
	p["policy_decision"] = map[string]any{"decision": "prompt", "rule_id": "r2", "approved": false}
	h.req(t, "p2", "exec.command", p)
	h.wg.Wait()
	f := h.frame(t, "p2", "resp")
	if f.Error == nil || f.Error.Code != ErrPolicyDenied {
		t.Fatalf("无人批准的 prompt 必须拒绝（失败方向朝安全），got %+v", f.Error)
	}
}

func TestPromptWithApprovalRuns(t *testing.T) {
	h := newHarness()
	h.init(t)
	p := helperParams("echo", map[string]string{"ACE_HELPER_TEXT": "approved"})
	p["policy_decision"] = map[string]any{"decision": "prompt", "rule_id": "r3", "approved": true}
	h.req(t, "p3", "exec.command", p)
	h.wg.Wait()
	if got := decodeB64(t, h.resultMap(t, "p3"), "stdout_b64"); got != "approved" {
		t.Fatalf("stdout = %q", got)
	}
}

func TestUnavailableTierFailsInsteadOfSilentlyDowngrading(t *testing.T) {
	h := newHarness()
	h.init(t)
	p := helperParams("echo", nil)
	p["sandbox"] = map[string]any{"tier": tierDocker, "allow_weaker_tier": false}
	h.req(t, "sb1", "exec.command", p)
	h.wg.Wait()
	f := h.frame(t, "sb1", "resp")
	if f.Error == nil || f.Error.Code != ErrSandboxUnavailable {
		t.Fatalf("want %s, got %+v", ErrSandboxUnavailable, f.Error)
	}
}

func TestAllowWeakerTierDowngradesAndSaysSo(t *testing.T) {
	h := newHarness()
	h.init(t)
	p := helperParams("echo", map[string]string{"ACE_HELPER_TEXT": "weak"})
	p["sandbox"] = map[string]any{"tier": tierDocker, "allow_weaker_tier": true}
	h.req(t, "sb2", "exec.command", p)
	h.wg.Wait()
	m := h.resultMap(t, "sb2")
	sa, _ := m["sandbox_applied"].(map[string]any)
	if sa["degraded"] != true || sa["degraded_reason"] == "" {
		t.Fatalf("降级必须如实上报且带原因: %v", sa)
	}
}

// TestUnenforceableBoundariesAreRejected 覆盖比"档位不可用"更隐蔽的一类问题：
// 请求里带了执行器**根本没实现**的边界字段。
//
// 这类字段以前是被静默忽略的 —— 反序列化进结构体，然后再没人读它。危害不在于
// 少了一层防护，而在于调用方写下 network_access:false 之后会以为子进程断网了，
// 并在这个假设上做别的决定（"反正它连不出去，那这条命令可以放行"）。
// 所以这里断言的是**报错**，而不是"忽略了也没事"。
func TestUnenforceableBoundariesAreRejected(t *testing.T) {
	cases := []struct {
		name    string
		sandbox map[string]any
	}{
		{"writable_roots", map[string]any{"tier": tierProcess, "writable_roots": []string{"C:\\tmp"}}},
		{"network_access", map[string]any{"tier": tierProcess, "network_access": false}},
		{"scratch_dir", map[string]any{"tier": tierProcess, "scratch_dir": "auto"}},
		{"policy", map[string]any{"tier": tierProcess, "policy": "read_only"}},
	}
	for i, c := range cases {
		h := newHarness()
		h.init(t)
		p := helperParams("echo", nil)
		p["sandbox"] = c.sandbox
		id := fmt.Sprintf("ue%d", i)
		h.req(t, id, "exec.command", p)
		h.wg.Wait()
		f := h.frame(t, id, "resp")
		if f.Error == nil || f.Error.Code != ErrSandboxUnavailable {
			t.Fatalf("%s: want %s, got %+v", c.name, ErrSandboxUnavailable, f.Error)
		}
		// 报错必须点出是哪个字段，否则宿主只知道"沙箱不可用"，改不动。
		if !strings.Contains(fmt.Sprint(f.Error.Data), c.name) {
			t.Fatalf("%s: 错误里没说清是哪个字段: %+v", c.name, f.Error.Data)
		}
	}
}

// TestNetworkAccessTrueIsNotRejected 是上一条的反面。
//
// network_access 用指针正是为了这条：值类型的 bool 零值就是 false，"没传"和
// "显式要求断网"会被判成同一件事，于是每一个不关心网络的请求都会被拒 ——
// 把一条诚实性修复变成一道功能墙。
func TestNetworkAccessTrueIsNotRejected(t *testing.T) {
	h := newHarness()
	h.init(t)
	p := helperParams("echo", map[string]string{"ACE_HELPER_TEXT": "net-ok"})
	p["sandbox"] = map[string]any{"tier": tierProcess, "network_access": true}
	h.req(t, "net1", "exec.command", p)
	h.wg.Wait()
	m := h.resultMap(t, "net1")
	if got := decodeB64(t, m, "stdout_b64"); got != "net-ok" {
		t.Fatalf("network_access=true 不该被拒，stdout = %q", got)
	}
}

// TestIntegrityLevelIsReported 固化 debugger 的实测结论：
// LUA_TOKEN 给到的是 **Medium**，不是 Low。
//
// 为什么值得一条断言：`restricted_token=true` 很容易被读成"降到了最低档"，
// 而 ADR-002 待实测假设第 1 项（Low IL 下 python/git/pip 还能不能干活）
// 至今没被触发，原因就是这里根本没降到 Low。把等级报出来并断言它非空，
// 是防止未来有人在"以为是 Low"的前提下省掉别的防护。
func TestIntegrityLevelIsReported(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("完整性等级是 Windows 概念")
	}
	h := newHarness()
	h.init(t)
	p := helperParams("echo", map[string]string{"ACE_HELPER_TEXT": "il"})
	p["sandbox"] = map[string]any{"tier": tierJobObject, "allow_weaker_tier": false}
	h.req(t, "il1", "exec.command", p)
	h.wg.Wait()
	m := h.resultMap(t, "il1")
	sa, _ := m["sandbox_applied"].(map[string]any)
	il, _ := sa["integrity_level"].(string)
	if il == "" {
		t.Fatalf("sandbox_applied 必须带 integrity_level: %v", sa)
	}
	if strings.HasPrefix(il, "unavailable") {
		t.Fatalf("本机查不到完整性等级，这本身是个问题: %s", il)
	}
	// 形如 "medium (S-1-16-8192)"：既要人能读，也要保留原始 SID 供排查。
	if !strings.Contains(il, "(S-1-16-") {
		t.Fatalf("integrity_level 应带原始 SID: %q", il)
	}
	if rt, _ := sa["restricted_token"].(bool); rt && strings.HasPrefix(il, "low") {
		t.Fatalf("意外降到了 Low IL —— 若真如此，ADR-002 待实测假设 1 必须重新评估: %q", il)
	}
	t.Logf("受限令牌下子进程的完整性等级 = %s", il)
}

func TestJobObjectTierActuallyRuns(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Job Object 是 Windows 专属原语")
	}
	h := newHarness()
	h.init(t)
	p := helperParams("echo", map[string]string{"ACE_HELPER_TEXT": "in-job"})
	p["sandbox"] = map[string]any{"tier": tierJobObject, "allow_weaker_tier": false}
	p["limits"] = map[string]any{"max_child_processes": 8, "max_memory_bytes": 512 << 20}
	h.req(t, "j1", "exec.command", p)
	h.wg.Wait()
	m := h.resultMap(t, "j1")
	// 这条断言同时覆盖了挂起态启动 + AssignProcessToJobObject + NtResumeProcess 三步：
	// 任何一步坏了，进程要么永久挂起（超时）要么起不来（E_SPAWN_FAILED），拿不到 stdout。
	if got := decodeB64(t, m, "stdout_b64"); got != "in-job" {
		t.Fatalf("Job 内进程未能正常运行完，stdout = %q", got)
	}
	sa, _ := m["sandbox_applied"].(map[string]any)
	if sa["job_object"] != true || sa["tier"] != tierJobObject {
		t.Fatalf("sandbox_applied 未如实反映 Job Object: %v", sa)
	}
	// 受限令牌：要么真的用上了（true），要么必须说清为什么没用上。
	// 只报 false 而不给理由，等于让宿主猜"平台不支持"还是"这次失败了"。
	rt, ok := sa["restricted_token"].(bool)
	if !ok {
		t.Fatalf("sandbox_applied 缺 restricted_token: %v", sa)
	}
	if !rt {
		if sa["restricted_token_reason"] == nil || sa["restricted_token_reason"] == "" {
			t.Fatalf("restricted_token 为 false 时必须给出理由: %v", sa)
		}
		t.Logf("本机未能应用受限令牌，理由: %v", sa["restricted_token_reason"])
	}
}

// TestRestrictedTokenIsCreatable 单独验证 ADR-002 三阶段的前置条件：
// 非管理员下能否从自身令牌派生受限令牌。这条不经过完整请求链路，
// 失败时能直接指认是 Win32 调用的问题，而不用在协议层排查。
func TestRestrictedTokenIsCreatable(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("受限令牌是 Windows 专属原语")
	}
	c, _ := newJobConfinement(execLimits{})
	defer c.release()
	sa := c.applied()
	if !sa.RestrictedToken {
		// 不 Fatal：这台机器的策略可能确实不允许，但必须留下可行动的记录。
		t.Skipf("本机无法创建受限令牌，理由: %s", sa.RestrictedTokenReason)
	}
	if sa.RestrictedTokenReason != "" {
		t.Fatalf("成功时不该带失败理由: %q", sa.RestrictedTokenReason)
	}
}

// TestRestrictedTokenChildStillRuns 是这项改动真正的风险点：
// 令牌降权后子进程可能连自己的 exe 都读不到、或拿不到窗口站，于是根本起不来。
// 必须验证"加了身份边界之后功能没坏"，否则这层保护会以"命令莫名失败"的形式反噬。
func TestRestrictedTokenChildStillRuns(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("受限令牌是 Windows 专属原语")
	}
	h := newHarness()
	h.init(t)
	p := helperParams("echo", map[string]string{"ACE_HELPER_TEXT": "restricted-ok"})
	p["sandbox"] = map[string]any{"tier": tierJobObject, "allow_weaker_tier": false}
	h.req(t, "rt1", "exec.command", p)
	h.wg.Wait()
	m := h.resultMap(t, "rt1")
	if got := decodeB64(t, m, "stdout_b64"); got != "restricted-ok" {
		t.Fatalf("受限令牌下子进程未能正常跑完，stdout = %q，完整结果 %v", got, m)
	}
	if ec, _ := m["exit_code"].(float64); ec != 0 {
		t.Fatalf("受限令牌下退出码非 0: %v", m)
	}
}

// TestRestrictedTokenActuallyDropsPrivileges 是这一层的**有效性**证明。
//
// 前面两个测试只说明"令牌造出来了"和"进程还能跑"，都不能说明特权真被摘掉了。
// 如果 DISABLE_MAX_PRIVILEGE 因为某种原因没生效，前两个测试照样全绿，
// 而我们会以为拿到了身份边界 —— 这正是最危险的那种假通过。
func TestRestrictedTokenActuallyDropsPrivileges(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("受限令牌是 Windows 专属原语")
	}
	parent := probeTokenPrivilegeCount()
	if parent < 0 {
		t.Skip("无法读取父进程令牌特权")
	}

	h := newHarness()
	h.init(t)

	// Tier-0：不带受限令牌，作为对照组。
	p0 := helperParams("token_privs", nil)
	h.req(t, "tp0", "exec.command", p0)
	h.wg.Wait()
	base := decodeB64(t, h.resultMap(t, "tp0"), "stdout_b64")

	// Tier-1：带受限令牌。
	h2 := newHarness()
	h2.init(t)
	p1 := helperParams("token_privs", nil)
	p1["sandbox"] = map[string]any{"tier": tierJobObject, "allow_weaker_tier": false}
	h2.req(t, "tp1", "exec.command", p1)
	h2.wg.Wait()
	m1 := h2.resultMap(t, "tp1")
	sa, _ := m1["sandbox_applied"].(map[string]any)
	if sa["restricted_token"] != true {
		t.Skipf("本机未应用受限令牌，无法验证特权削减: %v", sa["restricted_token_reason"])
	}
	restricted := decodeB64(t, m1, "stdout_b64")

	var baseN, restN int
	if _, err := fmt.Sscanf(base, "PRIVS=%d", &baseN); err != nil {
		t.Fatalf("对照组输出无法解析: %q", base)
	}
	if _, err := fmt.Sscanf(restricted, "PRIVS=%d", &restN); err != nil {
		t.Fatalf("受限组输出无法解析: %q", restricted)
	}
	if restN >= baseN {
		t.Fatalf("受限令牌没有真的削减特权：tier0=%d tier1=%d", baseN, restN)
	}
	// DISABLE_MAX_PRIVILEGE 的语义是只留 SeChangeNotifyPrivilege。
	if restN != 1 {
		t.Fatalf("受限令牌应只剩 1 项特权（SeChangeNotify），实际 %d", restN)
	}
	t.Logf("特权数 tier0=%d → tier1=%d", baseN, restN)
}

func TestJobObjectTimeoutUsesTreeTermination(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Job Object 是 Windows 专属原语")
	}
	h := newHarness()
	h.init(t)
	p := helperParams("sleep", nil)
	p["timeout_ms"] = 300
	p["sandbox"] = map[string]any{"tier": tierJobObject}
	h.req(t, "j2", "exec.command", p)
	h.wg.Wait()
	f := h.frame(t, "j2", "resp")
	if f.Error == nil || f.Error.Code != ErrTimeout {
		t.Fatalf("want %s, got %+v", ErrTimeout, f.Error)
	}
	// 走 Job 档位时终止必须是整树回收，退回单进程 Kill 就会留下孙进程孤儿。
	if f.Error.Data["kill_method"] != "TerminateJobObject" {
		t.Fatalf("kill_method = %v，Tier-1 下应为 TerminateJobObject", f.Error.Data["kill_method"])
	}
}

// ---- 纯函数层 ----

func TestBuildEnvModes(t *testing.T) {
	t.Setenv("ACE_TEST_SECRET", "s3cr3t")
	cases := []struct {
		mode     string
		wantLeak bool
	}{
		{"none", false},
		{"allowlist", false},
		{"inherit", true},
	}
	for _, c := range cases {
		p := &execParams{EnvPolicy: envPolicy{Mode: c.mode}}
		joined := strings.Join(p.buildEnv(), "\n")
		leaked := strings.Contains(joined, "ACE_TEST_SECRET=")
		if leaked != c.wantLeak {
			t.Fatalf("mode=%s leaked=%v want %v", c.mode, leaked, c.wantLeak)
		}
	}
}

// 回归：默认白名单必须带上 SystemDrive / ProgramData。
// 少了它们，shell 层里 `%SystemDrive%\ProgramData\...` 这类字面量路径展开不了，
// 就退化成相对路径，子进程会在 cwd（用户的项目目录）里造出一棵名叫
// `%SystemDrive%` 的垃圾目录树 —— 这是真实踩过的，不是假想。
// 反面同样要断言：APPDATA / LOCALAPPDATA 是用户可写的状态目录，不许默认放行。
func TestDefaultEnvAllowCoversShellPathVarsButNotUserState(t *testing.T) {
	have := map[string]bool{}
	for _, k := range defaultEnvAllow {
		have[strings.ToUpper(k)] = true
	}
	for _, want := range []string{"SYSTEMDRIVE", "PROGRAMDATA"} {
		if !have[want] {
			t.Fatalf("默认白名单缺少 %s，子进程会往 cwd 里拉垃圾目录", want)
		}
	}
	for _, deny := range []string{"APPDATA", "LOCALAPPDATA"} {
		if have[deny] {
			t.Fatalf("默认白名单不该放行 %s：等于白送一块用户可写的落脚点", deny)
		}
	}
}

func TestPythonArgvKeepsSourceOutOfCommandLine(t *testing.T) {
	p := &execParams{Source: "print(1)", Filename: "../../evil"}
	argv, cleanup, err := pythonArgv(p)
	if err != nil {
		t.Fatalf("pythonArgv: %v", err)
	}
	defer cleanup()
	if len(argv) != 4 || argv[1] != "-I" || argv[2] != "-B" {
		t.Fatalf("argv = %v; 必须带 -I -B 隔离标志", argv)
	}
	// 路径穿越必须被 filepath.Base 掐掉，否则 filename 能把文件写到工作区外。
	if strings.Contains(argv[3], "..") {
		t.Fatalf("filename 路径穿越未被清除: %v", argv[3])
	}
	for _, a := range argv {
		if strings.Contains(a, "print(1)") {
			t.Fatalf("源码出现在了命令行里: %v", argv)
		}
	}
	if b, err := os.ReadFile(argv[3]); err != nil || string(b) != "print(1)" {
		t.Fatalf("scratch 文件内容不对: %q %v", b, err)
	}
}

func TestRunExecRejectsEmptyArgv(t *testing.T) {
	fw := newFrameWriter(&bytes.Buffer{})
	_, e := runExec(context.Background(), "z", fw, &seqCounter{}, &execParams{}, nil, nil)
	if e == nil || e.Code != ErrBadRequest {
		t.Fatalf("want %s, got %+v", ErrBadRequest, e)
	}
}

// reapAfterKill 的三条路径。真实触发条件（孙子进程攥着继承来的 stdout 句柄导致
// EOF 永不到来）在测试里造不稳定，所以把等待逻辑拆成纯函数单测：这里验的是
// "放弃等待"这个能力本身存在，而不是它在哪个平台上会被触发。
func TestReapAfterKillReturnsImmediatelyWhenWaitLands(t *testing.T) {
	done := make(chan error, 1)
	want := fmt.Errorf("exit status 1")
	done <- want
	start := time.Now()
	err, reaped := reapAfterKill(done, time.Second, func() {
		t.Fatal("Wait 已经返回了，不该再补刀")
	})
	if !reaped || err != want {
		t.Fatalf("reaped=%v err=%v", reaped, err)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatalf("不该等满 grace：%v", time.Since(start))
	}
}

func TestReapAfterKillHardKillsThenReaps(t *testing.T) {
	done := make(chan error, 1)
	// hardKill 由 reapAfterKill 在调用方 goroutine 里同步调用，所以这里数普通 int
	// 就够了，不需要 atomic。
	hits := 0
	err, reaped := reapAfterKill(done, 20*time.Millisecond, func() {
		hits++
		done <- nil
	})
	if !reaped || err != nil {
		t.Fatalf("reaped=%v err=%v", reaped, err)
	}
	if hits != 1 {
		t.Fatalf("hardKill 调用次数 = %d，应为 1", hits)
	}
}

func TestReapAfterKillGivesUpBounded(t *testing.T) {
	// Wait 永不返回 —— 这正是原来那行裸 `<-waitDone` 会永久挂住的场景。
	done := make(chan error)
	start := time.Now()
	_, reaped := reapAfterKill(done, 20*time.Millisecond, func() {})
	if reaped {
		t.Fatal("Wait 从未返回，reaped 必须是 false")
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("放弃等待用了 %v，说明没有上界", el)
	}
}
