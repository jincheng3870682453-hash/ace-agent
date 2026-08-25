//go:build windows

package main

// sandbox_windows.go —— Tier-1：Job Object。
//
// 为什么用 syscall.NewLazyDLL 而不是 golang.org/x/sys/windows：执行器要能在任何一台
// 只装了 Go 工具链的机器上 `go build` 出来，不下载任何模块。Job Object 只需要 5 个
// kernel32 导出函数，手写声明的成本远低于引入依赖后 vendor / 校验和 / 离线构建的成本。
//
// 这一档提供的是**资源与进程树**边界，不是文件系统边界：
//   - ActiveProcessLimit  挡住 fork bomb
//   - ProcessMemoryLimit  挡住内存耗尽
//   - KILL_ON_JOB_CLOSE   保证句柄一关整树回收，不留孤儿
//   - 禁止 breakaway      保证子孙进程无法脱离 Job
// 想要文件系统边界得上 Tier-2（容器），这一点在 ADR-002 里写明了，不要指望这里。

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	ntdll    = syscall.NewLazyDLL("ntdll.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	procCreateJobObjectW         = kernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObject  = kernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJobObject = kernel32.NewProc("AssignProcessToJobObject")
	procTerminateJobObject       = kernel32.NewProc("TerminateJobObject")
	procOpenProcess              = kernel32.NewProc("OpenProcess")

	// NtResumeProcess 只需要进程句柄就能恢复整个进程，不必枚举线程。
	// os/exec 不暴露子进程主线程句柄，走 ResumeThread 那条路要么改标准库要么枚举系统线程；
	// 这个函数虽然未正式文档化，但从 NT 4 起接口稳定，是这里唯一低成本的解法。
	procNtResumeProcess = ntdll.NewProc("NtResumeProcess")

	procCreateRestrictedToken = advapi32.NewProc("CreateRestrictedToken")
)

const (
	_JobObjectExtendedLimitInformation = 9

	_JOB_OBJECT_LIMIT_ACTIVE_PROCESS             = 0x00000008
	_JOB_OBJECT_LIMIT_PROCESS_MEMORY             = 0x00000100
	_JOB_OBJECT_LIMIT_JOB_MEMORY                 = 0x00000200
	_JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400
	_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE          = 0x00002000

	_CREATE_SUSPENDED         = 0x00000004
	_CREATE_NEW_PROCESS_GROUP = 0x00000200

	_PROCESS_TERMINATE      = 0x0001
	_PROCESS_SET_QUOTA      = 0x0100
	_PROCESS_SUSPEND_RESUME = 0x0800
	_PROCESS_QUERY_LIMITED  = 0x1000

	// CreateRestrictedToken 的标志位。
	//
	// DISABLE_MAX_PRIVILEGE：删掉除 SeChangeNotifyPrivilege 之外的全部特权。
	//   这是这里最主要的收益 —— 被执行的命令再也拿不到 SeDebugPrivilege（附加到任意
	//   进程读内存）、SeBackupPrivilege（绕过文件 DACL 读任何文件）这类"绕过 ACL"的能力。
	// LUA_TOKEN：把令牌降为受限用户令牌，管理员组变成"仅用于拒绝"，完整性等级降到 Medium。
	//   宿主以管理员身份运行时，这一位是从"子进程也是管理员"变成"子进程不是"的关键。
	//
	// 刻意**不用** SidsToRestrict（restricting SIDs）：那会让子进程访问任何文件都要
	// 同时通过两次 ACL 检查，工作目录立刻变成不可写。这个执行器要跑 pytest、写编译产物，
	// 加上就等于把功能砍了。身份边界到"去特权 + 降完整性"为止，文件系统边界留给 Tier-2。
	_DISABLE_MAX_PRIVILEGE = 0x1
	_LUA_TOKEN             = 0x4

	// TokenIntegrityLevel（TOKEN_INFORMATION_CLASS = 25）。
	_TokenIntegrityLevel = 25
)

// integrityLevelName 把完整性等级 RID 翻成人能读的名字。
//
// 只认已定义的六档，未知值原样回报十六进制而不猜 —— 报错的 RID 本身就是排查线索。
func integrityLevelName(rid uint32) string {
	switch rid {
	case 0x0000:
		return "untrusted"
	case 0x1000:
		return "low"
	case 0x2000:
		return "medium"
	case 0x2100:
		return "medium-plus"
	case 0x3000:
		return "high"
	case 0x4000:
		return "system"
	default:
		return fmt.Sprintf("unknown(0x%x)", rid)
	}
}

// tokenIntegrityLevel 查一个令牌**实测**的完整性等级。
//
// 为什么用 sid.String() 解析而不是读 SubAuthority 数组：syscall 包没有暴露
// SubAuthority 访问器（那在 golang.org/x/sys/windows 里），而这个执行器刻意零依赖。
// SID 字符串形式 "S-1-16-8192" 的最后一段就是 RID，按 '-' 取尾段即可，
// 比手工对 SID 结构做指针算术安全得多。
func tokenIntegrityLevel(t syscall.Token) string {
	var size uint32
	// 第一次调用只为拿长度：TOKEN_MANDATORY_LABEL 尾随一个变长 SID，长度不固定。
	err := syscall.GetTokenInformation(t, _TokenIntegrityLevel, nil, 0, &size)
	if size == 0 {
		return fmt.Sprintf("unavailable: GetTokenInformation size query failed: %v", err)
	}
	buf := make([]byte, size)
	if err := syscall.GetTokenInformation(t, _TokenIntegrityLevel, &buf[0], size, &size); err != nil {
		return fmt.Sprintf("unavailable: GetTokenInformation failed: %v", err)
	}
	label := (*struct {
		Sid        *syscall.SID
		Attributes uint32
	})(unsafe.Pointer(&buf[0]))
	if label.Sid == nil {
		return "unavailable: mandatory label carries no SID"
	}
	s, err := label.Sid.String()
	if err != nil {
		return fmt.Sprintf("unavailable: SID string conversion failed: %v", err)
	}
	i := strings.LastIndexByte(s, '-')
	if i < 0 || i == len(s)-1 {
		return fmt.Sprintf("unavailable: unexpected SID form %q", s)
	}
	rid, err := strconv.ParseUint(s[i+1:], 10, 32)
	if err != nil {
		return fmt.Sprintf("unavailable: unexpected SID RID in %q", s)
	}
	return fmt.Sprintf("%s (%s)", integrityLevelName(uint32(rid)), s)
}

// selfIntegrityLevel 查执行器自己的完整性等级 —— 没有受限令牌时子进程继承的就是它。
func selfIntegrityLevel() string {
	var self syscall.Token
	err := syscall.OpenProcessToken(
		syscall.Handle(^uintptr(0)), syscall.TOKEN_QUERY, &self)
	if err != nil {
		return fmt.Sprintf("unavailable: OpenProcessToken failed: %v", err)
	}
	defer syscall.CloseHandle(syscall.Handle(self))
	return tokenIntegrityLevel(self)
}

type ioCounters struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

type jobBasicLimitInformation struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type jobExtendedLimitInformation struct {
	BasicLimitInformation jobBasicLimitInformation
	IoInfo                ioCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

type jobConfinement struct {
	handle   syscall.Handle
	lim      execLimits
	degraded bool
	reason   string

	// 受限令牌。创建失败时 token 为 0、tokenReason 说明原因，执行照常进行 ——
	// 少一层身份边界不等于不能跑，但必须如实上报，别让宿主以为有。
	token       syscall.Token
	tokenReason string
}

// newRestrictedToken 从当前进程令牌派生一个去特权、降完整性的主令牌。
//
// 为什么能在非管理员下成功：CreateProcessAsUser 通常需要 SeAssignPrimaryTokenPrivilege，
// 但当传入的令牌是**调用者自身令牌的受限版本**时，Windows 免除该要求。
// Chromium 的沙箱正是靠这条特例工作的，所以这里不需要提权。
func newRestrictedToken() (syscall.Token, string) {
	var self syscall.Token
	// TOKEN_DUPLICATE 是 CreateRestrictedToken 的必需权限；ASSIGN_PRIMARY 用于随后启动进程。
	err := syscall.OpenProcessToken(
		syscall.Handle(^uintptr(0)), // GetCurrentProcess() 的伪句柄 (HANDLE)-1
		syscall.TOKEN_DUPLICATE|syscall.TOKEN_QUERY|syscall.TOKEN_ASSIGN_PRIMARY,
		&self)
	if err != nil {
		return 0, fmt.Sprintf("OpenProcessToken failed: %v", err)
	}
	defer syscall.CloseHandle(syscall.Handle(self))

	var restricted syscall.Token
	r, _, e := procCreateRestrictedToken.Call(
		uintptr(self),
		uintptr(_DISABLE_MAX_PRIVILEGE|_LUA_TOKEN),
		0, 0, // DisableSidCount / SidsToDisable：LUA_TOKEN 已经处理了管理员组
		0, 0, // DeletePrivilegeCount / PrivilegesToDelete：DISABLE_MAX_PRIVILEGE 已覆盖
		0, 0, // RestrictedSidCount / SidsToRestrict：刻意留空，见上面常量处的说明
		uintptr(unsafe.Pointer(&restricted)),
	)
	if r == 0 {
		return 0, fmt.Sprintf("CreateRestrictedToken failed: %v", e)
	}
	return restricted, ""
}

// newJobConfinement 建 Job 并施加限额。
//
// 建不出来时不返回错误让整个请求失败，而是降级到 Tier-0 并把原因带回去：
// Job Object 在容器内或受策略限制的环境下可能不可用，此时"能跑但明确告知隔离更弱"
// 比"直接拒绝执行"更符合可用性，而宿主拿到 degraded=true 后可以自行决定是否放弃。
func newJobConfinement(lim execLimits) (confinement, string) {
	h, _, e := procCreateJobObjectW.Call(0, 0)
	if h == 0 {
		return degradedConfinement{reason: fmt.Sprintf("CreateJobObjectW failed: %v", e)}, ""
	}
	jc := &jobConfinement{handle: syscall.Handle(h), lim: lim}
	jc.token, jc.tokenReason = newRestrictedToken()

	info := jobExtendedLimitInformation{}
	info.BasicLimitInformation.LimitFlags =
		_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | _JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
	if lim.MaxChildProcesses > 0 {
		info.BasicLimitInformation.LimitFlags |= _JOB_OBJECT_LIMIT_ACTIVE_PROCESS
		info.BasicLimitInformation.ActiveProcessLimit = lim.MaxChildProcesses
	}
	if lim.MaxMemoryBytes > 0 {
		info.BasicLimitInformation.LimitFlags |=
			_JOB_OBJECT_LIMIT_PROCESS_MEMORY | _JOB_OBJECT_LIMIT_JOB_MEMORY
		info.ProcessMemoryLimit = uintptr(lim.MaxMemoryBytes)
		info.JobMemoryLimit = uintptr(lim.MaxMemoryBytes)
	}
	r, _, e := procSetInformationJobObject.Call(
		uintptr(jc.handle),
		_JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		unsafe.Sizeof(info),
	)
	if r == 0 {
		// 限额设不上的 Job 只剩"整树回收"这一项能力，配额形同虚设，必须如实标记降级。
		jc.degraded = true
		jc.reason = fmt.Sprintf("SetInformationJobObject failed: %v; only kill-on-close is in effect", e)
	}
	return jc, ""
}

// prepare 以挂起态启动子进程。
//
// 这是消除竞态的关键：如果让子进程正常启动再 AssignProcessToJobObject，
// 从 CreateProcess 返回到 Assign 生效之间存在一个窗口，子进程完全有时间 fork 出
// 孙进程，而那些孙进程不在 Job 里，杀不掉也限不住。挂起态启动把窗口压成零。
func (j *jobConfinement) prepare(cmd *exec.Cmd) error {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= _CREATE_SUSPENDED | _CREATE_NEW_PROCESS_GROUP
	if j.token != 0 {
		// os/exec 看到 Token 非 0 会改用 CreateProcessAsUser。这是唯一不改标准库
		// 就能让子进程带上受限令牌的路子。
		cmd.SysProcAttr.Token = j.token
	}
	return nil
}

func (j *jobConfinement) afterStart(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return fmt.Errorf("process not started")
	}
	access := uintptr(_PROCESS_TERMINATE | _PROCESS_SET_QUOTA | _PROCESS_SUSPEND_RESUME | _PROCESS_QUERY_LIMITED)
	ph, _, e := procOpenProcess.Call(access, 0, uintptr(cmd.Process.Pid))
	if ph == 0 {
		// 拿不到句柄就无法纳入 Job，也无法恢复运行。进程正挂着，必须杀掉，
		// 否则会留下一个永久挂起的僵尸进程占着 pid 和内存。
		_ = cmd.Process.Kill()
		return fmt.Errorf("OpenProcess failed: %v", e)
	}
	defer syscall.CloseHandle(syscall.Handle(ph))

	if r, _, e := procAssignProcessToJobObject.Call(uintptr(j.handle), ph); r == 0 {
		_ = cmd.Process.Kill()
		return fmt.Errorf("AssignProcessToJobObject failed: %v", e)
	}
	// 先纳入 Job 再恢复。顺序颠倒就等于没做挂起。
	if r, _, e := procNtResumeProcess.Call(ph); r != 0 {
		_ = cmd.Process.Kill()
		return fmt.Errorf("NtResumeProcess failed: NTSTATUS=0x%x (%v)", r, e)
	}
	return nil
}

// relaxAfterSpawnFailure 在进程因受限令牌起不来时放弃令牌，让 run.go 重试一次。
//
// 已实测的触发场景：Microsoft Store 版 python.exe 是"应用执行别名"（reparse point），
// 受限令牌解析不了它，CreateProcessAsUser 返回 ERROR_CANT_ACCESS_FILE。
//
// 只在**有令牌**的情况下返回 true —— 否则重试会用完全相同的参数再失败一次，
// 白白多花一次进程创建，还会把真正的错误（比如 argv[0] 不存在）掩盖成两次同样的失败。
func (j *jobConfinement) relaxAfterSpawnFailure(err error) bool {
	if j.token == 0 {
		return false
	}
	syscall.CloseHandle(syscall.Handle(j.token))
	j.token = 0
	j.tokenReason = fmt.Sprintf(
		"受限令牌下进程无法启动，已放弃令牌重试（Job Object 边界仍生效）: %v", err)
	// 这不算 degraded：Job Object 请求的资源与进程树边界一项没少，
	// 少的是本来就属于"尽力而为"的身份边界，由 restricted_token 字段单独表达。
	return true
}

func (j *jobConfinement) killTree(cmd *exec.Cmd) (string, error) {
	if r, _, e := procTerminateJobObject.Call(uintptr(j.handle), 1); r == 0 {
		// Job 级终止失败时退回单进程终止，至少别把请求挂死。
		if cmd.Process != nil {
			return "Process.Kill", cmd.Process.Kill()
		}
		return "TerminateJobObject", fmt.Errorf("TerminateJobObject failed: %v", e)
	}
	return "TerminateJobObject", nil
}

// release 关闭 Job 句柄。因为设了 KILL_ON_JOB_CLOSE，这一步同时是最后一道
// 孤儿进程兜底：即使前面所有 kill 路径都漏了，句柄关闭时内核会回收整棵树。
func (j *jobConfinement) release() {
	if j.handle != 0 {
		syscall.CloseHandle(j.handle)
		j.handle = 0
	}
	if j.token != 0 {
		syscall.CloseHandle(syscall.Handle(j.token))
		j.token = 0
	}
}

func (j *jobConfinement) applied() sandboxApplied {
	// 令牌已经放弃（或从未建成）时，子进程继承的是执行器自己的令牌，
	// 所以这里必须问 self 而不是回报一个"本来打算给它的"等级。
	il := selfIntegrityLevel()
	if j.token != 0 {
		il = tokenIntegrityLevel(j.token)
	}
	return sandboxApplied{
		Tier:                  tierJobObject,
		JobObject:             true,
		RestrictedToken:       j.token != 0,
		RestrictedTokenReason: j.tokenReason,
		IntegrityLevel:        il,
		Degraded:              j.degraded,
		DegradedReason:        j.reason,
	}
}
