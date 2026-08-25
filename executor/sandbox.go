package main

// sandbox.go —— 沙箱档位的平台无关部分。
//
// 档位不是编译期选型，而是协议字段：执行器在 initialize 里声明本机**实际可用**的集合，
// 宿主按需请求。请求了不可用的档位时默认报错而不是静默降级——静默降级会让宿主以为
// 自己在强隔离下运行，这比明确失败危险得多。

import (
	"os/exec"
	"runtime"
)

const (
	tierProcess   = "tier0_process"
	tierJobObject = "tier1_job_object"
	tierDocker    = "tier2_docker"
)

// sandboxApplied 回报**实际**施加了什么。degraded 为真表示请求的档位只部分生效
// （例如 Job Object 建成了但受限令牌因权限不足没能用上）。
type sandboxApplied struct {
	Tier            string `json:"tier"`
	JobObject       bool   `json:"job_object"`
	RestrictedToken bool   `json:"restricted_token"`
	// RestrictedToken 为 false 时说明原因。只报一个 false 等于告诉宿主"没有身份边界"，
	// 但不说是"平台根本没有这个原语"还是"这次创建失败了"——前者无解，
	// 后者可能是环境/策略问题，值得排查。
	RestrictedTokenReason string `json:"restricted_token_reason,omitempty"`
	// IntegrityLevel 是子进程令牌**实测**的完整性等级，形如 "medium (S-1-16-8192)"。
	//
	// 为什么单独报这一项：`restricted_token=true` 只说明"派生成功了"，不说明降到了哪一档，
	// 而两者的差别是实打实的攻击面差别 —— LUA_TOKEN 给到的是 Medium，不是 Low，
	// 因此子进程仍然能写用户 profile 下的绝大多数位置。ADR-002 的待实测假设第 1 项
	// （Low IL 下 python/git/pip 还能不能干活）到现在没被触发过，原因就在这里；
	// 把等级如实报出来，比让宿主从 "restricted_token=true" 推断出一个更强的结论要好。
	// 非 Windows 平台为空（完整性等级是 Windows 特有概念）。
	IntegrityLevel string `json:"integrity_level,omitempty"`
	Degraded       bool   `json:"degraded"`
	DegradedReason string `json:"degraded_reason,omitempty"`
}

// spawnRelaxer 是可选能力：约束器可以在"因为约束本身导致进程起不来"时主动放弃
// 一部分约束，让 run.go 重试一次。
//
// 为什么做成可选接口而不是加进 confinement：只有 Windows 的受限令牌需要这条退路，
// 强加进接口会让 Tier-0 和非 Windows 实现被迫写一个永远返回 false 的空方法。
//
// 实现方必须保证：返回 true 时约束已经**真的**放松了（否则重试会以同样的错误再失败一次），
// 并且 applied() 会如实反映放松后的状态。
type spawnRelaxer interface {
	relaxAfterSpawnFailure(err error) bool
}

// confinement 是"给一个子进程套上约束"的抽象。
//
// 生命周期严格是：prepare → cmd.Start() → afterStart → (运行) → release。
// afterStart 的实现**必须**保证进程处于可运行状态：Windows 实现会以挂起态启动
// 以消除"子进程在被纳入 Job 之前就 fork 出孙进程"的竞态，因此恢复运行的责任在它身上。
type confinement interface {
	prepare(cmd *exec.Cmd) error
	afterStart(cmd *exec.Cmd) error
	// killTree 整树终止，返回所用手段（写进协议的 kill_method）。
	killTree(cmd *exec.Cmd) (string, error)
	release()
	applied() sandboxApplied
}

// processConfinement 是 Tier-0：恒定启用，不依赖任何平台能力。
//
// 它提供的边界只有"独立进程 + 显式 cwd + 白名单环境变量 + 超时"，这几项都在 run.go 里。
// 这里唯一的职责是终止。注意 Kill 只杀直接子进程：Tier-0 下孙进程可能成为孤儿，
// 这是已知且被接受的局限，也正是 Tier-1 存在的理由。
type processConfinement struct{}

func (processConfinement) prepare(cmd *exec.Cmd) error    { return nil }
func (processConfinement) afterStart(cmd *exec.Cmd) error { return nil }

func (processConfinement) killTree(cmd *exec.Cmd) (string, error) {
	if cmd.Process == nil {
		return "none", nil
	}
	return "Process.Kill", cmd.Process.Kill()
}

func (processConfinement) release() {}

func (processConfinement) applied() sandboxApplied {
	return sandboxApplied{
		Tier:                  tierProcess,
		RestrictedTokenReason: "tier0 只做进程边界，不派生受限令牌",
		// 没有受限令牌时子进程继承执行器自己的令牌，所以子进程实际跑在哪一档
		// 完整性等级，问执行器自己就是答案。
		IntegrityLevel: selfIntegrityLevel(),
		Degraded:       false,
		DegradedReason: "",
	}
}

// sandboxInventory 报告本机可用与不可用的档位。unavailable 的 value 是**理由**，
// 宿主会把它原样展示给用户，所以理由必须具体到可行动。
func sandboxInventory() (available []string, unavailable map[string]string) {
	available = []string{tierProcess}
	unavailable = map[string]string{}

	if runtime.GOOS == "windows" {
		available = append(available, tierJobObject)
	} else {
		unavailable[tierJobObject] = "job objects are a Windows-only primitive"
	}

	// Docker 档位尚未实现执行路径。这里宁可报"未实现"也不报"可用"——
	// 声明了可用却跑不起来，宿主会以为拿到了强隔离。
	unavailable[tierDocker] = "not implemented in the Go executor yet"
	return available, unavailable
}

func tierAvailable(tier string) bool {
	avail, _ := sandboxInventory()
	for _, t := range avail {
		if t == tier {
			return true
		}
	}
	return false
}

// resolveConfinement 按请求档位构造约束器。
//
// 请求档位不可用时：allowWeaker 为真则降到 Tier-0 并在 applied 里标记 degraded，
// 否则返回 nil 让调用方回 E_SANDBOX_UNAVAILABLE。
func resolveConfinement(tier string, allowWeaker bool, lim execLimits) (confinement, string) {
	if tier == "" {
		tier = tierProcess
	}
	if tierAvailable(tier) {
		if tier == tierJobObject {
			return newJobConfinement(lim)
		}
		return processConfinement{}, ""
	}
	_, unavail := sandboxInventory()
	reason := unavail[tier]
	if reason == "" {
		reason = "unknown sandbox tier"
	}
	if !allowWeaker {
		return nil, reason
	}
	return degradedConfinement{reason: reason}, ""
}

// degradedConfinement 是显式降级后的 Tier-0：行为与 processConfinement 一致，
// 但在 applied 里把降级事实和原因带回宿主。
type degradedConfinement struct {
	processConfinement
	reason string
}

func (d degradedConfinement) applied() sandboxApplied {
	return sandboxApplied{
		Tier:           tierProcess,
		IntegrityLevel: selfIntegrityLevel(),
		Degraded:       true,
		DegradedReason: d.reason,
	}
}
