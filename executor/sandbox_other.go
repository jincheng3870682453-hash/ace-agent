//go:build !windows

package main

// sandbox_other.go —— 非 Windows 平台的 Tier-1 占位。
//
// sandboxInventory 已经把 tier1_job_object 列入 unavailable，正常路径不会走到这里；
// 保留这个实现只是为了让 resolveConfinement 在所有平台都能编译。
// Linux/macOS 的强隔离（seccomp / seatbelt）按 ADR-002 属于后续档位，不在此文件冒充。

func newJobConfinement(lim execLimits) (confinement, string) {
	return nil, "job objects are a Windows-only primitive"
}

// selfIntegrityLevel 在非 Windows 上返回空串。
//
// 不返回 "n/a" 之类的占位文本：`integrity_level` 是 omitempty 字段，空串等于
// "这个平台没有这个概念，别拿它做判断"，而一个占位字符串会让宿主的日志和告警
// 规则去解析一个没有意义的值。
func selfIntegrityLevel() string { return "" }
