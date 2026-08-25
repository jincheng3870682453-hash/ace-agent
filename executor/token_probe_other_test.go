//go:build !windows

package main

// 非 Windows 平台没有令牌这个概念，返回 -1 让相关测试自行跳过。
func probeTokenPrivilegeCount() int { return -1 }
