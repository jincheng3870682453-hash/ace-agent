//go:build windows

package main

// token_probe_windows_test.go —— 测试专用：读自己令牌里的特权数量。
//
// 为什么放在 _test.go 而不是生产文件里：执行器本身不需要这个能力，
// 它只用来**证明**受限令牌真的生效了。放进生产文件等于给正式二进制
// 塞一个没人调用的 Win32 探针。
//
// 为什么数 PrivilegeCount 而不是检查某个具体特权：DISABLE_MAX_PRIVILEGE 的语义是
// "删除除 SeChangeNotifyPrivilege 之外的全部特权"，所以受限令牌的计数应当是 1。
// 直接对比父子两个数字，比逐个点名特权更不容易随 Windows 版本漂移。

import (
	"syscall"
	"unsafe"
)

const (
	_TokenPrivileges = 3
	_currentProcess  = ^uintptr(0) // GetCurrentProcess() 的伪句柄
)

// probeTokenPrivilegeCount 返回当前进程令牌里的特权条数，失败返回 -1。
func probeTokenPrivilegeCount() int {
	var tok syscall.Token
	if err := syscall.OpenProcessToken(
		syscall.Handle(_currentProcess), syscall.TOKEN_QUERY, &tok); err != nil {
		return -1
	}
	defer syscall.CloseHandle(syscall.Handle(tok))

	// 先问长度：特权表长度取决于账户，不能猜一个固定缓冲区。
	var need uint32
	err := syscall.GetTokenInformation(tok, _TokenPrivileges, nil, 0, &need)
	if need == 0 {
		return -1
	}
	buf := make([]byte, need)
	if err = syscall.GetTokenInformation(
		tok, _TokenPrivileges, &buf[0], need, &need); err != nil {
		return -1
	}
	// TOKEN_PRIVILEGES 的头 4 字节就是 PrivilegeCount。
	return int(*(*uint32)(unsafe.Pointer(&buf[0])))
}
