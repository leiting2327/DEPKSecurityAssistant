//go:build windows

package main

import (
	"os/exec"
	"syscall"
	"unsafe"
)

var (
	modUser32   = syscall.NewLazyDLL("user32.dll")
	modKernel32 = syscall.NewLazyDLL("kernel32.dll")

	pCreateMutexW = modKernel32.NewProc("CreateMutexW")
	pCloseHandle = modKernel32.NewProc("CloseHandle")
	pGetLastError = modKernel32.NewProc("GetLastError")
	pMessageBoxW  = modUser32.NewProc("MessageBoxW")
)

const errorAlreadyExists = 183

var mutexHandle uintptr

func acquireMutex() bool {
	name, _ := syscall.UTF16PtrFromString("Local\\DEPKSecurityAssistant_Setup_216")
	h, _, _ := pCreateMutexW.Call(0, 0, uintptr(unsafe.Pointer(name)))
	if h == 0 {
		return true
	}
	mutexHandle = h
	errCode, _, _ := pGetLastError.Call()
	return errCode != errorAlreadyExists
}

func releaseMutex() {
	if mutexHandle != 0 {
		pCloseHandle.Call(mutexHandle)
		mutexHandle = 0
	}
}

func fatalBox(title, msg string) {
	if pMessageBoxW.Addr() == 0 {
		return
	}
	t, _ := syscall.UTF16PtrFromString(title)
	m, _ := syscall.UTF16PtrFromString(msg)
	pMessageBoxW.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), 0x10)
}

func hideCmd(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}
