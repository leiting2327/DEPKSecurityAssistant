//go:build !windows

package main

import "os/exec"

func acquireMutex() bool { return true }
func releaseMutex()      {}
func fatalBox(title, msg string) {
	_ = title
	_ = msg
}
func hideCmd(cmd *exec.Cmd) {}
