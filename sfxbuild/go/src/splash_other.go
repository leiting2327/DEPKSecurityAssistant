//go:build !windows

package main

import "sync/atomic"

// winProgress 在非 Windows 平台不存在，恒为静默模式
type winProgress struct{}

func newWinProgress(cancel *atomic.Bool) *winProgress { return nil }

func (w *winProgress) setProgress(pct int, status string) {}
func (w *winProgress) notifyDone()                       {}
func (w *winProgress) pump()                             {}
func (w *winProgress) mode() string                      { return "静默(无窗口)" }
