package main

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

var logPath = filepath.Join(os.Getenv("TEMP"), "DEPKSecurityAssistant_install.log")

var errCanceled = fmt.Errorf("安装已取消")

func logStage(s string) {
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	f.WriteString(time.Now().Format("2006-01-02 15:04:05") + "  " + s + "\n")
	f.Close()
}

func main() {
	logStage("=== 安装程序启动 ===")
	if err := run(); err != nil {
		if err == errCanceled {
			logStage("用户取消安装，正常退出")
			return
		}
		writeErrLog(err)
		logStage("失败: " + err.Error())
		fatalBox("DEPK Security Assistant 安装失败", err.Error()+"\n\n错误日志：\n"+logPath)
	}
	logStage("=== 安装程序结束 ===")
}

// progressUI 是安装进度窗口句柄（nil 时表示静默模式，不展示任何界面）
type progressUI struct {
	p *winProgress
}

func newProgressUI(cancel *atomic.Bool) *progressUI {
	return &progressUI{p: newWinProgress(cancel)}
}

func (u *progressUI) setProgress(pct int, status string) {
	if u.p != nil {
		u.p.setProgress(pct, status)
	}
}

func (u *progressUI) mode() string {
	if u.p == nil {
		return "静默(无窗口，窗口创建失败回退)"
	}
	return u.p.mode()
}

func (u *progressUI) notifyDone() {
	if u.p != nil {
		u.p.notifyDone()
	}
}

func run() error {
	if !acquireMutex() {
		logStage("已有安装程序在运行，本次自动退出（请勿重复双击）")
		return nil
	}
	defer releaseMutex()
	self, err := os.Executable()
	if err != nil {
		return err
	}
	f, err := os.Open(self)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(f, st.Size())
	if err != nil {
		return fmt.Errorf("安装包数据损坏（%v），请重新下载", err)
	}
	if len(zr.File) == 0 {
		return fmt.Errorf("安装包内容为空，请重新下载")
	}
	logStage(fmt.Sprintf("安装包读取成功，内含 %d 个组件", len(zr.File)))
	dir := filepath.Join(os.Getenv("TEMP"), fmt.Sprintf("DEPKSecurityAssistant_Setup_%d", os.Getpid()))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// 无论成败都清理临时目录
	defer os.RemoveAll(dir)

	// 取消标记：用户关闭进度窗口时置 1
	var cancel atomic.Bool
	ui := newProgressUI(&cancel)
	logStage("进度窗口: " + ui.mode())

	result := make(chan error, 1)
	go func() {
		result <- extractAndLaunch(zr, dir, &cancel, ui)
	}()

	if ui.p == nil {
		// 静默模式：直接等后台完成
		return <-result
	}
	// 有窗口模式：UI 线程专职跑消息循环，解压完全在后台 goroutine，窗口永不阻塞
	ui.p.pump()
	return <-result
}

func extractAndLaunch(zr *zip.Reader, dir string, cancel *atomic.Bool, ui *progressUI) error {
	total := len(zr.File)
	done := 0
	extractStart := time.Now()
	for _, zf := range zr.File {
		if cancel.Load() {
			logStage("用户取消安装")
			return errCanceled
		}
		p := filepath.Join(dir, zf.Name)
		if !strings.HasPrefix(p, dir+string(os.PathSeparator)) {
			return fmt.Errorf("安装包包含非法路径，已中止")
		}
		if zf.FileInfo().IsDir() {
			os.MkdirAll(p, 0o755)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		rc, err := zf.Open()
		if err != nil {
			return err
		}
		out, err := os.Create(p)
		if err != nil {
			rc.Close()
			return err
		}
		if _, err := io.Copy(out, rc); err != nil {
			out.Close()
			rc.Close()
			return err
		}
		out.Close()
		rc.Close()
		if m := zf.Mode(); m&0o111 != 0 {
			os.Chmod(p, 0o755)
		}
		done++
		if done%5 == 0 || done == total {
			pct := done * 100 / total
			ui.setProgress(pct, fmt.Sprintf("正在解压组件  %d/%d", done, total))
			logStage(fmt.Sprintf("解压中 %d/%d", done, total))
		}
	}
	logStage(fmt.Sprintf("组件解压完成：%d 个，耗时 %ds", done, int(time.Since(extractStart).Seconds())))
	if cancel.Load() {
		return errCanceled
	}
	exe := filepath.Join(dir, "DEPKSecurityAssistant.exe")
	if _, err := os.Stat(exe); err != nil {
		return fmt.Errorf("安装组件缺失：%v", err)
	}
	ui.setProgress(100, "正在启动安装向导…")
	ui.notifyDone()
	posted := true
	defer func() { if !posted { ui.notifyDone() } }()
	cmd := exec.Command(exe, "--setup")
	hideCmd(cmd)
	if err := cmd.Start(); err != nil {
		return err
	}
	logStage("安装向导已启动")
	cmd.Wait()
	logStage("安装向导已退出")
	for i := 0; i < 20; i++ {
		if err := os.RemoveAll(dir); err == nil {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	logStage("临时目录已清理")
	return nil
}

func writeErrLog(err error) {
	p := filepath.Join(os.Getenv("TEMP"), "DEPKSecurityAssistant_install_error.log")
	os.WriteFile(p, []byte(time.Now().Format("2006-01-02 15:04:05")+" "+err.Error()+"\n"), 0o644)
}
