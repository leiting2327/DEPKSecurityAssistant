//go:build windows

package main

import (
	"fmt"
	"runtime"
	"sync/atomic"
	"syscall"
	"unsafe"
)

/* Win11 风格安装进度窗口：UI 线程只跑消息循环，解压在后台 goroutine，
   通过 PostMessage 唤醒刷新；窗口永不因解压而阻塞。 */

var (
	modGdi32 = syscall.NewLazyDLL("gdi32.dll")

	pGetMessageW      = modUser32.NewProc("GetMessageW")
	pTranslateMessage = modUser32.NewProc("TranslateMessage")
	pDispatchMessageW = modUser32.NewProc("DispatchMessageW")
	pCreateWindowExW  = modUser32.NewProc("CreateWindowExW")
	pDefWindowProcW   = modUser32.NewProc("DefWindowProcW")
	pDestroyWindow    = modUser32.NewProc("DestroyWindow")
	pRegisterClassExW = modUser32.NewProc("RegisterClassExW")
	pGetModuleHandleW = modKernel32.NewProc("GetModuleHandleW")
	pBeginPaint       = modUser32.NewProc("BeginPaint")
	pEndPaint         = modUser32.NewProc("EndPaint")
	pGetClientRect    = modUser32.NewProc("GetClientRect")
	pInvalidateRect   = modUser32.NewProc("InvalidateRect")
	pPostMessageW     = modUser32.NewProc("PostMessageW")
	pPostQuitMessage  = modUser32.NewProc("PostQuitMessage")
	pSetWindowPos     = modUser32.NewProc("SetWindowPos")
	pShowWindow       = modUser32.NewProc("ShowWindow")
	pUpdateWindow     = modUser32.NewProc("UpdateWindow")
	pCreateSolidBrush = modGdi32.NewProc("CreateSolidBrush")
	pDeleteObject     = modGdi32.NewProc("DeleteObject")
	pSelectObject     = modGdi32.NewProc("SelectObject")
	pSetBkMode        = modGdi32.NewProc("SetBkMode")
	pSetTextColor     = modGdi32.NewProc("SetTextColor")
	pCreateFontW      = modGdi32.NewProc("CreateFontW")
	pExtTextOutW      = modGdi32.NewProc("ExtTextOutW")
	pGetTextExtentPoint32W = modGdi32.NewProc("GetTextExtentPoint32W")
	pFillRect         = modUser32.NewProc("FillRect")
)

const (
	wsOverlapped   = 0x00000000
	wsCaption      = 0x00C00000
	wsSysMenu      = 0x00080000
	wsMinimizeBox  = 0x00020000
	wsVisible      = 0x10000000
	wsExAppWindow  = 0x00040000
	wsExToolWindow = 0x00000080
	wmEraseBkgnd   = 0x0014
	wmPaint        = 0x000F
	wmDestroy      = 0x0002
	wmClose        = 0x0010
	wmAppRepaint   = 0x8000
	wmAppDone      = 0x8001
	csDblClks      = 0x0008
	csHRedraw      = 0x0001
	csVRedraw      = 0x0002
	transparent    = 1
)

const (
	winW = 560
	winH = 330
)

type rect struct{ left, top, right, bottom int32 }
type msg struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      struct{ x, y int32 }
}
type paintStruct struct {
	hdc         uintptr
	fErase      int32
	rcPaint     rect
	fRestore    int32
	fIncUpdate  int32
	rgbReserved [32]byte
}
type wndClassEx struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     uintptr
	hIcon         uintptr
	hCursor       uintptr
	hbrBackground uintptr
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       uintptr
}

type winProgress struct {
	hwnd     uintptr
	cancel   *atomic.Bool
	done     atomic.Bool
	pct      int
	status   string
	mu       syncLocker
	hTitle   uintptr
	hStatus  uintptr
	hPct     uintptr
	brushBG  uintptr
	brushTrk uintptr
}

// 轻量锁：解压线程写状态，UI 线程画图读取
type syncLocker struct{ locked atomic.Bool }

func (l *syncLocker) lock() {
	for !l.locked.CompareAndSwap(false, true) {
		runtime.Gosched()
	}
}
func (l *syncLocker) unlock() { l.locked.Store(false) }

var _wndProc = syscall.NewCallback(wndProc)

func wndProc(hwnd uintptr, uMsg uint32, wParam, lParam uintptr) uintptr {
	switch uMsg {
	case wmEraseBkgnd:
		return 1
	case wmAppRepaint:
		pInvalidateRect.Call(hwnd, 0, 0)
		return 0
	case wmAppDone:
		w := windowFromHwnd(hwnd)
		if w != nil {
			w.done.Store(true)
		}
		return 0
	case wmClose:
		w := windowFromHwnd(hwnd)
		if w != nil && w.cancel != nil && !w.cancel.Load() {
			w.cancel.Store(true)
			w.mu.lock()
			w.status = "正在取消，请稍候…"
			w.mu.unlock()
			pInvalidateRect.Call(hwnd, 0, 0)
			return 0
		}
		pDestroyWindow.Call(hwnd)
		return 0
	case wmDestroy:
		pPostQuitMessage.Call(0)
		return 0
	case wmPaint:
		paintWindow(hwnd)
		return 0
	}
	r, _, _ := pDefWindowProcW.Call(hwnd, uintptr(uMsg), wParam, lParam)
	return r
}

var _winMap = struct {
	sync atomic.Pointer[winProgress]
}{}

func registerWindow(w *winProgress) {
	_winMap.sync.Store(w)
}
func windowFromHwnd(hwnd uintptr) *winProgress {
	w := _winMap.sync.Load()
	if w != nil && w.hwnd == hwnd {
		return w
	}
	return nil
}

func newWinProgress(cancel *atomic.Bool) *winProgress {
	if cancel == nil {
		return nil
	}
	runtime.LockOSThread()
	cls := syscall.StringToUTF16Ptr("DEPKSetupProgress")
	var wc wndClassEx
	wc.cbSize = uint32(unsafe.Sizeof(wc))
	wc.style = csHRedraw | csVRedraw | csDblClks
	wc.lpfnWndProc = _wndProc
	hInst, _, _ := pGetModuleHandleW.Call(0)
	wc.hInstance = hInst
	wc.lpszClassName = cls
	pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	title := syscall.StringToUTF16Ptr("DEPK Security Assistant 安装程序")
	hwnd, _, err := pCreateWindowExW.Call(
		wsExAppWindow,
		uintptr(unsafe.Pointer(cls)), uintptr(unsafe.Pointer(title)),
		wsOverlapped|wsCaption|wsSysMenu|wsMinimizeBox,
		0, 0, winW, winH, 0, 0, hInst, 0)
	if hwnd == 0 {
		return nil // 窗口创建失败：回退静默模式
	}
	_ = err
	w := &winProgress{hwnd: hwnd, cancel: cancel}
	registerWindow(w)
	centerWindow(hwnd)
	pShowWindow.Call(hwnd, 5) // SW_SHOW
	pUpdateWindow.Call(hwnd)
	w.setProgress(1, "正在准备安装组件…")
	return w
}

func centerWindow(hwnd uintptr) {
	sw, _, _ := pGetSystemMetrics.Call(0)  // SM_CXSCREEN
	sh, _, _ := pGetSystemMetrics.Call(1)  // SM_CYSCREEN
	x := int32(sw)/2 - winW/2
	y := int32(sh)/2 - winH/2
	if x < 0 {
		x = 0
	}
	if y < 0 {
		y = 0
	}
	pSetWindowPos.Call(hwnd, 0, uintptr(x), uintptr(y), 0, 0, 0x0001|0x0004) // SWP_NOSIZE|SWP_NOZORDER
}

func (w *winProgress) setProgress(pct int, status string) {
	if w == nil {
		return
	}
	w.mu.lock()
	w.pct = pct
	w.status = status
	w.mu.unlock()
	pInvalidateRect.Call(w.hwnd, 0, 0)
}

func (w *winProgress) notifyDone() {
	if w == nil {
		return
	}
	pPostMessageW.Call(w.hwnd, wmAppDone, 0, 0)
}

func (w *winProgress) pump() {
	var m msg
	for {
		if w.done.Load() {
			break
		}
		r, _, _ := pGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		pTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		pDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
	pDestroyWindow.Call(w.hwnd)
}

func paintWindow(hwnd uintptr) {
	var ps paintStruct
	hdc, _, _ := pBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
	var rc rect
	pGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&rc)))
	w := rc.right - rc.left
	h := rc.bottom - rc.top

	wPrg := windowFromHwnd(hwnd)
	pct := 0
	status := "正在准备…"
	if wPrg != nil {
		wPrg.mu.lock()
		pct = wPrg.pct
		status = wPrg.status
		wPrg.mu.unlock()
	}

	// 背景
	bg, _, _ := pCreateSolidBrush.Call(rgbColor(0x1B1B1F))
	fill := func(clr uint32, l, t, r, b int32) {
		var rr rect
		rr.left = l
		rr.top = t
		rr.right = r
		rr.bottom = b
		br, _, _ := pCreateSolidBrush.Call(rgbColor(clr))
		pFillRect.Call(hdc, uintptr(unsafe.Pointer(&rr)), br)
		pDeleteObject.Call(br)
	}
	fill(0x1B1B1F, 0, 0, w, h)
	pDeleteObject.Call(bg)

	// 顶部细条
	fill(0x2E5CFF, 0, 0, w, 3)

	// 盾牌标志（简单多边形）
	drawShield(hdc, 32, 40, 34)

	// 标题
	drawText(hdc, "DEPK Security Assistant", 0xFFFFFF, 20, 80, 34, 0, "Segoe UI")
	// 副标题/状态
	drawText(hdc, status, 0x9AA0A6, 20, 120, 15, 0, "Segoe UI")
	// 百分比
	drawText(hdc, fmt.Sprintf("%d%%", pct), 0x2E5CFF, w-20, 0, 30, 0x0002, "Segoe UI")

	// 底部进度条
	const trkH = 10
	tl, tt, tr, tb := int32(20), h-trkH-28, w-20, h-trkH-18
	fill(0x34363C, tl, tt, tr, tb)
	if pct > 0 {
		fw := int32((tr - tl) * int32(pct) / 100)
		if fw < 4 {
			fw = 4
		}
		fill(0x2E5CFF, tl, tt, tl+fw, tb)
	}
	// 提示
	drawText(hdc, "点击右上角 × 可取消安装", 0x5F6368, 20, h-14, 11, 0, "Segoe UI")

	pEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
}

func rgbColor(rgb uint32) uintptr {
	// 颜色常量按 0xRRGGBB 书写，转为 COLORREF(0x00BBGGRR)
	return uintptr(((rgb>>16)&0xFF)<<16 | (rgb & 0xFF00) | (rgb & 0xFF))
}

func drawShield(hdc uintptr, x, y, size int32) {
	pen, _, _ := pCreatePen.Call(1, 2, rgbColor(0x2E5CFF))
	old, _, _ := pSelectObject.Call(hdc, pen)
	brush, _, _ := pCreateSolidBrush.Call(rgbColor(0x1B1B1F))
	oldb, _, _ := pSelectObject.Call(hdc, brush)
	pts := []struct{ x, y int32 }{
		{x + size / 2, y}, {x + size, y + size / 4},
		{x + size, y + size / 2}, {x + size / 2, y + size},
		{x, y + size / 2}, {x, y + size / 4},
	}
	poly := make([]uintptr, 0, len(pts)*2)
	for _, p := range pts {
		poly = append(poly, uintptr(p.x), uintptr(p.y))
	}
	pPolygon.Call(hdc, uintptr(unsafe.Pointer(&poly[0])), uintptr(len(pts)))
	// 对勾
	pMoveToEx.Call(hdc, uintptr(x+size/5), uintptr(y+size/2), 0)
	pLineTo.Call(hdc, uintptr(x+size/2), uintptr(y+size*3/4))
	pLineTo.Call(hdc, uintptr(x+size*4/5), uintptr(y+size/4))
	pSelectObject.Call(hdc, oldb)
	pSelectObject.Call(hdc, old)
	pDeleteObject.Call(brush)
	pDeleteObject.Call(pen)
}

func drawText(hdc uintptr, text string, color uint32, x, y, size, align int32, face string) {
	fnt, _, _ := pCreateFontW.Call(
		uintptr(int32(-size)), 0, 0, 0, 600, 0, 0, 0, 0x86, 0, 0, 4, 0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(face))))
	old, _, _ := pSelectObject.Call(hdc, fnt)
	pSetBkMode.Call(hdc, transparent)
	pSetTextColor.Call(hdc, rgbColor(color))
	txt := syscall.StringToUTF16Ptr(text)
	length := len(text)
	xPos := uintptr(x)
	if align&0x0002 != 0 { // TA_RIGHT：按传入坐标右对齐
		var size2 struct{ cx, cy int32 }
		pGetTextExtentPoint32W.Call(hdc, uintptr(unsafe.Pointer(txt)), uintptr(length), uintptr(unsafe.Pointer(&size2)))
		xPos = uintptr(int32(x) - size2.cx)
	}
	pExtTextOutW.Call(hdc, xPos, uintptr(y), 0, 0, uintptr(unsafe.Pointer(txt)), uintptr(length), 0)
	pSelectObject.Call(hdc, old)
	pDeleteObject.Call(fnt)
}

func (w *winProgress) mode() string { return "有窗口(Win11 进度条)" }

var (
	pGetSystemMetrics = modUser32.NewProc("GetSystemMetrics")
	pCreatePen        = modGdi32.NewProc("CreatePen")
	pPolygon          = modGdi32.NewProc("Polygon")
	pMoveToEx         = modGdi32.NewProc("MoveToEx")
	pLineTo           = modGdi32.NewProc("LineTo")
)
