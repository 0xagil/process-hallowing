package core

import (
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

func KCT() {
	const (
		CREATE_NEW_CONSOLE   = 0x00000010
		STARTF_USESHOWWINDOW = 0x00000001
		SW_HIDE              = 0
	)
	const PROCESS_ALL_ACCESS = syscall.STANDARD_RIGHTS_REQUIRED | syscall.SYNCHRONIZE | 0xFFF

	// Initialize the STARTUPINFO struct
	var si syscall.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = STARTF_USESHOWWINDOW
	si.ShowWindow = SW_HIDE

	// Initialize the PROCESS_INFORMATION struct
	var pi syscall.ProcessInformation

	// Convert command from string to UTF16 pointer
	appName, _ := syscall.UTF16PtrFromString(`C:\Windows\System32\notepad.exe`)

	// Create the process
	err := syscall.CreateProcess(
		appName,            // ApplicationName
		nil,                // CommandLine
		nil,                // ProcessAttributes
		nil,                // ThreadAttributes
		false,              // InheritHandles
		CREATE_NEW_CONSOLE, // CreationFlags
		nil,                // Environment
		nil,                // CurrentDirectory
		&si,                // StartupInfo
		&pi,                // ProcessInformation
	)

	// Check for errors
	if err != nil {
		fmt.Printf("CreateProcess failed: %v\n", err)
		return
	}

	// Process has been started, handles should be closed
	defer syscall.CloseHandle(pi.Process)
	defer syscall.CloseHandle(pi.Thread)

	fmt.Printf("Process created: PID = %d\n", pi.ProcessId)
	time.Sleep(500 * time.Millisecond)

	hWindow, err := findWindow("Notepad", "")
	if err != nil {
		fmt.Println("Error finding Notepad window:", err)
		return
	}
	fmt.Printf("[+] Window Handle: 0x%p\n", hWindow)

	hProcess, err := syscall.OpenProcess(PROCESS_ALL_ACCESS, false, pi.ProcessId)
	if err != nil {
		fmt.Println("Error opening process:", err)
		return
	}
	defer syscall.CloseHandle(hProcess)

	// Print the process handle
	fmt.Printf("[+] Process Handle: 0x%p\n", hProcess)

	ntdll, err := syscall.LoadLibrary("ntdll.dll")
	if err != nil {
		fmt.Println("Error loading ntdll.dll:", err)
		return
	}
	defer syscall.FreeLibrary(ntdll)

	ntQueryInformationProcess, err := syscall.GetProcAddress(ntdll, "NtQueryInformationProcess")
	if err != nil {
		fmt.Println("Error getting NtQueryInformationProcess address:", err)
		return
	}

	// Prepare PROCESS_BASIC_INFORMATION and call NtQueryInformationProcess
	var pbi PROCESS_BASIC_INFORMATION
	ret, _, callErr := syscall.Syscall6(uintptr(ntQueryInformationProcess), 5, uintptr(hProcess), 0, uintptr(unsafe.Pointer(&pbi)), uintptr(unsafe.Sizeof(pbi)), 0, 0)
	if ret != 0 {
		fmt.Println("NtQueryInformationProcess call failed:", callErr)
		return
	}

	// Output some information
	fmt.Printf("PEB Base Address: 0x%X\n", pbi.PebBaseAddress)
	fmt.Printf("Unique Process ID: %d\n", pbi.UniqueProcessId)

}

func findWindow(className, windowName string) (hwnd syscall.Handle, err error) {
	user32 := syscall.NewLazyDLL("user32.dll")
	procFindWindow := user32.NewProc("FindWindowW")
	var classNameUTF16 *uint16
	var windowNameUTF16 *uint16
	if className != "" {
		classNameUTF16, err = syscall.UTF16PtrFromString(className)
		if err != nil {
			return
		}
	}
	if windowName != "" {
		windowNameUTF16, err = syscall.UTF16PtrFromString(windowName)
		if err != nil {
			return
		}
	}
	r0, _, e1 := syscall.Syscall(procFindWindow.Addr(), 2,
		uintptr(unsafe.Pointer(classNameUTF16)),
		uintptr(unsafe.Pointer(windowNameUTF16)),
		0)
	hwnd = syscall.Handle(r0)
	if hwnd == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}
