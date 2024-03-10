package core

/*

This package exports all windows struct which are used

*/

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	ntdllpath    = "C:\\Windows\\System32\\ntdll.dll"
	kernel32path = "C:\\Windows\\System32\\kernel32.dll"
)

const (
	IDX = 32
)

type IMAGE_OPTIONAL_HEADER struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]IMAGE_DATA_DIRECTORY
}

type IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER

type IMAGE_OPTIONAL_HEADER32 struct {
	Magic                       uint16
	MajorLinkerVersion          byte
	MinorLinkerVersion          byte
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	BaseOfData                  uint32 // Different from 64 bit header
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               uintptr
}

type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size           uint32
}

type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type IMAGE_NT_HEADER struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER
}

type IMAGE_DOS_HEADER struct { // DOS .EXE header
	E_magic    uint16     // Magic number
	E_cblp     uint16     // Bytes on last page of file
	E_cp       uint16     // Pages in file
	E_crlc     uint16     // Relocations
	E_cparhdr  uint16     // Size of header in paragraphs
	E_minalloc uint16     // Minimum extra paragraphs needed
	E_maxalloc uint16     // Maximum extra paragraphs needed
	E_ss       uint16     // Initial (relative) SS value
	E_sp       uint16     // Initial SP value
	E_csum     uint16     // Checksum
	E_ip       uint16     // Initial IP value
	E_cs       uint16     // Initial (relative) CS value
	E_lfarlc   uint16     // File address of relocation table
	E_ovno     uint16     // Overlay number
	E_res      [4]uint16  // Reserved words
	E_oemid    uint16     // OEM identifier (for E_oeminfo)
	E_oeminfo  uint16     // OEM information; E_oemid specific
	E_res2     [10]uint16 // Reserved words
	E_lfanew   uint16     // File address of new exe header
}

type PEB struct {
	InheritedAddressSpace    byte        // BYTE	0
	ReadImageFileExecOptions byte        // BYTE	1
	BeingDebugged            byte        // BYTE	2
	reserved2                [1]byte     // BYTE 3
	Mutant                   uintptr     // BYTE 4
	ImageBaseAddress         uintptr     // BYTE 8
	Ldr                      uintptr     // PPEB_LDR_DATA
	ProcessParameters        uintptr     // PRTL_USER_PROCESS_PARAMETERS
	reserved4                [3]uintptr  // PVOID
	AtlThunkSListPtr         uintptr     // PVOID
	reserved5                uintptr     // PVOID
	reserved6                uint32      // ULONG
	reserved7                uintptr     // PVOID
	reserved8                uint32      // ULONG
	AtlThunkSListPtr32       uint32      // ULONG
	reserved9                [45]uintptr // PVOID
	reserved10               [96]byte    // BYTE
	PostProcessInitRoutine   uintptr     // PPS_POST_PROCESS_INIT_ROUTINE
	reserved11               [128]byte   // BYTE
	reserved12               [1]uintptr  // PVOID
	SessionId                uint32      // ULONG
}

// https://github.com/elastic/go-windows/blob/master/ntdll.go#L77
type PROCESS_BASIC_INFORMATION struct {
	reserved1                    uintptr    // PVOID
	PebBaseAddress               uintptr    // PPEB
	reserved2                    [2]uintptr // PVOID
	UniqueProcessId              uintptr    // ULONG_PTR
	InheritedFromUniqueProcessID uintptr    // PVOID
}

type ClientID struct {
	UniqueProcess windows.Handle
	UniqueThread  windows.Handle
}

type imageExportDir struct {
	_, _                  uint32
	_, _                  uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32
	AddressOfNames        uint32
	AddressOfNameOrdinals uint32
}

type memStatusEx struct { // Auxiliary struct to retrieve total memory
	dwLength     uint32
	dwMemoryLoad uint32
	ullTotalPhys uint64
	ullAvailPhys uint64
	unused       [5]uint64
}

type CLIENT_ID struct {
	UniqueProcess uintptr
	UniqueThread  uintptr
}

type PTHREAD_BASIC_INFORMATION struct {
	exitStatus      int32
	pTebBaseAddress uintptr
	clientId        CLIENT_ID
	AffinityMask    uintptr
	Priority        int
	BasePriority    int
	v               int
}

type SC_SERVICE_TAG_QUERY struct {
	processId  uint32
	serviceTag uint32
	reserved   uint32
	pBuffer    unsafe.Pointer
}

type M128A struct {
	Low  uint64
	High int64
}

type CONTEXT struct {
	P1Home               uint64
	P2Home               uint64
	P3Home               uint64
	P4Home               uint64
	P5Home               uint64
	P6Home               uint64
	ContextFlags         uint32
	MxCsr                uint32
	SegCs                uint16
	SegDs                uint16
	SegEs                uint16
	SegFs                uint16
	SegGs                uint16
	SegSs                uint16
	EFlags               uint32
	Dr0                  uint64
	Dr1                  uint64
	Dr2                  uint64
	Dr3                  uint64
	Dr6                  uint64
	Dr7                  uint64
	Rax                  uint64
	Rcx                  uint64
	Rdx                  uint64
	Rbx                  uint64
	Rsp                  uint64
	Rbp                  uint64
	Rsi                  uint64
	Rdi                  uint64
	R8                   uint64
	R9                   uint64
	R10                  uint64
	R11                  uint64
	R12                  uint64
	R13                  uint64
	R14                  uint64
	R15                  uint64
	Rip                  uint64
	VectorRegister       [26]M128A
	VectorControl        uint64
	DebugControl         uint64
	LastBranchToRip      uint64
	LastBranchFromRip    uint64
	LastExceptionToRip   uint64
	LastExceptionFromRip uint64
}
type IMAGE_NT_HEADERS64 struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER64
}

type IMAGE_SECTION_HEADER struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

type UString struct {
	Length        uint32
	MaximumLength uint32
	Buffer        *byte // This corresponds to PUCHAR in C
}
