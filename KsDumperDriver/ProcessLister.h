#pragma once
#include <ntddk.h>

#pragma pack(push, 1)
typedef struct _PROCESS_SUMMARY
{
	INT32 ProcessId;
	PVOID MainModuleBase;
	WCHAR MainModuleFileName[256];
	UINT32 MainModuleImageSize;
	PVOID MainModuleEntryPoint;
	BOOLEAN WOW64;
} PROCESS_SUMMARY, *PPROCESS_SUMMARY;
#pragma pack(pop)

typedef struct _SYSTEM_PROCESS_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR PageDirectoryBase;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef struct _SYSTEM_THREAD_INFORMATION
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandler;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB64 {
	CHAR Reserved[0x10];
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
} PEB64, *PPEB64;

typedef struct _IMAGE_DOS_HEADER {
	USHORT   e_magic;
	USHORT   e_cblp;
	USHORT   e_cp;
	USHORT   e_crlc;
	USHORT   e_cparhdr;
	USHORT   e_minalloc;
	USHORT   e_maxalloc;
	USHORT   e_ss;
	USHORT   e_sp;
	USHORT   e_csum;
	USHORT   e_ip;
	USHORT   e_cs;
	USHORT   e_lfarlc;
	USHORT   e_ovno;
	USHORT   e_res[4];
	USHORT   e_oemid;
	USHORT   e_oeminfo;
	USHORT   e_res2[10];
	LONG   e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _PE_HEADER {
	CHAR Signature[4];
	USHORT Machine;
	USHORT NumberOfSections;
	UINT32 TimeDateStamp;
	UINT32 PointerToSymbolTable;
	UINT32 NumberOfSymbols;
	USHORT SizeOfOptionalHeader;
	USHORT Characteristics;
	USHORT Magic;
} PE_HEADER, *PPE_HEADER;

typedef struct _IMAGE_SECTION_HEADER {
	UCHAR  Name[8];
	union {
		UINT32 PhysicalAddress;
		UINT32 VirtualSize;
	} Misc;
	UINT32 VirtualAddress;
	UINT32 SizeOfRawData;
	UINT32 PointerToRawData;
	UINT32 PointerToRelocations;
	UINT32 PointerToLinenumbers;
	USHORT NumberOfRelocations;
	USHORT NumberOfLinenumbers;
	UINT32 Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_NT_HEADERS64 {
	UINT32 Signature;
	struct {
		USHORT Machine;
		USHORT NumberOfSections;
		UINT32 TimeDateStamp;
		UINT32 PointerToSymbolTable;
		UINT32 NumberOfSymbols;
		USHORT SizeOfOptionalHeader;
		USHORT Characteristics;
	} FileHeader;
	struct {
		USHORT Magic;
		UCHAR  MajorLinkerVersion;
		UCHAR  MinorLinkerVersion;
		UINT32 SizeOfCode;
		UINT32 SizeOfInitializedData;
		UINT32 SizeOfUninitializedData;
		UINT32 AddressOfEntryPoint;
		UINT32 BaseOfCode;
		UINT64 ImageBase;
		UINT32 SectionAlignment;
		UINT32 FileAlignment;
		UCHAR  Reserved[128];
	} OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

#define IMAGE_DOS_SIGNATURE 0x5A4D

#define IMAGE_SCN_CNT_CODE              0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA  0x00000040
#define IMAGE_SCN_MEM_EXECUTE           0x20000000
#define IMAGE_SCN_MEM_WRITE             0x80000000

#define PE_HEADER_MAGIC_OFFSET 0x18
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10b

#define IS_WOW64_PE( baseAddress ) (*((USHORT*)((CHAR *)baseAddress + \
								((PIMAGE_DOS_HEADER)baseAddress)->e_lfanew + PE_HEADER_MAGIC_OFFSET)) \
								== IMAGE_NT_OPTIONAL_HDR32_MAGIC)

NTSTATUS GetProcessList(PVOID listedProcessBuffer, INT32 bufferSize, PINT32 requiredBufferSize, PINT32 processCount);

NTSTATUS GetModuleList(HANDLE processId, PVOID listedModuleBuffer, INT32 bufferSize, PINT32 requiredBufferSize, PINT32 moduleCount);

NTSTATUS UnprotectProcess(HANDLE processId, PINT32 protectionStatus);

NTSTATUS CheckTablesReady(HANDLE processId, PINT32 readyStatus);

NTSTATUS SuspendProcessThreads(HANDLE processId, PINT32 threadCount);

NTSTATUS ResumeProcessThreads(HANDLE processId, PINT32 threadCount);

NTSTATUS KillProcessByName(PWCH processName, PINT32 killedPid, PINT32 status);

NTSTATUS UnloadDriverByName(PWCH driverName, PINT32 status);

NTSTATUS UnloadModule(HANDLE processId, PVOID moduleBaseAddress, PINT32 status);

NTSTATUS LsassReadMemory(HANDLE targetProcessId, PVOID targetAddress, PVOID bufferAddress, INT32 bufferSize, PINT32 status);

NTSTATUS EnumerateLoadedDrivers(PVOID buffer, INT32 bufferSize, PINT32 requiredSize, PINT32 driverCount);

// ---- Thread Context Operations ----
NTSTATUS KernelGetThreadContext(HANDLE processId, HANDLE threadId, PVOID contextBuffer, INT32 contextSize, INT32 contextFlags, PINT32 status);
NTSTATUS KernelSetThreadContext(HANDLE processId, HANDLE threadId, PVOID contextBuffer, INT32 contextSize, PINT32 status);

// ---- Debug Operations ----
NTSTATUS KernelDebugAttach(HANDLE processId, PINT32 status);
NTSTATUS KernelDebugWaitEvent(INT32 timeoutMs, PVOID eventBuffer, INT32 bufferSize, PINT32 eventCode, PINT32 threadId, PVOID* eventAddress, PINT32 exceptionCode, PINT32 status);
NTSTATUS KernelDebugContinue(INT32 threadId, INT32 continueStatus, PINT32 status);

// ---- Anti-Cheat Bypass: Kernel Callbacks ----
NTSTATUS EnumKernelCallbacks(PVOID buffer, INT32 bufferSize, PINT32 callbackCount, PINT32 removedCount, INT32 removeCallbacks);

// ---- Process Cloning ----
NTSTATUS CloneProcess(HANDLE targetProcessId, PINT32 clonedProcessId, PINT32 status);

// ---- VAD Tree Enumeration ----
NTSTATUS EnumVadTree(HANDLE targetProcessId, PVOID buffer, INT32 bufferSize, PINT32 requiredSize, PINT32 vadCount);

// ---- Handle Enumeration ----
NTSTATUS EnumHandles(HANDLE targetProcessId, PVOID buffer, INT32 bufferSize, PINT32 requiredSize, PINT32 handleCount);

// ---- Kernel Module Enumeration ----
NTSTATUS EnumKernelModules(PVOID buffer, INT32 bufferSize, PINT32 requiredSize, PINT32 moduleCount);