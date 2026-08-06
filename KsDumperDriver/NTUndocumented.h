#pragma once
#include <ntddk.h>

typedef struct _KAPC_STATE {
	LIST_ENTRY ApcListHead[MaximumMode];
	struct _KPROCESS *Process;
	BOOLEAN KernelApcInProgress;
	BOOLEAN KernelApcPending;
	BOOLEAN UserApcPending;
} KAPC_STATE, *PKAPC_STATE, *PRKAPC_STATE;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemProcessInformation = 5
} SYSTEM_INFORMATION_CLASS;

typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation,
	MemoryWorkingSetInformation,
	MemoryMappedFilenameInformation,
	MemoryRegionInformation,
	MemoryWorkingSetExInformation

} MEMORY_INFORMATION_CLASS;


typedef struct _MEMORY_BASIC_INFORMATION {
	PVOID  BaseAddress;
	PVOID  AllocationBase;
	INT32  AllocationProtect;
	SIZE_T RegionSize;
	INT32  State;
	INT32  Protect;
	INT32  Type;
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;

NTKERNELAPI VOID KeStackAttachProcess(__inout struct _KPROCESS * PROCESS, __out PRKAPC_STATE ApcState);
NTKERNELAPI VOID KeUnstackDetachProcess(__in PRKAPC_STATE ApcState);

NTKERNELAPI NTSTATUS NTAPI MmCopyVirtualMemory(IN PEPROCESS FromProcess, IN PVOID FromAddress, IN PEPROCESS ToProcess, OUT PVOID ToAddress, IN SIZE_T BufferSize, IN KPROCESSOR_MODE PreviousMode, OUT PSIZE_T NumberOfBytesCopied);

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT PULONG ReturnLength OPTIONAL);
NTSYSAPI NTSTATUS NTAPI ZwQueryVirtualMemory(IN HANDLE ProcessHandle, IN PVOID BaseAddress, IN MEMORY_INFORMATION_CLASS MemoryInformationClass, OUT PVOID MemoryInformation, IN SIZE_T MemoryInformationLength, OUT PSIZE_T ReturnLength OPTIONAL);
NTSYSAPI NTSTATUS NTAPI ZwOpenProcess(OUT PHANDLE ProcessHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, IN PCLIENT_ID ClientId OPTIONAL);

NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(IN HANDLE ProcessId, OUT PEPROCESS *Process);
NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(__in PEPROCESS Process);
NTKERNELAPI PPEB NTAPI PsGetProcessPeb(IN PEPROCESS Process);
NTKERNELAPI BOOLEAN PsIsProtectedProcess(IN PEPROCESS Process);
NTKERNELAPI BOOLEAN PsIsProtectedProcessLight(IN PEPROCESS Process);
NTKERNELAPI ULONG PsGetProcessProtection(IN PEPROCESS Process);

typedef NTSTATUS (*PFnPsSuspendThread)(IN PETHREAD Thread, OUT PLONG PreviousSuspendCount OPTIONAL);
typedef NTSTATUS (*PFnPsResumeThread)(IN PETHREAD Thread, OUT PLONG PreviousSuspendCount OPTIONAL);

NTKERNELAPI NTSTATUS PsLookupThreadByThreadId(IN HANDLE ThreadId, OUT PETHREAD *Thread);

NTKERNELAPI NTSTATUS ObOpenObjectByPointer(IN PVOID Object, IN ULONG HandleAttributes,
	IN PACCESS_STATE PassedAccessState, IN ACCESS_MASK DesiredAccess,
	IN POBJECT_TYPE ObjectType, IN KPROCESSOR_MODE AccessMode, OUT PHANDLE Handle);

NTSYSAPI NTSTATUS NTAPI ZwGetContextThread(IN HANDLE ThreadHandle, OUT PCONTEXT Context);
NTSYSAPI NTSTATUS NTAPI ZwSetContextThread(IN HANDLE ThreadHandle, IN PCONTEXT Context);

#define THREAD_GET_CONTEXT       0x0008
#define THREAD_SET_CONTEXT       0x0010
#define THREAD_QUERY_INFORMATION 0x0040

#define DEBUG_ALL_ACCESS         0x001F000F

NTSYSAPI NTSTATUS NTAPI RtlGetVersion(OUT PRTL_OSVERSIONINFOW lpVersionInformation);

#define MEM_COMMIT   0x1000
#define MEM_IMAGE    0x1000000
#define PROCESS_ALL_ACCESS 0x001F0FFF

extern POBJECT_TYPE *PsProcessType;
extern POBJECT_TYPE *PsThreadType;

#define PAGE_READONLY           0x02
#define PAGE_READWRITE          0x04
#define PAGE_WRITECOPY          0x08
#define PAGE_EXECUTE_READ       0x20
#define PAGE_EXECUTE_READWRITE  0x40

NTKERNELAPI NTSTATUS IoCreateDriver(
    _In_opt_ PUNICODE_STRING DriverName,
    _In_ PDRIVER_INITIALIZE InitializationFunction
);
