#pragma once
#include <ntddk.h>

#define IO_GET_PROCESS_LIST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1724, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IO_COPY_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1725, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IO_GET_MODULE_LIST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1726, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IO_UNPROTECT_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1727, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IO_CHECK_TABLES_READY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1728, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IO_GET_EXPORT_MAP CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1729, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

// Status codes returned by IO_CHECK_TABLES_READY in the status field
#define TABLES_NOT_READY     0  // Tables still encrypted or .rdata not readable
#define TABLES_READY         1  // Import table resolved, .rdata readable
#define TABLES_NO_IMPORTS    2  // Process has no import table to check

typedef struct _KERNEL_PROCESS_LIST_OPERATION
{
	PVOID bufferAddress;
	INT32 bufferSize;
	INT32 processCount;
} KERNEL_PROCESS_LIST_OPERATION, *PKERNEL_PROCESS_LIST_OPERATION;

typedef struct _KERNEL_COPY_MEMORY_OPERATION
{
	INT32 targetProcessId;
	PVOID targetAddress;
	PVOID bufferAddress;
	INT32 bufferSize;
} KERNEL_COPY_MEMORY_OPERATION, *PKERNEL_COPY_MEMORY_OPERATION;

#pragma pack(push, 1)
typedef struct _MODULE_SUMMARY
{
	INT32 ProcessId;
	PVOID BaseAddress;
	PVOID EntryPoint;
	UINT32 ImageSize;
	WCHAR FileName[256];
	BOOLEAN Hidden;
} MODULE_SUMMARY, *PMODULE_SUMMARY;
#pragma pack(pop)

typedef struct _KERNEL_MODULE_LIST_OPERATION
{
	PVOID bufferAddress;
	INT32 bufferSize;
	INT32 moduleCount;
	INT32 targetProcessId;
} KERNEL_MODULE_LIST_OPERATION, *PKERNEL_MODULE_LIST_OPERATION;

typedef struct _KERNEL_UNPROTECT_OPERATION
{
	INT32 targetProcessId;
	INT32 status;          // Output: 0 = no protection, 1 = PPL cleared, 2 = callbacks removed, 3 = both
} KERNEL_UNPROTECT_OPERATION, *PKERNEL_UNPROTECT_OPERATION;

typedef struct _KERNEL_TABLE_CHECK_OPERATION
{
	INT32 targetProcessId;
	INT32 status;          // Output: TABLES_NOT_READY, TABLES_READY, or TABLES_NO_IMPORTS
} KERNEL_TABLE_CHECK_OPERATION, *PKERNEL_TABLE_CHECK_OPERATION;

typedef struct _EXPORT_MAP_OPERATION
{
	INT32 targetProcessId;
	PVOID bufferAddress;
	INT32 bufferSize;
	INT32 requiredSize;
	INT32 moduleCount;
} EXPORT_MAP_OPERATION, *PEXPORT_MAP_OPERATION;

#define IO_SUSPEND_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1730, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IO_RESUME_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1731, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

typedef struct _KERNEL_SUSPEND_OPERATION
{
	INT32 targetProcessId;
	INT32 threadCount;       // Output: number of threads suspended/resumed
} KERNEL_SUSPEND_OPERATION, *PKERNEL_SUSPEND_OPERATION;

#define IO_DUMP_STRINGS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1732, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IO_ENUM_REGIONS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1733, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IO_FIND_PATTERN CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1734, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IO_READ_IL2CPP_METADATA CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1735, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IO_KILL_PROCESS_BY_NAME CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1736, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IO_UNLOAD_DRIVER_BY_NAME CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1737, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IO_UNLOAD_MODULE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1738, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IO_LSASS_READ_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1739, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IO_WRITE_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1740, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

typedef struct _KERNEL_KILL_PROCESS_OPERATION
{
	WCHAR processName[64];       // Input: process name to kill (e.g., "EasyAntiCheat_EOS.exe")
	INT32 killedPid;             // Output: PID of killed process, or -1 if not found
	INT32 status;                // Output: 0=success, 1=not found, 2=failed
} KERNEL_KILL_PROCESS_OPERATION, *PKERNEL_KILL_PROCESS_OPERATION;

typedef struct _KERNEL_UNLOAD_DRIVER_OPERATION
{
	WCHAR driverName[64];        // Input: driver name (e.g., "EasyAntiCheat")
	INT32 status;                // Output: 0=success, 1=not found, 2=failed
} KERNEL_UNLOAD_DRIVER_OPERATION, *PKERNEL_UNLOAD_DRIVER_OPERATION;

typedef struct _KERNEL_UNLOAD_MODULE_OPERATION
{
	INT32 targetProcessId;
	PVOID moduleBaseAddress;
	INT32 status;                // Output: 0=success, 1=not found, 2=failed
} KERNEL_UNLOAD_MODULE_OPERATION, *PKERNEL_UNLOAD_MODULE_OPERATION;

typedef struct _KERNEL_LSASS_READ_OPERATION
{
	INT32 targetProcessId;
	PVOID targetAddress;
	PVOID bufferAddress;
	INT32 bufferSize;
	INT32 status;                // Output: 0=success, 1=lsass not found, 2=read failed
} KERNEL_LSASS_READ_OPERATION, *PKERNEL_LSASS_READ_OPERATION;

#define IO_ENUM_DRIVERS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x173A, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

typedef struct _KERNEL_DRIVER_LIST_OPERATION
{
	PVOID bufferAddress;
	INT32 bufferSize;
	INT32 requiredSize;
	INT32 driverCount;
} KERNEL_DRIVER_LIST_OPERATION, *PKERNEL_DRIVER_LIST_OPERATION;

// ---- Thread Context Operations ----
#define IO_GET_THREAD_CONTEXT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x173B, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_SET_THREAD_CONTEXT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x173C, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

typedef struct _KERNEL_THREAD_CONTEXT_OPERATION
{
	INT32 targetProcessId;
	INT32 threadId;
	PVOID contextBuffer;      // User-mode buffer for CONTEXT structure (must be >= 1232 bytes for x64)
	INT32 contextSize;        // Size of context buffer
	INT32 contextFlags;       // CONTEXT flags (e.g., CONTEXT_FULL, CONTEXT_DEBUG_REGISTERS)
	INT32 status;             // Output: 0=success, 1=thread not found, 2=failed
} KERNEL_THREAD_CONTEXT_OPERATION, *PKERNEL_THREAD_CONTEXT_OPERATION;

// ---- Debug Operations ----
#define IO_DEBUG_ACTIVE_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x173D, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_DEBUG_WAIT_EVENT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x173E, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_DEBUG_CONTINUE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x173F, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

typedef struct _KERNEL_DEBUG_OPERATION
{
	INT32 targetProcessId;
	INT32 status;             // Output: 0=success, 1=already debugging, 2=failed
} KERNEL_DEBUG_OPERATION, *PKERNEL_DEBUG_OPERATION;

typedef struct _KERNEL_DEBUG_WAIT_OPERATION
{
	INT32 timeoutMs;          // Timeout in milliseconds (-1 = infinite)
	PVOID eventBuffer;        // User-mode buffer for debug event data
	INT32 bufferSize;
	INT32 eventCode;          // Output: debug event code (1=exception, 2=create_thread, etc.)
	INT32 threadId;           // Output: thread ID that triggered the event
	PVOID eventAddress;       // Output: address related to the event (e.g., exception address)
	INT32 exceptionCode;      // Output: exception code if event is an exception
	INT32 status;             // Output: 0=event received, 1=timeout, 2=not debugging, 3=failed
} KERNEL_DEBUG_WAIT_OPERATION, *PKERNEL_DEBUG_WAIT_OPERATION;

typedef struct _KERNEL_DEBUG_CONTINUE_OPERATION
{
	INT32 threadId;
	INT32 continueStatus;     // DBG_CONTINUE (0x00010002) or DBG_EXCEPTION_NOT_HANDLED
	INT32 status;             // Output: 0=success, 1=failed
} KERNEL_DEBUG_CONTINUE_OPERATION, *PKERNEL_DEBUG_CONTINUE_OPERATION;

// ---- Anti-Cheat Bypass: Kernel Callback Enumeration ----
#define IO_ENUM_KERNEL_CALLBACKS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1741, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_REMOVE_KERNEL_CALLBACKS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1742, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#pragma pack(push, 1)
typedef struct _KERNEL_CALLBACK_ENTRY
{
	UINT64 CallbackAddress;      // Address of the callback function
	WCHAR DriverName[128];       // Driver that registered the callback
	UINT32 CallbackType;         // 0=Process, 1=LoadImage, 2=Thread, 3=ObRegister
	UINT32 Index;                // Index in the callback array
	UINT32 Removed;              // Output: 1 if removed, 0 if still active
} KERNEL_CALLBACK_ENTRY, *PKERNEL_CALLBACK_ENTRY;
#pragma pack(pop)

typedef struct _KERNEL_CALLBACK_OPERATION
{
	INT32 removeCallbacks;       // Input: 0=enumerate only, 1=enumerate and remove
	INT32 callbackCount;         // Output: number of callbacks found
	PVOID bufferAddress;         // Output buffer for callback entries
	INT32 bufferSize;            // Size of output buffer
	INT32 removedCount;          // Output: number of callbacks removed
} KERNEL_CALLBACK_OPERATION, *PKERNEL_CALLBACK_OPERATION;

// ---- Process Cloning ----
#define IO_CLONE_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1743, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

typedef struct _KERNEL_CLONE_PROCESS_OPERATION
{
	INT32 targetProcessId;       // Input: PID of process to clone
	INT32 clonedProcessId;       // Output: PID of cloned process, or -1 if failed
	INT32 status;                // Output: 0=success, 1=not found, 2=failed
} KERNEL_CLONE_PROCESS_OPERATION, *PKERNEL_CLONE_PROCESS_OPERATION;

// ---- VAD Tree Enumeration ----
#define IO_ENUM_VAD CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1744, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#pragma pack(push, 1)
typedef struct _VAD_ENTRY
{
	UINT64 StartAddress;
	UINT64 EndAddress;
	UINT32 Protection;
	UINT32 Flags;                // VAD flags (Private, Mapped, Image, etc.)
	UINT32 CommitCharge;         // Number of committed pages
	UINT64 ControlArea;          // Pointer to control area (for mapped/image VADs)
} VAD_ENTRY, *PVAD_ENTRY;
#pragma pack(pop)

typedef struct _KERNEL_VAD_OPERATION
{
	INT32 targetProcessId;
	PVOID bufferAddress;
	INT32 bufferSize;
	INT32 requiredSize;
	INT32 vadCount;
} KERNEL_VAD_OPERATION, *PKERNEL_VAD_OPERATION;

// ---- Handle Enumeration ----
#define IO_ENUM_HANDLES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1745, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#pragma pack(push, 1)
typedef struct _HANDLE_ENTRY
{
	UINT64 HandleValue;
	INT32 ProcessId;             // Process that owns the handle
	INT32 TargetProcessId;       // Target process (if handle points to a process)
	UINT32 GrantedAccess;
	UINT32 HandleAttributes;
	WCHAR ObjectName[128];       // Object name if available
	UINT32 ObjectTypeIndex;      // Object type index
} HANDLE_ENTRY, *PHANDLE_ENTRY;
#pragma pack(pop)

typedef struct _KERNEL_HANDLE_OPERATION
{
	INT32 targetProcessId;       // Enumerate handles TO this process
	PVOID bufferAddress;
	INT32 bufferSize;
	INT32 requiredSize;
	INT32 handleCount;
} KERNEL_HANDLE_OPERATION, *PKERNEL_HANDLE_OPERATION;

// ---- Kernel Module Enumeration (includes unlinked modules) ----
#define IO_ENUM_KERNEL_MODULES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1746, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#pragma pack(push, 1)
typedef struct _KERNEL_MODULE_ENTRY
{
	UINT64 BaseAddress;
	UINT32 ImageSize;
	WCHAR BaseName[128];
	WCHAR FullPath[256];
	UINT32 Flags;                // 0=normal, 1=unlinked from PsLoadedModuleList
} KERNEL_MODULE_ENTRY, *PKERNEL_MODULE_ENTRY;
#pragma pack(pop)

typedef struct _KERNEL_MODULE_ENUM_OPERATION
{
	PVOID bufferAddress;
	INT32 bufferSize;
	INT32 requiredSize;
	INT32 moduleCount;
} KERNEL_MODULE_ENUM_OPERATION, *PKERNEL_MODULE_ENUM_OPERATION;

#include "StringScanner.h"
#include "MemoryScanner.h"