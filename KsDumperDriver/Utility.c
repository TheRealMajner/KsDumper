#include "NTUndocumented.h"
#include "Utility.h"

NTSTATUS DriverSleep(int ms)
{
	LARGE_INTEGER li;
	li.QuadPart = -(LONGLONG)ms * 10000;
	return KeDelayExecutionThread(KernelMode, FALSE, &li);
}

PVOID SanitizeUserPointer(PVOID pointer, SIZE_T size)
{
	MEMORY_BASIC_INFORMATION memInfo;

	// Reject NULL and kernel-space pointers
	if (pointer == NULL || (uintptr_t)pointer < 0x10000)
		return NULL;

	// Check for integer overflow in pointer + size
	if ((uintptr_t)pointer + size < (uintptr_t)pointer)
		return NULL;

	if (!NT_SUCCESS(ZwQueryVirtualMemory(ZwCurrentProcess(), pointer, MemoryBasicInformation, &memInfo, sizeof(MEMORY_BASIC_INFORMATION), NULL)))
		return NULL;

	// Check 1: pointer + size must fit within the memory region
	uintptr_t regionEnd = (uintptr_t)memInfo.BaseAddress + memInfo.RegionSize;
	uintptr_t accessEnd = (uintptr_t)pointer + size;
	if (accessEnd > regionEnd)
		return NULL;

	// Check 2: region must be committed
	if (memInfo.State != MEM_COMMIT)
		return NULL;

	// Check 3: region must not be guarded or inaccessible
	if (memInfo.Protect & (PAGE_GUARD | PAGE_NOACCESS))
		return NULL;

	// Check 4: region must have some form of read access
	if (!(memInfo.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
		PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
		return NULL;

	return pointer;
}
