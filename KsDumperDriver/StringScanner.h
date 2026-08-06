#pragma once
#include <ntddk.h>

typedef struct _KERNEL_STRING_DUMP_OPERATION
{
	INT32 targetProcessId;
	INT32 minStringLength;
	PVOID bufferAddress;
	INT32 bufferSize;
	INT32 requiredSize;
	INT32 stringCount;
} KERNEL_STRING_DUMP_OPERATION, *PKERNEL_STRING_DUMP_OPERATION;

NTSTATUS DumpProcessStrings(
	HANDLE processId,
	INT32 minStringLength,
	PVOID bufferAddress,
	INT32 bufferSize,
	PINT32 requiredSize,
	PINT32 stringCount);
