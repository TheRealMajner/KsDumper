#include "StringScanner.h"
#include "NTUndocumented.h"

#define STRING_POOL_TAG 'StrK'
#define READ_CHUNK_SIZE  0x10000   // 64 KB
#define MAX_STRING_CHARS 4096
#define MAX_STRINGS      100000
#define MAX_USER_ADDRESS ((ULONG_PTR)0x00007FFFFFFEFFFF)
#define MAX_REGION_SCAN_SIZE 0x10000000  // 256 MB cap per region

#pragma pack(push, 1)
typedef struct _STRING_ENTRY_PACKED
{
	UINT64 Address;
	UINT16 ByteLength;
	UINT8  IsUnicode;
} STRING_ENTRY_PACKED, *PSTRING_ENTRY_PACKED;
#pragma pack(pop)

// Context passed through the scan to track output position
typedef struct _SCAN_CONTEXT
{
	PVOID  outputBuffer;     // NULL = sizing pass (no writes)
	INT32  outputCapacity;   // total output buffer size
	INT32  outputUsed;       // bytes written so far (or that would be written)
	INT32  stringCount;
	INT32  minLen;
} SCAN_CONTEXT, *PSCAN_CONTEXT;

static BOOLEAN IsPrintableAscii(UINT8 ch)
{
	return (ch >= 0x20 && ch <= 0x7E) || ch == 0x09 || ch == 0x0A || ch == 0x0D;
}

static BOOLEAN IsPrintableWide(UINT16 ch)
{
	return (ch >= 0x0020 && ch <= 0x007E) ||
		(ch >= 0x00A0 && ch <= 0xFFFE) ||
		ch == 0x0009 || ch == 0x000A || ch == 0x000D;
}

static BOOLEAN IsReadableProtection(INT32 protect)
{
	if (protect & PAGE_GUARD) return FALSE;
	if (protect == PAGE_NOACCESS) return FALSE;
	return (protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0;
}

static BOOLEAN EmitString(PSCAN_CONTEXT ctx, UINT64 address, BOOLEAN isUnicode, PVOID stringData, INT32 byteLength)
{
	if (byteLength <= 0 || byteLength > 0xFFFF)
		return TRUE;

	INT32 headerSize = (INT32)sizeof(STRING_ENTRY_PACKED);
	INT32 entrySize = headerSize + byteLength;

	if (ctx->stringCount >= MAX_STRINGS)
		return FALSE;

	if (ctx->outputBuffer != NULL)
	{
		if (ctx->outputUsed + entrySize > ctx->outputCapacity)
			return FALSE; // buffer full

		PSTRING_ENTRY_PACKED entry = (PSTRING_ENTRY_PACKED)((CHAR*)ctx->outputBuffer + ctx->outputUsed);
		entry->Address = address;
		entry->ByteLength = (UINT16)byteLength;
		entry->IsUnicode = isUnicode ? 1 : 0;
		RtlCopyMemory((CHAR*)entry + headerSize, stringData, byteLength);
	}

	ctx->outputUsed += entrySize;
	ctx->stringCount++;
	return TRUE;
}

static VOID ScanBufferAscii(PUCHAR buffer, SIZE_T bufferSize, UINT64 baseAddress, PSCAN_CONTEXT ctx)
{
	INT32 start = -1;

	for (SIZE_T i = 0; i <= bufferSize; i++)
	{
		BOOLEAN isPrintable = (i < bufferSize) ? IsPrintableAscii(buffer[i]) : FALSE;

		if (isPrintable)
		{
			if (start < 0)
				start = (INT32)i;
		}
		else
		{
			if (start >= 0)
			{
				INT32 len = (INT32)i - start;
				if (len >= ctx->minLen && len <= MAX_STRING_CHARS)
				{
					if (!EmitString(ctx, baseAddress + (UINT64)start, FALSE, &buffer[start], len))
						return;
				}
				start = -1;
			}
		}
	}
}

static VOID ScanBufferUnicode(PUCHAR buffer, SIZE_T bufferSize, UINT64 baseAddress, PSCAN_CONTEXT ctx)
{
	INT32 startCharIndex = -1;
	SIZE_T wordCount = bufferSize / sizeof(WCHAR);
	WCHAR* wideBuffer = (WCHAR*)buffer;

	for (SIZE_T i = 0; i <= wordCount; i++)
	{
		BOOLEAN isPrintable = FALSE;
		if (i < wordCount)
			isPrintable = IsPrintableWide((UINT16)wideBuffer[i]);

		if (isPrintable)
		{
			if (startCharIndex < 0)
				startCharIndex = (INT32)i;
		}
		else
		{
			if (startCharIndex >= 0)
			{
				INT32 charCount = (INT32)i - startCharIndex;
				if (charCount >= ctx->minLen && charCount <= MAX_STRING_CHARS)
				{
					INT32 byteLen = charCount * (INT32)sizeof(WCHAR);
					if (!EmitString(ctx, baseAddress + (UINT64)(startCharIndex * sizeof(WCHAR)), TRUE, &wideBuffer[startCharIndex], byteLen))
						return;
				}
				startCharIndex = -1;
			}
		}
	}
}

static NTSTATUS ScanProcessMemory(PEPROCESS targetProcess, PSCAN_CONTEXT ctx)
{
	PUCHAR readBuffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, READ_CHUNK_SIZE, STRING_POOL_TAG);
	if (!readBuffer)
		return STATUS_INSUFFICIENT_RESOURCES;

	KAPC_STATE state;
	KeStackAttachProcess(targetProcess, &state);

	__try
	{
		ULONG_PTR address = 0;

		while (address < MAX_USER_ADDRESS)
		{
			MEMORY_BASIC_INFORMATION mbi;
			SIZE_T returnLength = 0;

			NTSTATUS queryStatus = ZwQueryVirtualMemory(
				ZwCurrentProcess(),
				(PVOID)address,
				MemoryBasicInformation,
				&mbi,
				sizeof(mbi),
				&returnLength);

			if (!NT_SUCCESS(queryStatus))
				break;

			ULONG_PTR regionBase = (ULONG_PTR)mbi.BaseAddress;
			SIZE_T regionSize = mbi.RegionSize;

			if (mbi.State == MEM_COMMIT && IsReadableProtection(mbi.Protect))
			{
				SIZE_T scanSize = regionSize;
				if (scanSize > MAX_REGION_SCAN_SIZE)
					scanSize = MAX_REGION_SCAN_SIZE;

				SIZE_T offset = 0;
				while (offset < scanSize && ctx->stringCount < MAX_STRINGS)
				{
					SIZE_T chunkSize = READ_CHUNK_SIZE;
					if (offset + chunkSize > scanSize)
						chunkSize = scanSize - offset;

					SIZE_T bytesRead = 0;
					NTSTATUS readStatus = MmCopyVirtualMemory(
						targetProcess,
						(PVOID)(regionBase + offset),
						PsGetCurrentProcess(),
						readBuffer,
						chunkSize,
						KernelMode,
						&bytesRead);

					if (NT_SUCCESS(readStatus) && bytesRead > 0)
					{
						UINT64 chunkBase = (UINT64)(regionBase + offset);
						ScanBufferAscii(readBuffer, bytesRead, chunkBase, ctx);
						ScanBufferUnicode(readBuffer, bytesRead, chunkBase, ctx);
					}

					offset += chunkSize;
				}
			}

			ULONG_PTR nextAddress = regionBase + regionSize;
			if (nextAddress <= address)
				break;
			address = nextAddress;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrintEx(0, 0, "KsDumper: Exception during string scan.\n");
	}

	KeUnstackDetachProcess(&state);
	ExFreePoolWithTag(readBuffer, STRING_POOL_TAG);
	return STATUS_SUCCESS;
}

NTSTATUS DumpProcessStrings(
	HANDLE processId,
	INT32 minStringLength,
	PVOID bufferAddress,
	INT32 bufferSize,
	PINT32 requiredSize,
	PINT32 stringCount)
{
	PEPROCESS targetProcess = NULL;
	*requiredSize = 0;
	*stringCount = 0;

	if (minStringLength < 1) minStringLength = 4;

	if (!NT_SUCCESS(PsLookupProcessByProcessId(processId, &targetProcess)))
		return STATUS_INVALID_PARAMETER;

	// Use kernel buffer to avoid writing to user-mode buffer while attached to target process
	PVOID kernelBuffer = NULL;
	INT32 kernelBufSize = 0;

	if (bufferAddress != NULL && bufferSize > 0)
	{
		kernelBufSize = bufferSize;
		if (kernelBufSize > 16 * 1024 * 1024)
			kernelBufSize = 16 * 1024 * 1024;
		kernelBuffer = ExAllocatePoolWithTag(NonPagedPool, (SIZE_T)kernelBufSize, STRING_POOL_TAG);
		if (!kernelBuffer)
		{
			ObDereferenceObject(targetProcess);
			return STATUS_INSUFFICIENT_RESOURCES;
		}
	}

	SCAN_CONTEXT ctx;
	RtlZeroMemory(&ctx, sizeof(ctx));
	ctx.minLen = minStringLength;
	ctx.outputBuffer = kernelBuffer;
	ctx.outputCapacity = kernelBufSize;
	ctx.outputUsed = 0;
	ctx.stringCount = 0;

	NTSTATUS status = ScanProcessMemory(targetProcess, &ctx);

	ObDereferenceObject(targetProcess);

	*requiredSize = ctx.outputUsed;
	*stringCount = ctx.stringCount;

	// Copy kernel buffer to user buffer (now in caller's address space)
	if (kernelBuffer && bufferAddress)
	{
		INT32 copySize = ctx.outputUsed < kernelBufSize ? ctx.outputUsed : kernelBufSize;
		if (copySize > 0)
		{
			__try
			{
				RtlCopyMemory(bufferAddress, kernelBuffer, copySize);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				DbgPrintEx(0, 0, "KsDumper: Exception copying strings to user buffer.\n");
			}
		}
	}

	if (kernelBuffer)
		ExFreePoolWithTag(kernelBuffer, STRING_POOL_TAG);

	return status;
}
