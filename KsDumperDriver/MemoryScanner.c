#include "MemoryScanner.h"
#include "NTUndocumented.h"

#define MEMSCAN_POOL_TAG 'MscK'
#define SCAN_CHUNK_SIZE 0x10000  // 64 KB
#define MAX_USER_ADDRESS ((ULONG_PTR)0x00007FFFFFFEFFFF)
#define MAX_REGION_SCAN_SIZE 0x10000000  // 256 MB cap per region

static BOOLEAN IsReadableProtect(INT32 protect)
{
	if (protect & PAGE_GUARD) return FALSE;
	if (protect == PAGE_NOACCESS) return FALSE;
	return (protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0;
}

// ---- Region Enumeration ----

NTSTATUS EnumProcessRegions(HANDLE processId, PVOID bufferAddress, INT32 bufferSize, PINT32 requiredSize, PINT32 regionCount)
{
	PEPROCESS targetProcess = NULL;
	KAPC_STATE state;
	*requiredSize = 0;
	*regionCount = 0;

	if (!NT_SUCCESS(PsLookupProcessByProcessId(processId, &targetProcess)))
		return STATUS_INVALID_PARAMETER;

	PVOID kernelBuffer = NULL;
	INT32 kernelBufSize = 0;
	BOOLEAN writeMode = (bufferAddress != NULL && bufferSize > 0);

	if (writeMode)
	{
		kernelBufSize = bufferSize;
		if (kernelBufSize > 16 * 1024 * 1024)
			kernelBufSize = 16 * 1024 * 1024;
		kernelBuffer = ExAllocatePoolWithTag(NonPagedPool, (SIZE_T)kernelBufSize, MEMSCAN_POOL_TAG);
		if (!kernelBuffer)
		{
			ObDereferenceObject(targetProcess);
			return STATUS_INSUFFICIENT_RESOURCES;
		}
	}

	KeStackAttachProcess(targetProcess, &state);

	__try
	{
		ULONG_PTR address = 0;
		INT32 offset = 0;
		INT32 count = 0;
		INT32 entrySize = (INT32)sizeof(REGION_ENTRY_PACKED);

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

			if (mbi.State == MEM_COMMIT)
			{
				if (kernelBuffer && offset + entrySize <= kernelBufSize)
				{
					PREGION_ENTRY_PACKED entry = (PREGION_ENTRY_PACKED)((CHAR*)kernelBuffer + offset);
					entry->BaseAddress = (UINT64)(ULONG_PTR)mbi.BaseAddress;
					entry->RegionSize = (UINT64)mbi.RegionSize;
					entry->Protect = (UINT32)mbi.Protect;
					entry->State = (UINT32)mbi.State;
					entry->Type = (UINT32)mbi.Type;
				}
				offset += entrySize;
				count++;
			}

			ULONG_PTR nextAddress = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
			if (nextAddress <= address)
				break;
			address = nextAddress;
		}

		*requiredSize = offset;
		*regionCount = count;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrintEx(0, 0, "KsDumper: Exception in EnumProcessRegions.\n");
	}

	KeUnstackDetachProcess(&state);

	if (kernelBuffer && bufferAddress)
	{
		INT32 copySize = *requiredSize < kernelBufSize ? *requiredSize : kernelBufSize;
		if (copySize > 0)
		{
			__try
			{
				RtlCopyMemory(bufferAddress, kernelBuffer, copySize);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				DbgPrintEx(0, 0, "KsDumper: Exception copying regions to user buffer.\n");
			}
		}
	}

	if (kernelBuffer)
		ExFreePoolWithTag(kernelBuffer, MEMSCAN_POOL_TAG);

	ObDereferenceObject(targetProcess);
	return STATUS_SUCCESS;
}

// ---- Pattern Scanning ----

static BOOLEAN MatchPattern(PUCHAR data, PUCHAR pattern, INT32 length, UINT8 wildcard)
{
	for (INT32 i = 0; i < length; i++)
	{
		if (pattern[i] != wildcard && data[i] != pattern[i])
			return FALSE;
	}
	return TRUE;
}

NTSTATUS ScanProcessPattern(HANDLE processId, PUCHAR pattern, INT32 patternLength, UINT8 wildcard, PUINT64 results, INT32 maxResults, PINT32 matchCount)
{
	PEPROCESS targetProcess = NULL;
	KAPC_STATE state;
	*matchCount = 0;

	if (!NT_SUCCESS(PsLookupProcessByProcessId(processId, &targetProcess)))
		return STATUS_INVALID_PARAMETER;

	PUCHAR readBuffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, SCAN_CHUNK_SIZE, MEMSCAN_POOL_TAG);
	if (!readBuffer)
	{
		ObDereferenceObject(targetProcess);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// Copy pattern to kernel buffer before attach (pattern is user-mode pointer)
	PUCHAR kernelPattern = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, (SIZE_T)patternLength, MEMSCAN_POOL_TAG);
	if (!kernelPattern)
	{
		ExFreePoolWithTag(readBuffer, MEMSCAN_POOL_TAG);
		ObDereferenceObject(targetProcess);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	__try
	{
		RtlCopyMemory(kernelPattern, pattern, patternLength);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		ExFreePoolWithTag(kernelPattern, MEMSCAN_POOL_TAG);
		ExFreePoolWithTag(readBuffer, MEMSCAN_POOL_TAG);
		ObDereferenceObject(targetProcess);
		return STATUS_INVALID_PARAMETER;
	}

	// Allocate kernel results buffer
	PUINT64 kernelResults = NULL;
	if (results && maxResults > 0)
	{
		SIZE_T resultsSize = (SIZE_T)maxResults * sizeof(UINT64);
		if (resultsSize > 16 * 1024 * 1024)
			resultsSize = 16 * 1024 * 1024;
		kernelResults = (PUINT64)ExAllocatePoolWithTag(NonPagedPool, resultsSize, MEMSCAN_POOL_TAG);
		if (!kernelResults)
		{
			ExFreePoolWithTag(kernelPattern, MEMSCAN_POOL_TAG);
			ExFreePoolWithTag(readBuffer, MEMSCAN_POOL_TAG);
			ObDereferenceObject(targetProcess);
			return STATUS_INSUFFICIENT_RESOURCES;
		}
	}

	KeStackAttachProcess(targetProcess, &state);

	__try
	{
		ULONG_PTR address = 0;
		INT32 count = 0;

		while (address < MAX_USER_ADDRESS && count < maxResults)
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

			if (mbi.State == MEM_COMMIT && IsReadableProtect(mbi.Protect))
			{
				SIZE_T scanSize = regionSize;
				if (scanSize > MAX_REGION_SCAN_SIZE)
					scanSize = MAX_REGION_SCAN_SIZE;

				SIZE_T offset = 0;
				while (offset < scanSize && count < maxResults)
				{
					SIZE_T chunkSize = SCAN_CHUNK_SIZE;
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

					if (NT_SUCCESS(readStatus) && bytesRead >= (SIZE_T)patternLength)
					{
						for (SIZE_T i = 0; i <= bytesRead - patternLength && count < maxResults; i++)
						{
							if (MatchPattern(&readBuffer[i], kernelPattern, patternLength, wildcard))
							{
								if (kernelResults)
									kernelResults[count] = (UINT64)(regionBase + offset + i);
								count++;
							}
						}
					}

					offset += chunkSize;
				}
			}

			ULONG_PTR nextAddress = regionBase + regionSize;
			if (nextAddress <= address)
				break;
			address = nextAddress;
		}

		*matchCount = count;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrintEx(0, 0, "KsDumper: Exception in ScanProcessPattern.\n");
	}

	KeUnstackDetachProcess(&state);

	if (kernelResults && results && *matchCount > 0)
	{
		__try
		{
			RtlCopyMemory(results, kernelResults, (SIZE_T)*matchCount * sizeof(UINT64));
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			DbgPrintEx(0, 0, "KsDumper: Exception copying pattern results to user buffer.\n");
		}
	}

	if (kernelResults)
		ExFreePoolWithTag(kernelResults, MEMSCAN_POOL_TAG);
	ExFreePoolWithTag(kernelPattern, MEMSCAN_POOL_TAG);
	ExFreePoolWithTag(readBuffer, MEMSCAN_POOL_TAG);
	ObDereferenceObject(targetProcess);
	return STATUS_SUCCESS;
}

// ---- Il2Cpp Metadata Dump ----

// Il2Cpp metadata header magic: 0xFAB11BAF (little-endian: AF 1B B1 FA)
// Layout: UINT32 magic (offset 0), INT32 version (offset 4), ... metadata follows
#define IL2CPP_METADATA_MAGIC 0xFAB11BAF

NTSTATUS DumpIl2CppMetadata(HANDLE processId, PVOID bufferAddress, INT32 bufferSize, PINT32 metadataSize, PUINT64 metadataAddress)
{
	PEPROCESS targetProcess = NULL;
	KAPC_STATE state;
	*metadataSize = 0;
	*metadataAddress = 0;

	if (!NT_SUCCESS(PsLookupProcessByProcessId(processId, &targetProcess)))
		return STATUS_INVALID_PARAMETER;

	// Search for the magic in 64KB chunks
	PUCHAR readBuffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, SCAN_CHUNK_SIZE, MEMSCAN_POOL_TAG);
	if (!readBuffer)
	{
		ObDereferenceObject(targetProcess);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	KeStackAttachProcess(targetProcess, &state);

	__try
	{
		ULONG_PTR address = 0;
		UINT64 foundAddress = 0;
		BOOLEAN found = FALSE;

		// Phase 1: Find the magic
		while (address < MAX_USER_ADDRESS && !found)
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

			if (mbi.State == MEM_COMMIT && IsReadableProtect(mbi.Protect))
			{
				SIZE_T scanSize = regionSize;
				if (scanSize > 0x10000000)
					scanSize = 0x10000000;

				SIZE_T offset = 0;
				while (offset < scanSize && !found)
				{
					SIZE_T chunkSize = SCAN_CHUNK_SIZE;
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

					if (NT_SUCCESS(readStatus) && bytesRead >= 4)
					{
						for (SIZE_T i = 0; i <= bytesRead - 4; i += 4) // aligned search
						{
							if (*(UINT32*)&readBuffer[i] == IL2CPP_METADATA_MAGIC)
							{
								foundAddress = (UINT64)(regionBase + offset + i);
								found = TRUE;
								break;
							}
						}
					}

					offset += chunkSize;
				}
			}

			ULONG_PTR nextAddress = regionBase + regionSize;
			if (nextAddress <= address)
				break;
			address = nextAddress;
		}

		if (!found)
		{
			KeUnstackDetachProcess(&state);
			ExFreePoolWithTag(readBuffer, MEMSCAN_POOL_TAG);
			ObDereferenceObject(targetProcess);
			return STATUS_NOT_FOUND;
		}

		*metadataAddress = foundAddress;

		// Read the header to get metadata size.
		// The Il2CppGlobalMetadataHeader has: magic(4), version(4), ... then various offset/size pairs.
		// A simple heuristic: the metadata size can be derived from scanning the header fields.
		// For now, read 64 bytes of header to determine the size.
		UINT8 header[64];
		SIZE_T headerRead = 0;
		NTSTATUS hdrStatus = MmCopyVirtualMemory(
			targetProcess,
			(PVOID)(ULONG_PTR)foundAddress,
			PsGetCurrentProcess(),
			header,
			sizeof(header),
			KernelMode,
			&headerRead);

		if (!NT_SUCCESS(hdrStatus) || headerRead < 64)
		{
			KeUnstackDetachProcess(&state);
			ExFreePoolWithTag(readBuffer, MEMSCAN_POOL_TAG);
			ObDereferenceObject(targetProcess);
			return STATUS_UNSUCCESSFUL;
		}

		// Il2Cpp metadata: the total file size is typically the last offset + last size in the header.
		// For simplicity, use a heuristic: scan the header for the largest offset+size pair.
		// The header has pairs of (INT32 offset, INT32 size) starting at offset 8.
		INT32 maxEnd = 0;
		for (INT32 i = 8; i + 8 <= (INT32)headerRead; i += 8)
		{
			INT32 off = *(INT32*)&header[i];
			INT32 sz = *(INT32*)&header[i + 4];
			if (off > 0 && sz > 0 && off < MAX_REGION_SCAN_SIZE && sz < MAX_REGION_SCAN_SIZE &&
				off + sz > maxEnd && off + sz < MAX_REGION_SCAN_SIZE)
			{
				maxEnd = off + sz;
			}
		}

		if (maxEnd < 64)
			maxEnd = 64; // minimum

		INT32 totalSize = maxEnd;
		*metadataSize = totalSize;

		// Phase 2: Copy the metadata into kernel buffer (user buffer is invalid while attached)
		if (bufferAddress != NULL && bufferSize > 0)
		{
			INT32 copySize = totalSize < bufferSize ? totalSize : bufferSize;
			if (copySize > 16 * 1024 * 1024)
				copySize = 16 * 1024 * 1024;

			PVOID metaKernelBuf = ExAllocatePoolWithTag(NonPagedPool, (SIZE_T)copySize, MEMSCAN_POOL_TAG);
			if (metaKernelBuf)
			{
				SIZE_T copiedTotal = 0;
				INT32 remaining = copySize;
				ULONG_PTR srcAddr = (ULONG_PTR)foundAddress;
				ULONG_PTR dstAddr = (ULONG_PTR)metaKernelBuf;

				while (remaining > 0)
				{
					SIZE_T toRead = remaining > SCAN_CHUNK_SIZE ? SCAN_CHUNK_SIZE : (SIZE_T)remaining;
					SIZE_T bytesRead = 0;

					NTSTATUS readStatus = MmCopyVirtualMemory(
						targetProcess,
						(PVOID)srcAddr,
						PsGetCurrentProcess(),
						(PVOID)dstAddr,
						toRead,
						KernelMode,
						&bytesRead);

					if (!NT_SUCCESS(readStatus) || bytesRead == 0)
						break;

					copiedTotal += bytesRead;
					srcAddr += bytesRead;
					dstAddr += bytesRead;
					remaining -= (INT32)bytesRead;
				}

				KeUnstackDetachProcess(&state);

				// Now in caller's context — copy kernel buffer to user buffer
				__try
				{
					RtlCopyMemory(bufferAddress, metaKernelBuf, copiedTotal);
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					DbgPrintEx(0, 0, "KsDumper: Exception copying Il2Cpp metadata to user buffer.\n");
				}

				ExFreePoolWithTag(metaKernelBuf, MEMSCAN_POOL_TAG);
				ExFreePoolWithTag(readBuffer, MEMSCAN_POOL_TAG);
				ObDereferenceObject(targetProcess);
				return STATUS_SUCCESS;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrintEx(0, 0, "KsDumper: Exception in DumpIl2CppMetadata.\n");
	}

	KeUnstackDetachProcess(&state);
	ExFreePoolWithTag(readBuffer, MEMSCAN_POOL_TAG);
	ObDereferenceObject(targetProcess);
	return STATUS_SUCCESS;
}
