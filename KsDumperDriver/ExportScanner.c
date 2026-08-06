#include "ExportScanner.h"
#include "ProcessLister.h"
#include "NTUndocumented.h"

#define EXPORT_POOL_TAG 'ExpK'
#define MIN_USER_ADDRESS ((ULONG_PTR)0x10000)
#define MAX_USER_ADDRESS ((ULONG_PTR)0x00007FFFFFFEFFFF)

// Simplified export directory for kernel parsing
typedef struct _IMAGE_EXPORT_DIRECTORY_K {
	UINT32 Characteristics;
	UINT32 TimeDateStamp;
	USHORT MajorVersion;
	USHORT MinorVersion;
	UINT32 Name;
	UINT32 Base;
	UINT32 NumberOfFunctions;
	UINT32 NumberOfNames;
	UINT32 AddressOfFunctions;
	UINT32 AddressOfNames;
	UINT32 AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY_K, *PIMAGE_EXPORT_DIRECTORY_K;

#pragma pack(push, 1)
typedef struct _EXPORT_ENTRY_PACKED {
	UINT64 Address;
	CHAR   Name[64];
	USHORT Ordinal;
} EXPORT_ENTRY_PACKED, *PEXPORT_ENTRY_PACKED;

typedef struct _MODULE_EXPORTS_HEADER {
	UINT64 ModuleBase;
	WCHAR  ModuleName[64];
	INT32  EntryCount;
} MODULE_EXPORTS_HEADER, *PMODULE_EXPORTS_HEADER;
#pragma pack(pop)

static BOOLEAN SanitizeUserPointerExport(PVOID pointer, SIZE_T size)
{
	return (ULONG_PTR)pointer > MIN_USER_ADDRESS && (ULONG_PTR)pointer < MAX_USER_ADDRESS &&
		((ULONG_PTR)pointer + size) < MAX_USER_ADDRESS;
}

// Parse a single module's export table and append entries to the output buffer.
// Returns the number of bytes written, or the required size if buffer is too small.
static INT32 ScanModuleExports(PVOID moduleBase, INT32 processId, PVOID outputBuffer, INT32 bufferRemaining, PINT32 entryCountOut)
{
	*entryCountOut = 0;

	__try
	{
		PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
		if (dosHeader->e_magic != 0x5A4D)
			return 0;

		PPE_HEADER peHeader = (PPE_HEADER)((CHAR*)dosHeader + dosHeader->e_lfanew);
		if (*(UINT32*)peHeader != 0x00004550)
			return 0;

		// Export directory is data directory [0]
		UINT32 exportDirRVA = 0;
		UINT32 exportDirSize = 0;

		// Data directory offset: PE sig(4) + FileHeader(20) + OptionalHeader start
		// For PE32+: data dir at offset 112 from optional header start
		// For PE32:  data dir at offset 96 from optional header start
		CHAR* optHeader = (CHAR*)&peHeader->Magic;
		USHORT magic = peHeader->Magic;

		if (magic == 0x20b) // PE32+
		{
			UINT32* dd = (UINT32*)(optHeader + 112); // DataDirectory[0]
			exportDirRVA = dd[0];
			exportDirSize = dd[1];
		}
		else if (magic == 0x10b) // PE32
		{
			UINT32* dd = (UINT32*)(optHeader + 96);
			exportDirRVA = dd[0];
			exportDirSize = dd[1];
		}
		else
			return 0;

		if (exportDirRVA == 0 || exportDirSize == 0)
			return 0;

		PIMAGE_EXPORT_DIRECTORY_K exportDir = (PIMAGE_EXPORT_DIRECTORY_K)((CHAR*)moduleBase + exportDirRVA);

		if (!SanitizeUserPointerExport(exportDir, sizeof(IMAGE_EXPORT_DIRECTORY_K)))
			return 0;

		if (exportDir->NumberOfNames == 0 || exportDir->NumberOfFunctions == 0)
			return 0;

		// Cap to prevent excessive enumeration
		UINT32 numNames = exportDir->NumberOfNames;
		if (numNames > 8192)
			numNames = 8192;

		UINT32* nameRVAs = (UINT32*)((CHAR*)moduleBase + exportDir->AddressOfNames);
		USHORT* ordinals = (USHORT*)((CHAR*)moduleBase + exportDir->AddressOfNameOrdinals);
		UINT32* funcRVAs = (UINT32*)((CHAR*)moduleBase + exportDir->AddressOfFunctions);

		INT32 headerSize = (INT32)sizeof(MODULE_EXPORTS_HEADER);
		INT32 entrySize = (INT32)sizeof(EXPORT_ENTRY_PACKED);
		INT32 totalNeeded = headerSize + (INT32)(numNames * entrySize);

		*entryCountOut = (INT32)numNames;

		if (bufferRemaining < totalNeeded)
			return totalNeeded;

		// Write module header (base address and name filled by caller)
		PMODULE_EXPORTS_HEADER modHeader = (PMODULE_EXPORTS_HEADER)outputBuffer;
		modHeader->ModuleBase = (UINT64)(ULONG_PTR)moduleBase;
		RtlZeroMemory(modHeader->ModuleName, sizeof(modHeader->ModuleName));
		modHeader->EntryCount = (INT32)numNames;

		// Write export entries
		PEXPORT_ENTRY_PACKED entries = (PEXPORT_ENTRY_PACKED)((CHAR*)outputBuffer + headerSize);

		for (UINT32 i = 0; i < numNames; i++)
		{
			__try
			{
				USHORT ordinal = ordinals[i];
				UINT32 funcRVA = funcRVAs[ordinal];

				entries[i].Address = (UINT64)(ULONG_PTR)((CHAR*)moduleBase + funcRVA);
				entries[i].Ordinal = ordinal + (USHORT)exportDir->Base;
				RtlZeroMemory(entries[i].Name, sizeof(entries[i].Name));

				CHAR* namePtr = (CHAR*)moduleBase + nameRVAs[i];
				if (SanitizeUserPointerExport(namePtr, 64))
				{
					INT32 j;
					for (j = 0; j < 63 && namePtr[j] != '\0'; j++)
						entries[i].Name[j] = namePtr[j];
					entries[i].Name[j] = '\0';
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				entries[i].Address = 0;
				entries[i].Name[0] = '\0';
				entries[i].Ordinal = 0;
			}
		}

		return totalNeeded;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return 0;
	}
}

NTSTATUS GetExportMap(HANDLE processId, PVOID outputBuffer, INT32 bufferSize, PINT32 requiredSize, PINT32 moduleCount)
{
	PEPROCESS targetProcess = NULL;
	KAPC_STATE state;
	*moduleCount = 0;
	*requiredSize = 0;

	if (!NT_SUCCESS(PsLookupProcessByProcessId(processId, &targetProcess)))
		return STATUS_INVALID_PARAMETER;

	PVOID kernelBuffer = NULL;
	INT32 kernelBufSize = bufferSize;

	if (kernelBufSize > 0 && outputBuffer != NULL)
	{
		if (kernelBufSize > 16 * 1024 * 1024)
			kernelBufSize = 16 * 1024 * 1024;
		kernelBuffer = ExAllocatePoolWithTag(NonPagedPool, (SIZE_T)kernelBufSize, EXPORT_POOL_TAG);
		if (!kernelBuffer)
		{
			ObDereferenceObject(targetProcess);
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		RtlZeroMemory(kernelBuffer, kernelBufSize);
	}

	KeStackAttachProcess(targetProcess, &state);

	__try
	{
		PPEB64 peb = (PPEB64)PsGetProcessPeb(targetProcess);
		if (peb && peb->Ldr)
		{
			PLIST_ENTRY head = &peb->Ldr->InLoadOrderModuleList;
			PLIST_ENTRY entry = head->Flink;

			INT32 offset = 0;
			INT32 modCount = 0;

			while (entry != head && modCount < 512)
			{
				PLDR_DATA_TABLE_ENTRY mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

				if (!SanitizeUserPointerExport(mod, sizeof(LDR_DATA_TABLE_ENTRY)) || !mod->DllBase)
				{
					entry = entry->Flink;
					continue;
				}

				INT32 entryCount = 0;
				INT32 bytesWritten = 0;

				if (kernelBuffer && offset < kernelBufSize)
				{
					PVOID bufPtr = (PVOID)((CHAR*)kernelBuffer + offset);
					INT32 remaining = kernelBufSize - offset;

					bytesWritten = ScanModuleExports(mod->DllBase, (INT32)(LONG_PTR)processId, bufPtr, remaining, &entryCount);
				}
				else
				{
					bytesWritten = ScanModuleExports(mod->DllBase, (INT32)(LONG_PTR)processId, NULL, 0, &entryCount);
					if (entryCount > 0)
						bytesWritten = (INT32)sizeof(MODULE_EXPORTS_HEADER) + entryCount * (INT32)sizeof(EXPORT_ENTRY_PACKED);
				}

				if (entryCount > 0 && bytesWritten > 0)
				{
					if (kernelBuffer && offset < kernelBufSize)
					{
						PMODULE_EXPORTS_HEADER modHeader = (PMODULE_EXPORTS_HEADER)((CHAR*)kernelBuffer + offset);
						if (mod->BaseDllName.Buffer && mod->BaseDllName.Length > 0)
						{
							INT32 copyLen = mod->BaseDllName.Length < 63 * sizeof(WCHAR) ? mod->BaseDllName.Length : 63 * sizeof(WCHAR);
							RtlCopyMemory(modHeader->ModuleName, mod->BaseDllName.Buffer, copyLen);
						}
					}

					offset += bytesWritten;
					modCount++;
				}

				entry = entry->Flink;
			}

			*requiredSize = offset;
			*moduleCount = modCount;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrintEx(0, 0, "KsDumper: Exception during export map scan.\n");
	}

	KeUnstackDetachProcess(&state);

	if (kernelBuffer && outputBuffer)
	{
		INT32 copySize = *requiredSize < kernelBufSize ? *requiredSize : kernelBufSize;
		if (copySize > 0)
		{
			__try
			{
				RtlCopyMemory(outputBuffer, kernelBuffer, copySize);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				DbgPrintEx(0, 0, "KsDumper: Exception copying export map to user buffer.\n");
			}
		}
	}

	if (kernelBuffer)
		ExFreePoolWithTag(kernelBuffer, EXPORT_POOL_TAG);

	ObDereferenceObject(targetProcess);
	return STATUS_SUCCESS;
}
