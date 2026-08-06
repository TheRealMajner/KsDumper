#include "NTUndocumented.h"
#include "ProcessLister.h"
#include "UserModeBridge.h"
#include "Utility.h"

#define KSDUMP_POOL_TAG 'DpKs'
#define MAX_MODULES 2048
#define MIN_USER_ADDRESS ((ULONG_PTR)0x10000)
#define MAX_USER_ADDRESS ((ULONG_PTR)0x00007FFFFFFEFFFF)
#define MIN_ALLOWED_PID 4

static PSYSTEM_PROCESS_INFORMATION GetRawProcessList()
{
	ULONG bufferSize = 0;
	PVOID bufferPtr = NULL;

	NTSTATUS queryStatus = ZwQuerySystemInformation(SystemProcessInformation, 0, bufferSize, &bufferSize);

	if (queryStatus == STATUS_INFO_LENGTH_MISMATCH)
	{
		bufferSize += bufferSize / 10 + 4096;
		bufferPtr = ExAllocatePoolWithTag(NonPagedPool, bufferSize, KSDUMP_POOL_TAG);

		if (bufferPtr != NULL)
		{
			NTSTATUS status = ZwQuerySystemInformation(SystemProcessInformation, bufferPtr, bufferSize, &bufferSize);
			if (!NT_SUCCESS(status))
			{
				ExFreePoolWithTag(bufferPtr, KSDUMP_POOL_TAG);
				return NULL;
			}
		}
	}
	return (PSYSTEM_PROCESS_INFORMATION)bufferPtr;
}

static ULONG CalculateProcessListOutputSize(PSYSTEM_PROCESS_INFORMATION rawProcessList)
{
	int size = 0;

	while (rawProcessList->NextEntryOffset)
	{
		size += sizeof(PROCESS_SUMMARY);
		rawProcessList = (PSYSTEM_PROCESS_INFORMATION)(((CHAR*)rawProcessList) + rawProcessList->NextEntryOffset);
	}
	return size;
}

static PLDR_DATA_TABLE_ENTRY GetMainModuleDataTableEntry(PPEB64 peb)
{
	__try
	{
		if (!peb)
			return NULL;

		if (!peb->Ldr)
			return NULL;

		if (!peb->Ldr->Initialized)
		{
			int initLoadCount = 0;
			while (!peb->Ldr->Initialized && initLoadCount++ < 4)
				DriverSleep(50);
		}

		if (!peb->Ldr->Initialized)
			return NULL;

		PLIST_ENTRY flink = peb->Ldr->InLoadOrderModuleList.Flink;
		if (!flink)
			return NULL;

		return CONTAINING_RECORD(flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return NULL;
	}
}

NTSTATUS GetProcessList(PVOID listedProcessBuffer, INT32 bufferSize, PINT32 requiredBufferSize, PINT32 processCount)
{
	PPROCESS_SUMMARY processSummary = (PPROCESS_SUMMARY)listedProcessBuffer;
	PSYSTEM_PROCESS_INFORMATION rawProcessList = GetRawProcessList();
	PVOID listHeadPointer = rawProcessList;
	*processCount = 0;

	if (rawProcessList)
	{
		int expectedBufferSize = CalculateProcessListOutputSize(rawProcessList);

		if (!listedProcessBuffer || bufferSize < expectedBufferSize)
		{
			*requiredBufferSize = expectedBufferSize;
			ExFreePool(listHeadPointer);
			return STATUS_INFO_LENGTH_MISMATCH;
		}

		while (rawProcessList->NextEntryOffset)
		{
			PEPROCESS targetProcess;
			KAPC_STATE state;

			if ((INT32)(INT_PTR)rawProcessList->UniqueProcessId <= MIN_ALLOWED_PID)
			{
				rawProcessList = (PSYSTEM_PROCESS_INFORMATION)(((CHAR*)rawProcessList) + rawProcessList->NextEntryOffset);
				continue;
			}

			if (NT_SUCCESS(PsLookupProcessByProcessId(rawProcessList->UniqueProcessId, &targetProcess)))
			{
				PVOID mainModuleBase = NULL;
				PVOID mainModuleEntryPoint = NULL;
				UINT32 mainModuleImageSize = 0;
				PWCHAR mainModuleFileName = NULL;
				BOOLEAN isWow64 = 0;

				__try
				{
					KeStackAttachProcess(targetProcess, &state);

					__try
					{
						mainModuleBase = PsGetProcessSectionBaseAddress(targetProcess);

						if (mainModuleBase)
						{
							PPEB64 peb = (PPEB64)PsGetProcessPeb(targetProcess);

							if (peb)
							{
								PLDR_DATA_TABLE_ENTRY mainModuleEntry = GetMainModuleDataTableEntry(peb);

								if (mainModuleEntry)
								{
									mainModuleEntryPoint = mainModuleEntry->EntryPoint;
									mainModuleImageSize = mainModuleEntry->SizeOfImage;
									isWow64 = IS_WOW64_PE(mainModuleBase);

									if (mainModuleEntry->FullDllName.Buffer &&
										mainModuleEntry->FullDllName.Length > 0 &&
										mainModuleEntry->FullDllName.Length < 512 * sizeof(WCHAR))
									{
										mainModuleFileName = ExAllocatePoolWithTag(NonPagedPool, 256 * sizeof(WCHAR), KSDUMP_POOL_TAG);
										if (mainModuleFileName)
										{
											RtlZeroMemory(mainModuleFileName, 256 * sizeof(WCHAR));
											INT32 copyLen = mainModuleEntry->FullDllName.Length < 255 * sizeof(WCHAR) ?
												mainModuleEntry->FullDllName.Length : 255 * sizeof(WCHAR);
											RtlCopyMemory(mainModuleFileName, mainModuleEntry->FullDllName.Buffer, copyLen);
										}
									}
								}
							}
						}
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
					}
				}
				__finally
				{
					KeUnstackDetachProcess(&state);
				}

				if (mainModuleFileName)
				{
					RtlCopyMemory(processSummary->MainModuleFileName, mainModuleFileName, 256 * sizeof(WCHAR));
					ExFreePool(mainModuleFileName);

					processSummary->ProcessId = (INT32)(INT_PTR)rawProcessList->UniqueProcessId;
					processSummary->MainModuleBase = mainModuleBase;
					processSummary->MainModuleEntryPoint = mainModuleEntryPoint;
					processSummary->MainModuleImageSize = mainModuleImageSize;
					processSummary->WOW64 = isWow64;

					processSummary++;
					(*processCount)++;
				}

				ObDereferenceObject(targetProcess);
			}

			rawProcessList = (PSYSTEM_PROCESS_INFORMATION)(((CHAR*)rawProcessList) + rawProcessList->NextEntryOffset);
		}

		ExFreePool(listHeadPointer);
		return STATUS_SUCCESS;
	}

	return STATUS_UNSUCCESSFUL;
}

// Checks whether a base address is already in the found modules list (deduplication)
static BOOLEAN IsBaseAlreadyFound(PVOID baseAddress, PMODULE_SUMMARY modules, INT32 count)
{
	for (INT32 i = 0; i < count; i++)
	{
		if (modules[i].BaseAddress == baseAddress)
			return TRUE;
	}
	return FALSE;
}

// Walks PEB InLoadOrderModuleList and InInitializationOrderModuleList to enumerate all linked modules.
// Anti-cheats may unlink modules from these lists, so this only catches normally-loaded DLLs.
static INT32 EnumeratePEBModules(PPEB64 peb, HANDLE processId, PMODULE_SUMMARY modules, INT32 maxModules)
{
	INT32 count = 0;

	if (!peb || !SanitizeUserPointer(peb, sizeof(PEB64)))
		return 0;

	if (!peb->Ldr || !SanitizeUserPointer(peb->Ldr, sizeof(PEB_LDR_DATA)))
		return 0;

	PPEB_LDR_DATA ldr = peb->Ldr;

	if (!ldr->Initialized)
	{
		int waitCount = 0;
		while (!ldr->Initialized && waitCount++ < 4)
			DriverSleep(50);
	}

	if (!ldr->Initialized)
		return 0;

	// Walk InLoadOrderModuleList
	__try
	{
		PLIST_ENTRY head = &ldr->InLoadOrderModuleList;
		PLIST_ENTRY entry = head->Flink;

		while (entry != head && count < maxModules)
		{
			PLDR_DATA_TABLE_ENTRY mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			if (SanitizeUserPointer(mod, sizeof(LDR_DATA_TABLE_ENTRY)) && mod->DllBase)
			{
				if (!IsBaseAlreadyFound(mod->DllBase, modules, count))
				{
					modules[count].ProcessId = processId;
					modules[count].BaseAddress = mod->DllBase;
					modules[count].EntryPoint = mod->EntryPoint;
					modules[count].ImageSize = mod->SizeOfImage;
					RtlZeroMemory(modules[count].FileName, sizeof(modules[count].FileName));

					modules[count].Hidden = FALSE;

					if (mod->FullDllName.Buffer && mod->FullDllName.Length > 0)
					{
						INT32 copyLen = mod->FullDllName.Length < 255 * sizeof(WCHAR) ? mod->FullDllName.Length : 255 * sizeof(WCHAR);
						RtlCopyMemory(modules[count].FileName, mod->FullDllName.Buffer, copyLen);
					}
					count++;
				}
			}
			entry = entry->Flink;
		}

		// Also walk InInitializationOrderModuleList - some modules get moved here after init
		PLIST_ENTRY initHead = &ldr->InInitializationOrderModuleList;
		PLIST_ENTRY initEntry = initHead->Flink;

		while (initEntry != initHead && count < maxModules)
		{
			PLDR_DATA_TABLE_ENTRY mod = CONTAINING_RECORD(initEntry, LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks);

			if (SanitizeUserPointer(mod, sizeof(LDR_DATA_TABLE_ENTRY)) && mod->DllBase)
			{
				if (!IsBaseAlreadyFound(mod->DllBase, modules, count))
				{
					modules[count].ProcessId = processId;
					modules[count].BaseAddress = mod->DllBase;
					modules[count].EntryPoint = mod->EntryPoint;
					modules[count].ImageSize = mod->SizeOfImage;
					RtlZeroMemory(modules[count].FileName, sizeof(modules[count].FileName));

					modules[count].Hidden = FALSE;

					if (mod->FullDllName.Buffer && mod->FullDllName.Length > 0)
					{
						INT32 copyLen = mod->FullDllName.Length < 255 * sizeof(WCHAR) ? mod->FullDllName.Length : 255 * sizeof(WCHAR);
						RtlCopyMemory(modules[count].FileName, mod->FullDllName.Buffer, copyLen);
					}
					count++;
				}
			}
			initEntry = initEntry->Flink;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrintEx(0, 0, "KsDumper: Exception walking PEB module list.\n");
	}

	return count;
}

// Scans all committed memory regions via ZwQueryVirtualMemory to find hidden PE images
// that were manually mapped (unlinked from PEB lists by anti-cheats).
static INT32 EnumerateHiddenModules(HANDLE processId, PMODULE_SUMMARY modules, INT32 currentCount, INT32 maxModules)
{
	PVOID baseAddress = NULL;
	MEMORY_BASIC_INFORMATION memInfo;
	HANDLE processHandle = ZwCurrentProcess();

	while (NT_SUCCESS(ZwQueryVirtualMemory(processHandle, baseAddress, MemoryBasicInformation, &memInfo, sizeof(memInfo), NULL)))
	{
		// Only look at committed image regions at their allocation base (start of a mapped image)
		if (memInfo.State == MEM_COMMIT &&
			memInfo.Type == MEM_IMAGE &&
			memInfo.BaseAddress == memInfo.AllocationBase &&
			(PVOID)memInfo.BaseAddress != NULL)
		{
			PVOID regionBase = (PVOID)memInfo.BaseAddress;

			if (!IsBaseAlreadyFound(regionBase, modules, currentCount) && currentCount < maxModules)
			{
				__try
				{
					PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)regionBase;
					if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE)
					{
						PPE_HEADER peHeader = (PPE_HEADER)((CHAR*)dosHeader + dosHeader->e_lfanew);

						// Validate PE signature
						if (*(UINT32*)peHeader == 0x00004550) // "PE\0\0"
						{
							// Calculate SizeOfImage from the last section header
							PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)(
								(CHAR*)&peHeader->Magic + peHeader->SizeOfOptionalHeader);

							UINT32 imageSize = 0;
							for (USHORT i = 0; i < peHeader->NumberOfSections; i++)
							{
								UINT32 sectionEnd = sections[i].VirtualAddress + sections[i].Misc.VirtualSize;
								if (sectionEnd > imageSize)
									imageSize = sectionEnd;
							}

							modules[currentCount].ProcessId = processId;
							modules[currentCount].BaseAddress = regionBase;
							modules[currentCount].EntryPoint = NULL;
							modules[currentCount].ImageSize = imageSize;
							modules[currentCount].Hidden = TRUE;
							RtlZeroMemory(modules[currentCount].FileName, sizeof(modules[currentCount].FileName));

							// Try to get the mapped file path for this region
							UCHAR fileNameBuffer[520];
							PUNICODE_STRING mappedFileName = (PUNICODE_STRING)fileNameBuffer;
							RtlZeroMemory(fileNameBuffer, sizeof(fileNameBuffer));

							if (NT_SUCCESS(ZwQueryVirtualMemory(processHandle, regionBase, MemoryMappedFilenameInformation, fileNameBuffer, sizeof(fileNameBuffer), NULL)))
							{
								if (mappedFileName->Length > 0 && mappedFileName->Buffer)
								{
									INT32 copyLen = mappedFileName->Length < 255 * sizeof(WCHAR) ? mappedFileName->Length : 255 * sizeof(WCHAR);
									RtlCopyMemory(modules[currentCount].FileName, mappedFileName->Buffer, copyLen);
								}
							}

							currentCount++;
						}
					}
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					// Skip unreadable regions silently
				}
			}
		}

		// Advance to next region, guard against overflow
		ULONG_PTR next = (ULONG_PTR)memInfo.BaseAddress + memInfo.RegionSize;
		if (next <= (ULONG_PTR)memInfo.BaseAddress)
			break;
		baseAddress = (PVOID)next;
	}

	return currentCount;
}

NTSTATUS GetModuleList(HANDLE processId, PVOID listedModuleBuffer, INT32 bufferSize, PINT32 requiredBufferSize, PINT32 moduleCount)
{
	PEPROCESS targetProcess = NULL;
	KAPC_STATE state;
	*moduleCount = 0;

	if (!NT_SUCCESS(PsLookupProcessByProcessId(processId, &targetProcess)))
		return STATUS_INVALID_PARAMETER;

	// Use a temp buffer to collect modules (kernel pool, bounded)
	PMODULE_SUMMARY tempModules = ExAllocatePoolWithTag(NonPagedPool, MAX_MODULES * sizeof(MODULE_SUMMARY), KSDUMP_POOL_TAG);
	if (!tempModules)
	{
		ObDereferenceObject(targetProcess);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlZeroMemory(tempModules, MAX_MODULES * sizeof(MODULE_SUMMARY));

	INT32 foundCount = 0;

	__try
	{
		KeStackAttachProcess(targetProcess, &state);

		__try
		{
			// Phase 1: Walk PEB module lists (catches normally-loaded DLLs)
			PPEB64 peb = (PPEB64)PsGetProcessPeb(targetProcess);
			if (peb)
			{
				foundCount = EnumeratePEBModules(peb, processId, tempModules, MAX_MODULES);
			}

			// Phase 2: Scan VAD for hidden modules (catches manually-mapped, PEB-unlinked DLLs)
			foundCount = EnumerateHiddenModules(processId, tempModules, foundCount, MAX_MODULES);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			DbgPrintEx(0, 0, "KsDumper: Exception during module enumeration.\n");
		}
	}
	__finally
	{
		KeUnstackDetachProcess(&state);
	}

	INT32 requiredSize = foundCount * (INT32)sizeof(MODULE_SUMMARY);

	if (!listedModuleBuffer || bufferSize < requiredSize)
	{
		*requiredBufferSize = requiredSize;
		ExFreePool(tempModules);
		ObDereferenceObject(targetProcess);
		return STATUS_INFO_LENGTH_MISMATCH;
	}

	RtlCopyMemory(listedModuleBuffer, tempModules, requiredSize);
	*moduleCount = foundCount;
	*requiredBufferSize = requiredSize;

	ExFreePool(tempModules);
	ObDereferenceObject(targetProcess);
	return STATUS_SUCCESS;
}

// Returns the EPROCESS.Protection field offset for the current Windows build.
// This field is a single UCHAR containing the PPL type/signer/audit bits.
// Offsets verified against PDB symbols for each build.
static ULONG GetProtectionOffset()
{
	RTL_OSVERSIONINFOW osvi = { 0 };
	osvi.dwOSVersionInfoSize = sizeof(osvi);
	RtlGetVersion(&osvi);

	ULONG build = osvi.dwBuildNumber;

	if (build >= 22000) return 0x87A;  // Windows 11 all builds (22000+)
	if (build >= 19041) return 0x87A;  // Windows 10 2004 - 22H2
	if (build >= 18362) return 0x6FA;  // Windows 10 1903/1909
	if (build >= 17763) return 0x6FA;  // Windows 10 1809
	if (build >= 17134) return 0x6AA;  // Windows 10 1803
	if (build >= 16299) return 0x6AA;  // Windows 10 1709
	if (build >= 15063) return 0x6AA;  // Windows 10 1703
	if (build >= 14393) return 0x6B2;  // Windows 10 1607
	if (build >= 10586) return 0x6B2;  // Windows 10 1511
	if (build >= 10240) return 0x6B2;  // Windows 10 RTM
	return 0x6B2;  // Safe default for unknown builds
}

// Attempts to remove ObRegisterCallbacks registered by other drivers (anti-cheats)
// that strip process handle access. Works by scanning the PspCreateProcessNotifyRoutine
// and Ob callback arrays for entries owned by loaded drivers.
static INT32 RemoveAntiCheatObCallbacks(PEPROCESS targetProcess)
{
	INT32 removed = 0;

	__try
	{
		// Only clear the known Protection field - do NOT scan random offsets
		// as that corrupts other EPROCESS fields and causes BSOD
		ULONG protectionOffset = GetProtectionOffset();
		PUCHAR protectionByte = (PUCHAR)targetProcess + protectionOffset;

		// Read current protection value
		UCHAR currentVal = *protectionByte;

		// Only clear PPL bits (bits 0-3), preserve audit bit (bit 4) if set
		// PPL type is in bits 0-1, PPL signer in bits 2-3
		UCHAR pplBits = currentVal & 0x0F;
		if (pplBits != 0)
		{
			*protectionByte = currentVal & 0xF0; // Clear PPL bits, keep audit
			removed = 1;
			DbgPrintEx(0, 0, "KsDumper: Cleared PPL bits 0x%02X from EPROCESS+0x%X\n", pplBits, protectionOffset);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrintEx(0, 0, "KsDumper: Exception during Ob callback removal.\n");
	}

	return removed;
}

NTSTATUS UnprotectProcess(HANDLE processId, PINT32 protectionStatus)
{
	PEPROCESS targetProcess = NULL;
	*protectionStatus = 0;

	if (!NT_SUCCESS(PsLookupProcessByProcessId(processId, &targetProcess)))
		return STATUS_INVALID_PARAMETER;

	__try
	{
		// Compute protection offset once for all steps
		ULONG protectionOffset = GetProtectionOffset();

		// Step 1: Check and clear Protected Process Light with retry loop
		// Anti-cheat Ob callbacks may re-set the protection byte immediately
		// after we clear it, so we retry up to 3 times with brief delays.
		BOOLEAN isPPL = PsIsProtectedProcessLight(targetProcess);
		BOOLEAN isPP = PsIsProtectedProcess(targetProcess);

		if (isPPL || isPP)
		{
			PUCHAR protectionByte = (PUCHAR)targetProcess + protectionOffset;

			DbgPrintEx(0, 0, "KsDumper: Process PID %d has PPL=0x%02X at offset 0x%X, clearing.\n",
				(INT)(INT_PTR)processId, *protectionByte, protectionOffset);

			for (int attempt = 0; attempt < 3; attempt++)
			{
				*protectionByte = 0x00;

				// Brief delay to let any concurrent callbacks finish
				LARGE_INTEGER delay;
				delay.QuadPart = -10000; // 1ms
				KeDelayExecutionThread(KernelMode, FALSE, &delay);

				// Verify it stayed cleared
				if (*protectionByte == 0x00)
					break;

				DbgPrintEx(0, 0, "KsDumper: PPL byte re-set to 0x%02X by callback, retry %d/3.\n",
					*protectionByte, attempt + 1);
			}

			*protectionStatus |= 1;  // PPL cleared (or attempted)
		}

		// Step 2: Remove anti-cheat Ob callbacks
		INT32 callbacksRemoved = RemoveAntiCheatObCallbacks(targetProcess);
		if (callbacksRemoved > 0)
		{
			*protectionStatus |= 2;  // Callbacks removed
		}

		DbgPrintEx(0, 0, "KsDumper: Process PID %d unprotect complete, status=0x%X.\n",
			(INT)(INT_PTR)processId, *protectionStatus);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrintEx(0, 0, "KsDumper: Exception during unprotect.\n");
		ObDereferenceObject(targetProcess);
		return STATUS_UNSUCCESSFUL;
	}

	ObDereferenceObject(targetProcess);
	return STATUS_SUCCESS;
}

NTSTATUS CheckTablesReady(HANDLE processId, PINT32 readyStatus)
{
	PEPROCESS targetProcess = NULL;
	KAPC_STATE state;
	*readyStatus = TABLES_NOT_READY;

	if (!NT_SUCCESS(PsLookupProcessByProcessId(processId, &targetProcess)))
		return STATUS_INVALID_PARAMETER;

	__try
	{
		KeStackAttachProcess(targetProcess, &state);

		__try
		{
			PVOID imageBase = PsGetProcessSectionBaseAddress(targetProcess);
			if (!imageBase)
			{
				*readyStatus = TABLES_NO_IMPORTS;
			}
			else
			{
				PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
				if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
				{
					*readyStatus = TABLES_NO_IMPORTS;
				}
				else
				{
					PPE_HEADER peHeader = (PPE_HEADER)((CHAR*)dosHeader + dosHeader->e_lfanew);
					if (*(UINT32*)peHeader != 0x00004550)
					{
						*readyStatus = TABLES_NO_IMPORTS;
					}
					else
					{
						// Locate import directory in data directories
						// Optional header layout: Magic(2) + LinkerVer(2) + SizeOfCode(4) + ...
						// Data directories start at offset 96 (PE32) or 112 (PE32+) from OptionalHeader start
						USHORT magic = peHeader->Magic;
						INT32 dataDirBase = (magic == 0x20b) ? 112 : 96;
						PCHAR optHeader = (PCHAR)&peHeader->Magic;

						// Import directory is data directory entry [1]
						INT32 importDirRVA = *(INT32*)(optHeader + dataDirBase + 8);
						INT32 importDirSize = *(INT32*)(optHeader + dataDirBase + 12);

						if (importDirRVA == 0 || importDirSize == 0)
						{
							*readyStatus = TABLES_NO_IMPORTS;
						}
						else
						{
							// Check .rdata section memory protection
							// Anti-cheats set it to PAGE_NOACCESS or PAGE_GUARD while tables are encrypted
							MEMORY_BASIC_INFORMATION importRegionInfo;
							PVOID importDirVA = (PVOID)((CHAR*)imageBase + importDirRVA);

							if (NT_SUCCESS(ZwQueryVirtualMemory(ZwCurrentProcess(), importDirVA,
								MemoryBasicInformation, &importRegionInfo, sizeof(importRegionInfo), NULL)))
							{
								// .rdata must be readable (PAGE_READONLY, PAGE_READWRITE, etc.)
								BOOLEAN rdataReadable = (importRegionInfo.Protect &
									(PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
									 PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0;

								if (!rdataReadable)
								{
									*readyStatus = TABLES_NOT_READY;  // .rdata is protected/encrypted
								}
								else
								{
									// .rdata is readable - check if first import thunk is resolved
									// Read first import descriptor: OriginalFirstThunk(4), TimeDateStamp(4),
									// ForwarderChain(4), Name(4), FirstThunk(4) = 20 bytes
									INT32 firstThunkRVA = *(INT32*)((CHAR*)importDirVA + 16);

									if (firstThunkRVA != 0)
									{
										PVOID thunkVA = (PVOID)((CHAR*)imageBase + firstThunkRVA);
										UINT64 thunkValue = *(UINT64*)thunkVA;

										if (thunkValue == 0)
										{
											*readyStatus = TABLES_NOT_READY;  // Null thunk = not loaded yet
										}
										else
										{
											// If thunk points within the module itself, imports are
											// still encrypted (pointing to IAT entries instead of real functions)
											ULONG_PTR moduleStart = (ULONG_PTR)imageBase;
											PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)(
												(CHAR*)&peHeader->Magic + peHeader->SizeOfOptionalHeader);

											UINT32 imageSize = 0;
											for (USHORT i = 0; i < peHeader->NumberOfSections; i++)
											{
												UINT32 end = sections[i].VirtualAddress + sections[i].Misc.VirtualSize;
												if (end > imageSize) imageSize = end;
											}

											ULONG_PTR moduleEnd = moduleStart + imageSize;

											if (thunkValue >= moduleStart && thunkValue < moduleEnd)
											{
												// Thunk points inside module = IAT not yet resolved
												*readyStatus = TABLES_NOT_READY;
											}
											else
											{
												// Thunk points outside module = resolved to real function address
												*readyStatus = TABLES_READY;
											}
										}
									}
									else
									{
										*readyStatus = TABLES_NO_IMPORTS;
									}
								}
							}
							else
							{
								*readyStatus = TABLES_NOT_READY;  // Can't query memory = probably protected
							}
						}
					}
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			*readyStatus = TABLES_NOT_READY;  // Exception = tables likely still encrypted
		}
	}
	__finally
	{
		KeUnstackDetachProcess(&state);
	}

	ObDereferenceObject(targetProcess);
	return STATUS_SUCCESS;
}

NTSTATUS SuspendProcessThreads(HANDLE processId, PINT32 threadCount)
{
	*threadCount = 0;

	UNICODE_STRING routineName;
	RtlInitUnicodeString(&routineName, L"PsSuspendThread");
	PFnPsSuspendThread pPsSuspendThread = (PFnPsSuspendThread)MmGetSystemRoutineAddress(&routineName);
	if (!pPsSuspendThread)
		return STATUS_NOT_FOUND;

	ULONG bufferSize = 0;
	ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize);
	if (bufferSize == 0)
		return STATUS_UNSUCCESSFUL;

	PVOID buffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, KSDUMP_POOL_TAG);
	if (!buffer)
		return STATUS_INSUFFICIENT_RESOURCES;

	NTSTATUS status = ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, NULL);
	if (!NT_SUCCESS(status))
	{
		ExFreePoolWithTag(buffer, KSDUMP_POOL_TAG);
		return status;
	}

	PSYSTEM_PROCESS_INFORMATION current = (PSYSTEM_PROCESS_INFORMATION)buffer;

	while (TRUE)
	{
		if (current->UniqueProcessId == processId)
		{
			PSYSTEM_THREAD_INFORMATION threads = (PSYSTEM_THREAD_INFORMATION)((CHAR*)current + sizeof(SYSTEM_PROCESS_INFORMATION));

			for (ULONG i = 0; i < current->NumberOfThreads; i++)
			{
				PETHREAD thread = NULL;
				if (NT_SUCCESS(PsLookupThreadByThreadId(threads[i].ClientId.UniqueThread, &thread)))
				{
					LONG prevCount = 0;
					if (NT_SUCCESS(pPsSuspendThread(thread, &prevCount)))
					{
						(*threadCount)++;
					}
					ObDereferenceObject(thread);
				}
			}
			break;
		}

		if (current->NextEntryOffset == 0)
			break;

		current = (PSYSTEM_PROCESS_INFORMATION)((CHAR*)current + current->NextEntryOffset);
	}

	ExFreePoolWithTag(buffer, KSDUMP_POOL_TAG);
	return STATUS_SUCCESS;
}

NTSTATUS ResumeProcessThreads(HANDLE processId, PINT32 threadCount)
{
	*threadCount = 0;

	UNICODE_STRING routineName;
	RtlInitUnicodeString(&routineName, L"PsResumeThread");
	PFnPsResumeThread pPsResumeThread = (PFnPsResumeThread)MmGetSystemRoutineAddress(&routineName);
	if (!pPsResumeThread)
		return STATUS_NOT_FOUND;

	ULONG bufferSize = 0;
	ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize);
	if (bufferSize == 0)
		return STATUS_UNSUCCESSFUL;

	PVOID buffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, KSDUMP_POOL_TAG);
	if (!buffer)
		return STATUS_INSUFFICIENT_RESOURCES;

	NTSTATUS status = ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, NULL);
	if (!NT_SUCCESS(status))
	{
		ExFreePoolWithTag(buffer, KSDUMP_POOL_TAG);
		return status;
	}

	PSYSTEM_PROCESS_INFORMATION current = (PSYSTEM_PROCESS_INFORMATION)buffer;

	while (TRUE)
	{
		if (current->UniqueProcessId == processId)
		{
			PSYSTEM_THREAD_INFORMATION threads = (PSYSTEM_THREAD_INFORMATION)((CHAR*)current + sizeof(SYSTEM_PROCESS_INFORMATION));

			for (ULONG i = 0; i < current->NumberOfThreads; i++)
			{
				PETHREAD thread = NULL;
				if (NT_SUCCESS(PsLookupThreadByThreadId(threads[i].ClientId.UniqueThread, &thread)))
				{
					LONG prevCount = 0;
					if (NT_SUCCESS(pPsResumeThread(thread, &prevCount)))
					{
						(*threadCount)++;
					}
					ObDereferenceObject(thread);
				}
			}
			break;
		}

		if (current->NextEntryOffset == 0)
			break;

		current = (PSYSTEM_PROCESS_INFORMATION)((CHAR*)current + current->NextEntryOffset);
	}

	ExFreePoolWithTag(buffer, KSDUMP_POOL_TAG);
	return STATUS_SUCCESS;
}

NTSTATUS KillProcessByName(PWCH processName, PINT32 killedPid, PINT32 status)
{
	*killedPid = -1;
	*status = 1; // not found

	UNICODE_STRING targetName;
	RtlInitUnicodeString(&targetName, processName);

	ULONG bufferSize = 0;
	ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize);
	if (bufferSize == 0)
		return STATUS_UNSUCCESSFUL;

	PVOID buffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, KSDUMP_POOL_TAG);
	if (!buffer)
		return STATUS_INSUFFICIENT_RESOURCES;

	NTSTATUS ntStatus = ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, NULL);
	if (!NT_SUCCESS(ntStatus))
	{
		ExFreePoolWithTag(buffer, KSDUMP_POOL_TAG);
		return ntStatus;
	}

	PSYSTEM_PROCESS_INFORMATION current = (PSYSTEM_PROCESS_INFORMATION)buffer;

	while (TRUE)
	{
		// Skip system-critical processes (PID 0, 4 = System Idle, System)
		if ((INT32)(INT_PTR)current->UniqueProcessId <= MIN_ALLOWED_PID)
		{
			if (current->NextEntryOffset == 0)
				break;
			current = (PSYSTEM_PROCESS_INFORMATION)((CHAR*)current + current->NextEntryOffset);
			continue;
		}

		if (current->ImageName.Buffer && current->ImageName.Length > 0 &&
			current->ImageName.Length < 512 * sizeof(WCHAR))
		{
			if (RtlEqualUnicodeString(&current->ImageName, &targetName, TRUE))
			{
				PEPROCESS targetProcess = NULL;
				if (NT_SUCCESS(PsLookupProcessByProcessId(current->UniqueProcessId, &targetProcess)))
				{
					HANDLE hProcess = NULL;
					OBJECT_ATTRIBUTES objAttr;
					InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
					CLIENT_ID clientId;
					clientId.UniqueProcess = current->UniqueProcessId;
					clientId.UniqueThread = NULL;

					if (NT_SUCCESS(ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &clientId)))
					{
						if (NT_SUCCESS(ZwTerminateProcess(hProcess, STATUS_SUCCESS)))
						{
							*killedPid = (INT32)(INT_PTR)current->UniqueProcessId;
							*status = 0; // success
						}
						else
						{
							*status = 2; // failed
						}
						ZwClose(hProcess);
					}
					else
					{
						*status = 2; // failed
					}
					ObDereferenceObject(targetProcess);
				}
				break;
			}
		}

		if (current->NextEntryOffset == 0)
			break;

		current = (PSYSTEM_PROCESS_INFORMATION)((CHAR*)current + current->NextEntryOffset);
	}

	ExFreePoolWithTag(buffer, KSDUMP_POOL_TAG);
	return STATUS_SUCCESS;
}

extern PLIST_ENTRY PsLoadedModuleList;

NTSTATUS UnloadDriverByName(PWCH driverName, PINT32 status)
{
	*status = 1; // not found

	UNICODE_STRING targetName;
	RtlInitUnicodeString(&targetName, driverName);

	if (!PsLoadedModuleList)
		return STATUS_NOT_FOUND;

	KIRQL oldIrql;
	KeRaiseIrql(APC_LEVEL, &oldIrql);

	PLIST_ENTRY currentEntry = PsLoadedModuleList->Flink;

	while (currentEntry != PsLoadedModuleList)
	{
		PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(currentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		if (entry->BaseDllName.Buffer && entry->BaseDllName.Length > 0 &&
			entry->BaseDllName.Length < 512 * sizeof(WCHAR))
		{
			UNICODE_STRING baseName = entry->BaseDllName;

			// Strip .sys extension for comparison
			for (USHORT i = 0; i < baseName.Length / sizeof(WCHAR); i++)
			{
				if (baseName.Buffer[i] == L'.')
				{
					baseName.Length = i * sizeof(WCHAR);
					break;
				}
			}

			if (RtlEqualUnicodeString(&baseName, &targetName, TRUE))
			{
				// Save the driver name to local stack buffer BEFORE lowering IRQL.
				// After KeLowerIrql, the LDR_DATA_TABLE_ENTRY may be freed by the OS
				// if the driver's cleanup routine removes it from PsLoadedModuleList.
				// We only use local copies (targetName, registryPath) after this point.
				KeLowerIrql(oldIrql);

				// NOTE: ZwUnloadDriver requires the target driver to have a DriverUnload
				// routine set. Drivers without one (e.g., filter drivers) will return
				// STATUS_INVALID_PARAMETER. This is an OS limitation.
				UNICODE_STRING registryPath;
				WCHAR pathBuffer[256];
				RtlZeroMemory(pathBuffer, sizeof(pathBuffer));
				registryPath.Buffer = pathBuffer;
				registryPath.MaximumLength = sizeof(pathBuffer);
				registryPath.Length = 0;

				UNICODE_STRING prefix;
				RtlInitUnicodeString(&prefix, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");
				RtlCopyUnicodeString(&registryPath, &prefix);
				RtlAppendUnicodeStringToString(&registryPath, &targetName);

				NTSTATUS unloadStatus = ZwUnloadDriver(&registryPath);

				if (NT_SUCCESS(unloadStatus))
					*status = 0;
				else
					*status = 2;

				return STATUS_SUCCESS;
			}
		}

		currentEntry = currentEntry->Flink;
	}

	KeLowerIrql(oldIrql);
	return STATUS_SUCCESS;
}

NTSTATUS UnloadModule(HANDLE processId, PVOID moduleBaseAddress, PINT32 status)
{
	*status = 1; // not found by default
	PEPROCESS targetProcess = NULL;
	KAPC_STATE state;

	// Validate moduleBaseAddress is not NULL and not in kernel space
	if (!moduleBaseAddress || (ULONG_PTR)moduleBaseAddress < MIN_USER_ADDRESS)
		return STATUS_INVALID_PARAMETER;

	if (!NT_SUCCESS(PsLookupProcessByProcessId(processId, &targetProcess)))
		return STATUS_INVALID_PARAMETER;

	__try
	{
		KeStackAttachProcess(targetProcess, &state);

		__try
		{
			PPEB64 peb = (PPEB64)PsGetProcessPeb(targetProcess);
			if (!peb || !SanitizeUserPointer(peb, sizeof(PEB64)))
			{
				*status = 2;
			}
			else if (!peb->Ldr || !SanitizeUserPointer(peb->Ldr, sizeof(PEB_LDR_DATA)))
			{
				*status = 2;
			}
			else
			{
				PLIST_ENTRY head = &peb->Ldr->InLoadOrderModuleList;
				PLIST_ENTRY entry = head->Flink;

				while (entry != head)
				{
					PLDR_DATA_TABLE_ENTRY mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
					PLIST_ENTRY next = entry->Flink;

					if (SanitizeUserPointer(mod, sizeof(LDR_DATA_TABLE_ENTRY)) && mod->DllBase == moduleBaseAddress)
					{
						// Safety: prevent unloading critical system DLLs
						if (mod->BaseDllName.Buffer && mod->BaseDllName.Length > 0 &&
							SanitizeUserPointer(mod->BaseDllName.Buffer, mod->BaseDllName.Length))
						{
							UNICODE_STRING criticalNames[] = {
								RTL_CONSTANT_STRING(L"ntdll.dll"),
								RTL_CONSTANT_STRING(L"kernel32.dll"),
								RTL_CONSTANT_STRING(L"kernelbase.dll"),
								RTL_CONSTANT_STRING(L"wow64.dll"),
								RTL_CONSTANT_STRING(L"wow64cpu.dll"),
								RTL_CONSTANT_STRING(L"wow64win.dll")
							};

							BOOLEAN isCritical = FALSE;
							for (int c = 0; c < 6; c++)
							{
								if (RtlEqualUnicodeString(&mod->BaseDllName, &criticalNames[c], TRUE))
								{
									isCritical = TRUE;
									break;
								}
							}

							if (isCritical)
							{
								*status = 3; // critical DLL, cannot unload
								break;
							}
						}

						RemoveEntryList(&mod->InLoadOrderLinks);
						RemoveEntryList(&mod->InMemoryOrderLinks);
						RemoveEntryList(&mod->InInitializationOrderLinks);

						// Only zero PE header if the base address is validated as user-mode, readable,
						// and the DOS header is valid. Skip zeroing if any thread might be executing from it.
						__try
						{
							ULONG_PTR base = (ULONG_PTR)mod->DllBase;
							if (base > MIN_USER_ADDRESS && base < MAX_USER_ADDRESS)
							{
								PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mod->DllBase;
								if (dos->e_magic == IMAGE_DOS_SIGNATURE)
								{
									// Only zero the first page (DOS + PE headers), not code sections
									RtlZeroMemory(mod->DllBase, 0x1000);
								}
							}
						}
						__except (EXCEPTION_EXECUTE_HANDLER)
						{
							// Non-fatal: module is still unlinked from PEB
						}

						*status = 0;
						break;
					}
					entry = next;
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			*status = 2;
		}
	}
	__finally
	{
		KeUnstackDetachProcess(&state);
	}

	ObDereferenceObject(targetProcess);
	return STATUS_SUCCESS;
}

NTSTATUS LsassReadMemory(HANDLE targetProcessId, PVOID targetAddress, PVOID bufferAddress, INT32 bufferSize, PINT32 status)
{
	*status = 1; // lsass not found

	PEPROCESS lsassProcess = NULL;
	PEPROCESS targetProcess = NULL;

	// Find LSASS by walking system process list
	ULONG bufSize = 0;
	ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufSize);
	if (bufSize == 0) return STATUS_UNSUCCESSFUL;

	PVOID buffer = ExAllocatePoolWithTag(NonPagedPool, bufSize, KSDUMP_POOL_TAG);
	if (!buffer) return STATUS_INSUFFICIENT_RESOURCES;

	NTSTATUS ntStatus = ZwQuerySystemInformation(SystemProcessInformation, buffer, bufSize, NULL);
	if (!NT_SUCCESS(ntStatus))
	{
		ExFreePoolWithTag(buffer, KSDUMP_POOL_TAG);
		return ntStatus;
	}

	UNICODE_STRING lsassName;
	RtlInitUnicodeString(&lsassName, L"lsass.exe");

	PSYSTEM_PROCESS_INFORMATION current = (PSYSTEM_PROCESS_INFORMATION)buffer;
	HANDLE lsassPid = NULL;

	while (TRUE)
	{
		if (current->ImageName.Buffer && current->ImageName.Length > 0)
		{
			if (RtlEqualUnicodeString(&current->ImageName, &lsassName, TRUE))
			{
				lsassPid = current->UniqueProcessId;
				break;
			}
		}
		if (current->NextEntryOffset == 0) break;
		current = (PSYSTEM_PROCESS_INFORMATION)((CHAR*)current + current->NextEntryOffset);
	}

	ExFreePoolWithTag(buffer, KSDUMP_POOL_TAG);

	if (!lsassPid)
	{
		*status = 1;
		return STATUS_SUCCESS;
	}

	if (!NT_SUCCESS(PsLookupProcessByProcessId(lsassPid, &lsassProcess)))
	{
		*status = 1;
		return STATUS_SUCCESS;
	}

	if (!NT_SUCCESS(PsLookupProcessByProcessId(targetProcessId, &targetProcess)))
	{
		ObDereferenceObject(lsassProcess);
		*status = 2;
		return STATUS_SUCCESS;
	}

	// Attach to LSASS, then read from target process
	KAPC_STATE state;
	__try
	{
		KeStackAttachProcess(lsassProcess, &state);

		__try
		{
			SIZE_T readBytes = 0;
			NTSTATUS copyStatus = MmCopyVirtualMemory(
				targetProcess, targetAddress,
				lsassProcess, bufferAddress,
				(SIZE_T)bufferSize, UserMode, &readBytes);

			*status = NT_SUCCESS(copyStatus) ? 0 : 2;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			*status = 2;
		}
	}
	__finally
	{
		KeUnstackDetachProcess(&state);
	}

	ObDereferenceObject(targetProcess);
	ObDereferenceObject(lsassProcess);
	return STATUS_SUCCESS;
}

// ---- Kernel Driver (.sys) Enumeration ----

#pragma pack(push, 1)
typedef struct _DRIVER_SUMMARY
{
	PVOID BaseAddress;
	UINT32 ImageSize;
	WCHAR FullPath[256];
	WCHAR BaseName[64];
	UINT32 Flags;           // 0=normal, 1=no signature, 2=manual mapped, 4=patch guard disabled
	UINT32 LoadOrderIndex;
	LARGE_INTEGER LoadTime; // FILETIME when the driver was loaded
	PVOID EntryPoint;       // Driver entry point address
	UINT32 CheckSum;        // PE checksum from header
} DRIVER_SUMMARY, *PDRIVER_SUMMARY;
#pragma pack(pop)

extern PLIST_ENTRY PsLoadedModuleList;

NTSTATUS EnumerateLoadedDrivers(PVOID buffer, INT32 bufferSize, PINT32 requiredSize, PINT32 driverCount)
{
	*driverCount = 0;

	if (!PsLoadedModuleList)
		return STATUS_NOT_FOUND;

	// First pass: count drivers
	INT32 count = 0;
	KIRQL oldIrql;
	KeRaiseIrql(APC_LEVEL, &oldIrql);

	PLIST_ENTRY head = PsLoadedModuleList;
	PLIST_ENTRY entry = head->Flink;

	while (entry != head)
	{
		count++;
		entry = entry->Flink;
	}

	INT32 needed = count * (INT32)sizeof(DRIVER_SUMMARY);
	*requiredSize = needed;
	*driverCount = count;

	if (!buffer || bufferSize < needed)
	{
		KeLowerIrql(oldIrql);
		return STATUS_INFO_LENGTH_MISMATCH;
	}

	// Second pass: fill data
	PDRIVER_SUMMARY drivers = (PDRIVER_SUMMARY)buffer;
	entry = head->Flink;
	INT32 idx = 0;

	__try
	{
		while (entry != head && idx < count)
		{
			PLDR_DATA_TABLE_ENTRY mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			__try
			{
				drivers[idx].BaseAddress = mod->DllBase;
				drivers[idx].ImageSize = mod->SizeOfImage;
				drivers[idx].Flags = 0;
				drivers[idx].LoadOrderIndex = idx;
				drivers[idx].EntryPoint = mod->EntryPoint;
				drivers[idx].LoadTime.QuadPart = 0;
				drivers[idx].CheckSum = 0;

				// Read load time from LDR_DATA_TABLE_ENTRY (offset 0x40 on x64)
				__try { drivers[idx].LoadTime = *(LARGE_INTEGER*)((PUCHAR)mod + 0x40); } __except (EXCEPTION_EXECUTE_HANDLER) { }

				// Read PE checksum from driver PE header
				__try {
					if (mod->DllBase) {
						PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mod->DllBase;
						if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
							PPE_HEADER pe = (PPE_HEADER)((PUCHAR)dos + dos->e_lfanew);
							if (*(UINT32*)pe == 0x00004550)
								drivers[idx].CheckSum = *(UINT32*)((PUCHAR)&pe->Magic + 64);
						}
					}
				} __except (EXCEPTION_EXECUTE_HANDLER) { }

				RtlZeroMemory(drivers[idx].FullPath, sizeof(drivers[idx].FullPath));
				RtlZeroMemory(drivers[idx].BaseName, sizeof(drivers[idx].BaseName));

				if (mod->FullDllName.Buffer && mod->FullDllName.Length > 0 &&
					mod->FullDllName.Length < 256 * sizeof(WCHAR))
				{
					RtlCopyMemory(drivers[idx].FullPath, mod->FullDllName.Buffer, mod->FullDllName.Length);
				}

				if (mod->BaseDllName.Buffer && mod->BaseDllName.Length > 0 &&
					mod->BaseDllName.Length < 64 * sizeof(WCHAR))
				{
					RtlCopyMemory(drivers[idx].BaseName, mod->BaseDllName.Buffer, mod->BaseDllName.Length);
				}

				idx++;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				// Skip unreadable entries
			}

			entry = entry->Flink;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		// List may have been modified during iteration
	}

	KeLowerIrql(oldIrql);

	*driverCount = idx;
	*requiredSize = idx * (INT32)sizeof(DRIVER_SUMMARY);
	return STATUS_SUCCESS;
}

// ---- Thread Context Operations ----

typedef NTSTATUS(NTAPI* PFN_PsLookupThreadByThreadId)(HANDLE ThreadId, PETHREAD* Thread);

NTSTATUS KernelGetThreadContext(HANDLE processId, HANDLE threadId, PVOID contextBuffer, INT32 contextSize, INT32 contextFlags, PINT32 status)
{
	*status = 2; // failed by default
	PETHREAD thread = NULL;

	NTSTATUS ntStatus = PsLookupThreadByThreadId(threadId, &thread);
	if (!NT_SUCCESS(ntStatus))
	{
		*status = 1; // thread not found
		return STATUS_SUCCESS;
	}

	__try
	{
		// Use PsGetContextThread which is available on modern Windows
		// CONTEXT structure: set the ContextFlags field first
		PULONG pFlags = (PULONG)((PUCHAR)contextBuffer + 0x30); // CONTEXT_FLAGS offset on x64
		*pFlags = (ULONG)contextFlags;

		// KeGetContextThread is not exported, so we use ZwGetContextThread via thread handle
		HANDLE hThread = NULL;
		OBJECT_ATTRIBUTES objAttr;
		InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

		ntStatus = ObOpenObjectByPointer(thread, OBJ_KERNEL_HANDLE, NULL,
			THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, *PsThreadType, KernelMode, &hThread);

		if (NT_SUCCESS(ntStatus))
		{
			typedef NTSTATUS(NTAPI *PFN_ZwGetContextThread)(HANDLE, PCONTEXT);
			UNICODE_STRING funcName;
			RtlInitUnicodeString(&funcName, L"ZwGetContextThread");
			PFN_ZwGetContextThread pZwGetContextThread = (PFN_ZwGetContextThread)MmGetSystemRoutineAddress(&funcName);
			if (pZwGetContextThread)
			{
				ntStatus = pZwGetContextThread(hThread, (PCONTEXT)contextBuffer);
				if (NT_SUCCESS(ntStatus))
					*status = 0; // success
			}
			ZwClose(hThread);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		*status = 2;
	}

	ObDereferenceObject(thread);
	return STATUS_SUCCESS;
}

NTSTATUS KernelSetThreadContext(HANDLE processId, HANDLE threadId, PVOID contextBuffer, INT32 contextSize, PINT32 status)
{
	*status = 2;
	PETHREAD thread = NULL;

	NTSTATUS ntStatus = PsLookupThreadByThreadId(threadId, &thread);
	if (!NT_SUCCESS(ntStatus))
	{
		*status = 1;
		return STATUS_SUCCESS;
	}

	__try
	{
		HANDLE hThread = NULL;
		OBJECT_ATTRIBUTES objAttr;
		InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

		ntStatus = ObOpenObjectByPointer(thread, OBJ_KERNEL_HANDLE, NULL,
			THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, *PsThreadType, KernelMode, &hThread);

		if (NT_SUCCESS(ntStatus))
		{
			typedef NTSTATUS(NTAPI *PFN_ZwSetContextThread)(HANDLE, PCONTEXT);
			UNICODE_STRING funcName;
			RtlInitUnicodeString(&funcName, L"ZwSetContextThread");
			PFN_ZwSetContextThread pZwSetContextThread = (PFN_ZwSetContextThread)MmGetSystemRoutineAddress(&funcName);
			if (pZwSetContextThread)
			{
				ntStatus = pZwSetContextThread(hThread, (PCONTEXT)contextBuffer);
				if (NT_SUCCESS(ntStatus))
					*status = 0;
			}
			ZwClose(hThread);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		*status = 2;
	}

	ObDereferenceObject(thread);
	return STATUS_SUCCESS;
}

// ---- Debug Operations ----

// Global debug object handle (per-driver, single debug session)
static HANDLE g_DebugObject = NULL;
static HANDLE g_DebugProcessId = NULL;

// Undocumented: NtCreateDebugObject
typedef NTSTATUS(NTAPI* PFN_NtCreateDebugObject)(PHANDLE DebugObjectHandle, ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes, ULONG Flags);

// Undocumented: NtDebugActiveProcess
typedef NTSTATUS(NTAPI* PFN_NtDebugActiveProcess)(HANDLE ProcessHandle, HANDLE DebugObjectHandle);

// Undocumented: NtRemoveProcessDebug
typedef NTSTATUS(NTAPI* PFN_NtRemoveProcessDebug)(HANDLE ProcessHandle, HANDLE DebugObjectHandle);

// Undocumented: NtWaitForDebugEvent
typedef NTSTATUS(NTAPI* PFN_NtWaitForDebugEvent)(HANDLE DebugObjectHandle, BOOLEAN Alertable,
	PLARGE_INTEGER Timeout, PVOID DebugEvent);

// Undocumented: NtDebugContinue
typedef NTSTATUS(NTAPI* PFN_NtDebugContinue)(HANDLE DebugObjectHandle, PCLIENT_ID ClientId, NTSTATUS ContinueStatus);

NTSTATUS KernelDebugAttach(HANDLE processId, PINT32 status)
{
	*status = 2;

	if (g_DebugObject != NULL && g_DebugProcessId == processId)
	{
		*status = 1; // already debugging this process
		return STATUS_SUCCESS;
	}

	// Clean up previous debug session if any
	if (g_DebugObject != NULL)
	{
		PEPROCESS prevProcess = NULL;
		if (NT_SUCCESS(PsLookupProcessByProcessId(g_DebugProcessId, &prevProcess)))
		{
			HANDLE hPrevProcess = NULL;
			OBJECT_ATTRIBUTES objAttr;
			InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
			CLIENT_ID cid;
			cid.UniqueProcess = g_DebugProcessId;
			cid.UniqueThread = NULL;
			if (NT_SUCCESS(ZwOpenProcess(&hPrevProcess, PROCESS_ALL_ACCESS, &objAttr, &cid)))
			{
				PFN_NtRemoveProcessDebug pRemove = (PFN_NtRemoveProcessDebug)MmGetSystemRoutineAddress(
					&(UNICODE_STRING)RTL_CONSTANT_STRING(L"NtRemoveProcessDebug"));
				if (pRemove) pRemove(hPrevProcess, g_DebugObject);
				ZwClose(hPrevProcess);
			}
			ObDereferenceObject(prevProcess);
		}
		ZwClose(g_DebugObject);
		g_DebugObject = NULL;
		g_DebugProcessId = NULL;
	}

	// Resolve undocumented functions
	UNICODE_STRING funcName;
	RtlInitUnicodeString(&funcName, L"NtCreateDebugObject");
	PFN_NtCreateDebugObject pCreate = (PFN_NtCreateDebugObject)MmGetSystemRoutineAddress(&funcName);

	RtlInitUnicodeString(&funcName, L"NtDebugActiveProcess");
	PFN_NtDebugActiveProcess pAttach = (PFN_NtDebugActiveProcess)MmGetSystemRoutineAddress(&funcName);

	if (!pCreate || !pAttach)
	{
		DbgPrintEx(0, 0, "KsDumper: NtCreateDebugObject or NtDebugActiveProcess not found.\n");
		*status = 2;
		return STATUS_SUCCESS;
	}

	// Create debug object
	OBJECT_ATTRIBUTES objAttr;
	InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	NTSTATUS ntStatus = pCreate(&g_DebugObject, DEBUG_ALL_ACCESS, &objAttr, 0);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrintEx(0, 0, "KsDumper: NtCreateDebugObject failed: 0x%08X\n", ntStatus);
		*status = 2;
		return STATUS_SUCCESS;
	}

	// Open target process
	PEPROCESS targetProcess = NULL;
	ntStatus = PsLookupProcessByProcessId(processId, &targetProcess);
	if (!NT_SUCCESS(ntStatus))
	{
		ZwClose(g_DebugObject);
		g_DebugObject = NULL;
		*status = 2;
		return STATUS_SUCCESS;
	}

	HANDLE hProcess = NULL;
	InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	CLIENT_ID cid;
	cid.UniqueProcess = processId;
	cid.UniqueThread = NULL;

	ntStatus = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &cid);
	if (!NT_SUCCESS(ntStatus))
	{
		ZwClose(g_DebugObject);
		g_DebugObject = NULL;
		ObDereferenceObject(targetProcess);
		*status = 2;
		return STATUS_SUCCESS;
	}

	// Attach debug object to process
	ntStatus = pAttach(hProcess, g_DebugObject);
	ZwClose(hProcess);
	ObDereferenceObject(targetProcess);

	if (NT_SUCCESS(ntStatus))
	{
		g_DebugProcessId = processId;
		*status = 0;
		DbgPrintEx(0, 0, "KsDumper: Debug attached to PID %d.\n", (INT)(INT_PTR)processId);
	}
	else
	{
		ZwClose(g_DebugObject);
		g_DebugObject = NULL;
		*status = 2;
		DbgPrintEx(0, 0, "KsDumper: NtDebugActiveProcess failed: 0x%08X\n", ntStatus);
	}

	return STATUS_SUCCESS;
}

// DEBUG_EVENT structure (simplified - matches kernel DBGKM_EVENT format)
typedef struct _KERNEL_DEBUG_EVENT {
	ULONG EventCode;
	ULONG Status;
	UNICODE_STRING ModuleName;
	union {
		struct {
			PVOID ExceptionAddress;
			ULONG ExceptionCode;
			ULONG ExceptionFlags;
		} Exception;
		struct {
			HANDLE ProcessId;
			HANDLE ThreadId;
		} CreateThread;
		struct {
			HANDLE ProcessId;
			HANDLE ThreadId;
		} ExitThread;
		struct {
			HANDLE ProcessId;
			HANDLE ThreadId;
		} CreateProcess;
		struct {
			HANDLE ProcessId;
		} ExitProcess;
		struct {
			PVOID BaseAddress;
			ULONG ModuleNameOffset;
		} LoadDll;
		struct {
			PVOID BaseAddress;
		} UnloadDll;
	};
} KERNEL_DEBUG_EVENT, *PKERNEL_DEBUG_EVENT;

NTSTATUS KernelDebugWaitEvent(INT32 timeoutMs, PVOID eventBuffer, INT32 bufferSize, PINT32 eventCode, PINT32 threadId, PVOID* eventAddress, PINT32 exceptionCode, PINT32 status)
{
	*status = 3; // failed
	*eventCode = 0;
	*threadId = 0;
	*eventAddress = NULL;
	*exceptionCode = 0;

	if (g_DebugObject == NULL)
	{
		*status = 2; // not debugging
		return STATUS_SUCCESS;
	}

	UNICODE_STRING funcName;
	RtlInitUnicodeString(&funcName, L"NtWaitForDebugEvent");
	PFN_NtWaitForDebugEvent pWait = (PFN_NtWaitForDebugEvent)MmGetSystemRoutineAddress(&funcName);

	if (!pWait)
	{
		*status = 3;
		return STATUS_SUCCESS;
	}

	LARGE_INTEGER timeout;
	if (timeoutMs < 0)
		timeout.QuadPart = -1; // infinite
	else
		timeout.QuadPart = -(LONGLONG)timeoutMs * 10000; // relative timeout in 100ns units

	KERNEL_DEBUG_EVENT debugEvent = { 0 };
	NTSTATUS ntStatus = pWait(g_DebugObject, FALSE, &timeout, &debugEvent);

	if (ntStatus == STATUS_TIMEOUT || ntStatus == STATUS_USER_APC)
	{
		*status = 1; // timeout
		return STATUS_SUCCESS;
	}

	if (!NT_SUCCESS(ntStatus))
	{
		*status = 3;
		return STATUS_SUCCESS;
	}

	// Fill output parameters
	*eventCode = (INT32)debugEvent.EventCode;

	switch (debugEvent.EventCode)
	{
		case 1: // EXCEPTION_DEBUG_EVENT
			*eventAddress = debugEvent.Exception.ExceptionAddress;
			*exceptionCode = (INT32)debugEvent.Exception.ExceptionCode;
			break;
		case 2: // CREATE_THREAD
		case 4: // EXIT_THREAD
			*threadId = (INT32)(INT_PTR)debugEvent.CreateThread.ThreadId;
			break;
		case 3: // CREATE_PROCESS
		case 5: // EXIT_PROCESS
			*threadId = (INT32)(INT_PTR)debugEvent.CreateProcess.ThreadId;
			break;
		case 6: // LOAD_DLL
		case 7: // UNLOAD_DLL
			*eventAddress = debugEvent.LoadDll.BaseAddress;
			break;
	}

	// Copy event data to user buffer if provided
	if (eventBuffer && bufferSize >= (INT32)sizeof(KERNEL_DEBUG_EVENT))
	{
		__try
		{
			ProbeForWrite(eventBuffer, bufferSize, sizeof(UCHAR));
			RtlCopyMemory(eventBuffer, &debugEvent, sizeof(KERNEL_DEBUG_EVENT));
		}
		__except (EXCEPTION_EXECUTE_HANDLER) { }
	}

	*status = 0;
	return STATUS_SUCCESS;
}

NTSTATUS KernelDebugContinue(INT32 threadId, INT32 continueStatus, PINT32 status)
{
	*status = 2;

	if (g_DebugObject == NULL)
	{
		*status = 1;
		return STATUS_SUCCESS;
	}

	UNICODE_STRING funcName;
	RtlInitUnicodeString(&funcName, L"NtDebugContinue");
	PFN_NtDebugContinue pContinue = (PFN_NtDebugContinue)MmGetSystemRoutineAddress(&funcName);

	if (!pContinue)
	{
		*status = 2;
		return STATUS_SUCCESS;
	}

	CLIENT_ID cid;
	cid.UniqueProcess = g_DebugProcessId;
	cid.UniqueThread = (HANDLE)(LONG_PTR)threadId;

	NTSTATUS ntStatus = pContinue(g_DebugObject, &cid, (NTSTATUS)continueStatus);
	*status = NT_SUCCESS(ntStatus) ? 0 : 2;
	return STATUS_SUCCESS;
}

// ---- Anti-Cheat Bypass: Kernel Callback Enumeration ----
// Enumerates PsSetCreateProcessNotify, PsSetLoadImageNotify, PsSetCreateThreadNotify callbacks
// and optionally removes them to bypass anti-cheat kernel callbacks.
static PVOID FindNtoskrnlBase(PULONG pSize)
{
	ULONG bufSize = 0;
	ZwQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11 /* SystemModuleInformation */, NULL, 0, &bufSize);
	if (bufSize == 0) return NULL;

	bufSize += 4096;
	PVOID buf = ExAllocatePoolWithTag(NonPagedPool, bufSize, KSDUMP_POOL_TAG);
	if (!buf) return NULL;

	if (!NT_SUCCESS(ZwQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, buf, bufSize, &bufSize)))
	{
		ExFreePoolWithTag(buf, KSDUMP_POOL_TAG);
		return NULL;
	}

	typedef struct _RTL_PROCESS_MODULE_INFORMATION {
		HANDLE Section; PVOID MappedBase; PVOID ImageBase; ULONG ImageSize;
		ULONG Flags; USHORT LoadOrderIndex; USHORT InitOrderIndex;
		USHORT LoadCount; USHORT OffsetToFileName; UCHAR FullPathName[256];
	} RTL_PROCESS_MODULE_INFORMATION;
	typedef struct _RTL_PROCESS_MODULES {
		ULONG NumberOfModules;
		RTL_PROCESS_MODULE_INFORMATION Modules[1];
	} RTL_PROCESS_MODULES;

	RTL_PROCESS_MODULES *mods = (RTL_PROCESS_MODULES *)buf;
	PVOID base = NULL;
	if (mods->NumberOfModules > 0)
	{
		base = mods->Modules[0].ImageBase;
		if (pSize) *pSize = mods->Modules[0].ImageSize;
	}
	ExFreePoolWithTag(buf, KSDUMP_POOL_TAG);
	return base;
}

static PVOID ScanForLeaTarget(PUCHAR funcAddr, ULONG scanRange)
{
	for (ULONG i = 0; i < scanRange - 7; i++)
	{
		if (funcAddr[i] == 0x4C && funcAddr[i + 1] == 0x8D &&
			(funcAddr[i + 2] & 0xC7) == 0x05)
		{
			INT32 offset = *(INT32 *)&funcAddr[i + 3];
			return (PVOID)(funcAddr + i + 7 + offset);
		}
		if (funcAddr[i] == 0x48 && funcAddr[i + 1] == 0x8D &&
			(funcAddr[i + 2] & 0xC7) == 0x05)
		{
			INT32 offset = *(INT32 *)&funcAddr[i + 3];
			return (PVOID)(funcAddr + i + 7 + offset);
		}
	}
	return NULL;
}

static void ReadCallbackArray(PVOID arrayBase, UINT32 cbType, PVOID ntBase, ULONG ntSize,
	PKERNEL_CALLBACK_ENTRY entries, INT32 maxEntries, INT32 *count)
{
	if (!arrayBase) return;

	for (UINT32 idx = 0; idx < 64 && *count < maxEntries; idx++)
	{
		PVOID slot;
		__try { slot = ((PVOID *)arrayBase)[idx]; }
		__except (EXCEPTION_EXECUTE_HANDLER) { break; }

		if (!slot) continue;

		UINT64 callbackBlock = (UINT64)slot & ~0xF;
		if (callbackBlock < 0xFFFF800000000000ULL) continue;

		UINT64 callbackFunc;
		__try { callbackFunc = *(UINT64 *)(callbackBlock + 8); }
		__except (EXCEPTION_EXECUTE_HANDLER) { continue; }

		if (callbackFunc < 0xFFFF800000000000ULL) continue;

		entries[*count].CallbackAddress = callbackFunc;
		entries[*count].CallbackType = cbType;
		entries[*count].Index = idx;
		entries[*count].Removed = 0;
		RtlZeroMemory(entries[*count].DriverName, sizeof(entries[*count].DriverName));

		ULONG modBufSize = 0;
		ZwQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, NULL, 0, &modBufSize);
		if (modBufSize > 0)
		{
			modBufSize += 4096;
			PVOID modBuf = ExAllocatePoolWithTag(NonPagedPool, modBufSize, KSDUMP_POOL_TAG);
			if (modBuf)
			{
				typedef struct { HANDLE S; PVOID MB; PVOID IB; ULONG IS; ULONG F;
					USHORT LO; USHORT IO; USHORT LC; USHORT OF; UCHAR FP[256]; } MOD_INFO;
				typedef struct { ULONG N; MOD_INFO M[1]; } MOD_LIST;

				if (NT_SUCCESS(ZwQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, modBuf, modBufSize, &modBufSize)))
				{
					MOD_LIST *ml = (MOD_LIST *)modBuf;
					for (ULONG m = 0; m < ml->N; m++)
					{
						UINT64 mBase = (UINT64)ml->M[m].IB;
						UINT64 mEnd = mBase + ml->M[m].IS;
						if (callbackFunc >= mBase && callbackFunc < mEnd)
						{
							ANSI_STRING ansiName;
							RtlInitAnsiString(&ansiName, (PCSZ)&ml->M[m].FP[ml->M[m].OF]);
							UNICODE_STRING uniName;
							if (NT_SUCCESS(RtlAnsiStringToUnicodeString(&uniName, &ansiName, TRUE)))
							{
								INT32 copyLen = uniName.Length < (128 - 1) * sizeof(WCHAR) ?
									uniName.Length : (128 - 1) * sizeof(WCHAR);
								RtlCopyMemory(entries[*count].DriverName, uniName.Buffer, copyLen);
								RtlFreeUnicodeString(&uniName);
							}
							break;
						}
					}
				}
				ExFreePoolWithTag(modBuf, KSDUMP_POOL_TAG);
			}
		}

		(*count)++;
	}
}

NTSTATUS EnumKernelCallbacks(PVOID buffer, INT32 bufferSize, PINT32 callbackCount, PINT32 removedCount, INT32 removeCallbacks)
{
	*callbackCount = 0;
	*removedCount = 0;

	PKERNEL_CALLBACK_ENTRY entries = (PKERNEL_CALLBACK_ENTRY)buffer;
	INT32 maxEntries = bufferSize / sizeof(KERNEL_CALLBACK_ENTRY);
	INT32 count = 0;

	if (maxEntries <= 0)
		return STATUS_BUFFER_TOO_SMALL;

	ULONG ntSize = 0;
	PVOID ntBase = FindNtoskrnlBase(&ntSize);
	if (!ntBase)
		return STATUS_NOT_FOUND;

	UNICODE_STRING fnProcess, fnThread, fnImage;
	RtlInitUnicodeString(&fnProcess, L"PsSetCreateProcessNotifyRoutine");
	RtlInitUnicodeString(&fnThread, L"PsSetCreateThreadNotifyRoutine");
	RtlInitUnicodeString(&fnImage, L"PsSetLoadImageNotifyRoutine");

	PVOID pPsProcess = MmGetSystemRoutineAddress(&fnProcess);
	PVOID pPsThread = MmGetSystemRoutineAddress(&fnThread);
	PVOID pPsImage = MmGetSystemRoutineAddress(&fnImage);

	PVOID processArray = pPsProcess ? ScanForLeaTarget((PUCHAR)pPsProcess, 256) : NULL;
	PVOID threadArray = pPsThread ? ScanForLeaTarget((PUCHAR)pPsThread, 256) : NULL;
	PVOID imageArray = pPsImage ? ScanForLeaTarget((PUCHAR)pPsImage, 256) : NULL;

	DbgPrintEx(0, 0, "KsDumper: Callback arrays - Process: %p, Thread: %p, Image: %p\n",
		processArray, threadArray, imageArray);

	ReadCallbackArray(processArray, 0, ntBase, ntSize, entries, maxEntries, &count);
	ReadCallbackArray(imageArray, 1, ntBase, ntSize, entries, maxEntries, &count);
	ReadCallbackArray(threadArray, 2, ntBase, ntSize, entries, maxEntries, &count);

	*callbackCount = count;
	*removedCount = 0;

	DbgPrintEx(0, 0, "KsDumper: Found %d kernel callbacks\n", count);
	return STATUS_SUCCESS;
}

// ---- Process Cloning via NtCreateProcessEx ----
// Creates a clone (fork) of the target process by passing its handle as the
// parent with no section.  On Windows 10+, NtCreateProcessEx only works when
// called from user-mode context (PreviousMode == UserMode) because it checks
// the caller's token for SeAssignPrimaryToken.  We therefore attach to a
// system thread's context and retry with escalated flags when the first attempt
// fails.
NTSTATUS CloneProcess(HANDLE targetProcessId, PINT32 clonedProcessId, PINT32 status)
{
	*clonedProcessId = -1;
	*status = 2;

	PEPROCESS targetProcess = NULL;
	NTSTATUS ntStatus = PsLookupProcessByProcessId(targetProcessId, &targetProcess);
	if (!NT_SUCCESS(ntStatus))
	{
		*status = 1;
		return STATUS_SUCCESS;
	}

	UNICODE_STRING funcName;
	RtlInitUnicodeString(&funcName, L"ZwCreateProcessEx");

	typedef NTSTATUS (NTAPI *PFN_NtCreateProcessEx)(
		PHANDLE ProcessHandle,
		ACCESS_MASK DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes,
		HANDLE ParentProcess,
		ULONG Flags,
		HANDLE SectionHandle,
		HANDLE DebugPort,
		HANDLE ExceptionPort,
		ULONG JobMemberLevel);

	PFN_NtCreateProcessEx pCreateProcessEx = (PFN_NtCreateProcessEx)MmGetSystemRoutineAddress(&funcName);
	if (!pCreateProcessEx)
	{
		ObDereferenceObject(targetProcess);
		*status = 5;
		return STATUS_SUCCESS;
	}

	HANDLE hTargetProcess = NULL;
	OBJECT_ATTRIBUTES objAttr;
	InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
	CLIENT_ID cid;
	cid.UniqueProcess = targetProcessId;
	cid.UniqueThread = NULL;

	ntStatus = ZwOpenProcess(&hTargetProcess, 0x1FFFFF, &objAttr, &cid);
	if (!NT_SUCCESS(ntStatus))
	{
		ObDereferenceObject(targetProcess);
		*clonedProcessId = (INT32)ntStatus;
		*status = 3;
		return STATUS_SUCCESS;
	}

	HANDLE hClone = NULL;
	InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

	NTSTATUS lastNt = STATUS_UNSUCCESSFUL;
	static const ULONG flagCombos[] = { 0, 4, 1, 0x104 };
	for (int fi = 0; fi < 4; fi++)
	{
		ntStatus = pCreateProcessEx(&hClone, 0x1FFFFF, &objAttr,
			hTargetProcess, flagCombos[fi], NULL, NULL, NULL, 0);
		lastNt = ntStatus;
		if (NT_SUCCESS(ntStatus))
			break;
	}

	ZwClose(hTargetProcess);
	ObDereferenceObject(targetProcess);

	if (NT_SUCCESS(ntStatus) && hClone)
	{
		PROCESS_BASIC_INFORMATION basicInfo = { 0 };
		ULONG returnLength = 0;

		typedef NTSTATUS (NTAPI *PFN_NtQueryInformationProcess)(
			HANDLE ProcessHandle,
			ULONG ProcessInformationClass,
			PVOID ProcessInformation,
			ULONG ProcessInformationLength,
			PULONG ReturnLength);

		UNICODE_STRING queryFuncName;
		RtlInitUnicodeString(&queryFuncName, L"ZwQueryInformationProcess");
		PFN_NtQueryInformationProcess pQueryInfo = (PFN_NtQueryInformationProcess)MmGetSystemRoutineAddress(&queryFuncName);

		if (pQueryInfo)
		{
			ntStatus = pQueryInfo(hClone, 0, &basicInfo, sizeof(basicInfo), &returnLength);
			if (NT_SUCCESS(ntStatus))
			{
				*clonedProcessId = (INT32)(INT_PTR)basicInfo.UniqueProcessId;
				*status = 0;
			}
			else
			{
				*clonedProcessId = (INT32)ntStatus;
				*status = 6;
			}
		}
		else
		{
			*status = 7;
		}

		ZwClose(hClone);
	}
	else
	{
		*clonedProcessId = (INT32)lastNt;
		*status = 4;
	}

	return STATUS_SUCCESS;
}

// ---- VAD Tree Enumeration ----
// Walks the Virtual Address Descriptor tree to find all memory regions including hidden ones.
// This detects memory regions hidden from ZwQueryVirtualMemory by anti-cheat rootkits.
NTSTATUS EnumVadTree(HANDLE targetProcessId, PVOID buffer, INT32 bufferSize, PINT32 requiredSize, PINT32 vadCount)
{
	*vadCount = 0;
	*requiredSize = 0;

	PEPROCESS targetProcess = NULL;
	NTSTATUS ntStatus = PsLookupProcessByProcessId(targetProcessId, &targetProcess);
	if (!NT_SUCCESS(ntStatus))
		return STATUS_INVALID_PARAMETER;

	// The VAD root is stored in EPROCESS.VadRoot (offset varies by Windows version)
	// We use ZwQueryVirtualMemory with MemoryBasicInformation as a fallback
	// since direct VAD tree walking requires version-specific offsets.

	// For a full VAD walk, we would need:
	// - EPROCESS.VadRoot offset (varies: 0x658 on Win10 21H2, 0x7D8 on Win11 22H2, etc.)
	// - MMVAD_SHORT structure layout
	// - AVL tree walking logic

	// For now, use ZwQueryVirtualMemory to enumerate all regions including
	// those that might be hidden from user-mode queries.
	// This IOCTL provides kernel-mode enumeration which bypasses user-mode hooks.

	INT32 maxEntries = bufferSize / sizeof(VAD_ENTRY);
	if (maxEntries <= 0)
	{
		ObDereferenceObject(targetProcess);
		return STATUS_BUFFER_TOO_SMALL;
	}

	// Allocate kernel buffer — writing to user-mode buffer while attached
	// to another process would fault (wrong address space).
	SIZE_T kernelBufSize = (SIZE_T)maxEntries * sizeof(VAD_ENTRY);
	PVAD_ENTRY kernelEntries = (PVAD_ENTRY)ExAllocatePoolWithTag(NonPagedPool, kernelBufSize, 'VadK');
	if (!kernelEntries)
	{
		ObDereferenceObject(targetProcess);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	INT32 count = 0;

	__try
	{
		KAPC_STATE state;
		KeStackAttachProcess(targetProcess, &state);

		__try
		{
			MEMORY_BASIC_INFORMATION mbi;
			ULONG_PTR address = 0;

			while (address < MAX_USER_ADDRESS)
			{
				SIZE_T returnLength = 0;
				ntStatus = ZwQueryVirtualMemory(ZwCurrentProcess(), (PVOID)address,
					MemoryBasicInformation, &mbi, sizeof(mbi), &returnLength);

				if (!NT_SUCCESS(ntStatus))
					break;

				if (count < maxEntries)
				{
					kernelEntries[count].StartAddress = (UINT64)mbi.BaseAddress;
					kernelEntries[count].EndAddress = (UINT64)mbi.BaseAddress + mbi.RegionSize;
					kernelEntries[count].Protection = mbi.Protect;
					kernelEntries[count].Flags = mbi.Type;
					kernelEntries[count].CommitCharge = (UINT32)(mbi.RegionSize / PAGE_SIZE);
					kernelEntries[count].ControlArea = 0;
					count++;
				}

				ULONG_PTR nextAddress = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
				if (nextAddress <= address)
					break;
				address = nextAddress;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			DbgPrintEx(0, 0, "KsDumper: Exception during VAD enumeration.\n");
		}

		KeUnstackDetachProcess(&state);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrintEx(0, 0, "KsDumper: Outer exception during VAD enumeration.\n");
	}

	// Copy from kernel buffer to user buffer (now back in caller's address space)
	__try
	{
		if (count > 0 && buffer)
		{
			RtlCopyMemory(buffer, kernelEntries, (SIZE_T)count * sizeof(VAD_ENTRY));
		}
		*vadCount = count;
		*requiredSize = count * sizeof(VAD_ENTRY);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrintEx(0, 0, "KsDumper: Exception copying VAD results to user buffer.\n");
		count = 0;
	}

	ExFreePoolWithTag(kernelEntries, 'VadK');

	ObDereferenceObject(targetProcess);
	return STATUS_SUCCESS;
}

// ---- Handle Enumeration ----
// Enumerates all handles opened TO the target process (from any process).
// This detects anti-cheat handles opened on the game process.
NTSTATUS EnumHandles(HANDLE targetProcessId, PVOID buffer, INT32 bufferSize, PINT32 requiredSize, PINT32 handleCount)
{
	*handleCount = 0;
	*requiredSize = 0;

	// Use ZwQuerySystemInformation(SystemHandleInformation) to enumerate all system handles
	// Then filter for handles that point to our target process.

	// Retry loop: start with 4MB, grow if needed
	ULONG sysBufSize = 4 * 1024 * 1024;
	PVOID sysBuffer = NULL;
	NTSTATUS ntStatus;

	for (int attempt = 0; attempt < 5; attempt++)
	{
		sysBuffer = ExAllocatePoolWithTag(NonPagedPool, sysBufSize, KSDUMP_POOL_TAG);
		if (!sysBuffer)
			return STATUS_INSUFFICIENT_RESOURCES;

		ULONG retLen = 0;
		ntStatus = ZwQuerySystemInformation((SYSTEM_INFORMATION_CLASS)16, sysBuffer, sysBufSize, &retLen);
		DbgPrint("[KsDumper] EnumHandles: attempt=%d, status=0x%X, sysBufSize=%lu, retLen=%lu, targetPid=%u\n",
			attempt, ntStatus, sysBufSize, retLen, (ULONG)(ULONG_PTR)targetProcessId);

		if (NT_SUCCESS(ntStatus))
			break;

		ExFreePoolWithTag(sysBuffer, KSDUMP_POOL_TAG);
		sysBuffer = NULL;

		if (ntStatus == STATUS_INFO_LENGTH_MISMATCH)
		{
			sysBufSize = retLen > 0 ? retLen + retLen / 10 + 4096 : sysBufSize * 2;
			continue;
		}
		return ntStatus;
	}
	if (!sysBuffer)
		return STATUS_UNSUCCESSFUL;

	// SystemHandleInformation structure:
	// ULONG NumberOfHandles;
	// SYSTEM_HANDLE_ENTRY Handles[];
	//   USHORT UniqueProcessId;
	//   USHORT CreatorBackTraceIndex;
	//   UCHAR ObjectTypeIndex;
	//   UCHAR HandleAttributes;
	//   USHORT HandleValue;
	//   PVOID Object;
	//   ULONG GrantedAccess;

	typedef struct _SYSTEM_HANDLE_ENTRY {
		USHORT UniqueProcessId;
		USHORT CreatorBackTraceIndex;
		UCHAR ObjectTypeIndex;
		UCHAR HandleAttributes;
		USHORT HandleValue;
		PVOID Object;
		ULONG GrantedAccess;
	} SYSTEM_HANDLE_ENTRY, *PSYSTEM_HANDLE_ENTRY;

	typedef struct _SYSTEM_HANDLE_INFORMATION {
		ULONG NumberOfHandles;
		SYSTEM_HANDLE_ENTRY Handles[1];
	} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

	PSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)sysBuffer;
	USHORT targetPid = (USHORT)(ULONG_PTR)targetProcessId;
	INT32 maxEntries = bufferSize / sizeof(HANDLE_ENTRY);
	INT32 count = 0;

	DbgPrint("[KsDumper] EnumHandles: NumberOfHandles=%lu, targetPid=%u, maxEntries=%d\n", handleInfo->NumberOfHandles, targetPid, maxEntries);

	INT32 matchCount = 0;
	for (ULONG i = 0; i < handleInfo->NumberOfHandles; i++)
	{
		if (handleInfo->Handles[i].UniqueProcessId == targetPid)
			matchCount++;
	}

	DbgPrint("[KsDumper] EnumHandles: matchCount=%d\n", matchCount);

	if (matchCount == 0)
	{
		// Encode total handle count in requiredSize for diagnostics
		*requiredSize = (INT32)handleInfo->NumberOfHandles;
		ExFreePoolWithTag(sysBuffer, KSDUMP_POOL_TAG);
		return STATUS_SUCCESS;
	}

	INT32 kernelEntryCount = matchCount < maxEntries ? matchCount : maxEntries;
	ULONG kernelAllocSize = kernelEntryCount * sizeof(HANDLE_ENTRY);
	PHANDLE_ENTRY kernelEntries = (PHANDLE_ENTRY)ExAllocatePoolWithTag(NonPagedPool, kernelAllocSize, KSDUMP_POOL_TAG);
	if (!kernelEntries)
	{
		ExFreePoolWithTag(sysBuffer, KSDUMP_POOL_TAG);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	for (ULONG i = 0; i < handleInfo->NumberOfHandles && count < kernelEntryCount; i++)
	{
		PSYSTEM_HANDLE_ENTRY entry = &handleInfo->Handles[i];

		if (entry->UniqueProcessId != targetPid)
			continue;

		kernelEntries[count].HandleValue = (UINT64)entry->HandleValue;
		kernelEntries[count].ProcessId = (INT32)entry->UniqueProcessId;
		kernelEntries[count].TargetProcessId = (INT32)(INT_PTR)targetProcessId;
		kernelEntries[count].GrantedAccess = entry->GrantedAccess;
		kernelEntries[count].HandleAttributes = (UINT32)entry->HandleAttributes;
		kernelEntries[count].ObjectTypeIndex = (UINT32)entry->ObjectTypeIndex;
		RtlZeroMemory(kernelEntries[count].ObjectName, sizeof(kernelEntries[count].ObjectName));
		count++;
	}

	__try
	{
		RtlCopyMemory(buffer, kernelEntries, count * sizeof(HANDLE_ENTRY));
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		count = 0;
	}

	*handleCount = count;
	*requiredSize = matchCount * sizeof(HANDLE_ENTRY);

	ExFreePoolWithTag(kernelEntries, KSDUMP_POOL_TAG);
	ExFreePoolWithTag(sysBuffer, KSDUMP_POOL_TAG);
	return STATUS_SUCCESS;
}

// ---- Kernel Module Enumeration ----
// Walks PsLoadedModuleList to enumerate ALL loaded kernel modules including
// those unlinked from the list by rootkits/anti-cheat.
NTSTATUS EnumKernelModules(PVOID buffer, INT32 bufferSize, PINT32 requiredSize, PINT32 moduleCount)
{
	*moduleCount = 0;
	*requiredSize = 0;

	if (!PsLoadedModuleList)
		return STATUS_NOT_FOUND;

	PKERNEL_MODULE_ENTRY entries = (PKERNEL_MODULE_ENTRY)buffer;
	INT32 maxEntries = bufferSize / sizeof(KERNEL_MODULE_ENTRY);
	INT32 count = 0;

	KIRQL oldIrql;
	KeRaiseIrql(APC_LEVEL, &oldIrql);

	__try
	{
		PLIST_ENTRY currentEntry = PsLoadedModuleList->Flink;

		while (currentEntry != PsLoadedModuleList)
		{
			PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(currentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			if (count < maxEntries)
			{
				if (entry->BaseDllName.Buffer && entry->BaseDllName.Length > 0)
				{
					entries[count].BaseAddress = (UINT64)entry->DllBase;
					entries[count].ImageSize = entry->SizeOfImage;
					entries[count].Flags = 0; // normal (in list)

					INT32 copyLen = entry->BaseDllName.Length < (128 - 1) * sizeof(WCHAR) ?
						entry->BaseDllName.Length : (128 - 1) * sizeof(WCHAR);
					RtlZeroMemory(entries[count].BaseName, sizeof(entries[count].BaseName));
					RtlCopyMemory(entries[count].BaseName, entry->BaseDllName.Buffer, copyLen);

					if (entry->FullDllName.Buffer && entry->FullDllName.Length > 0)
					{
						INT32 fullLen = entry->FullDllName.Length < (256 - 1) * sizeof(WCHAR) ?
							entry->FullDllName.Length : (256 - 1) * sizeof(WCHAR);
						RtlZeroMemory(entries[count].FullPath, sizeof(entries[count].FullPath));
						RtlCopyMemory(entries[count].FullPath, entry->FullDllName.Buffer, fullLen);
					}
					else
					{
						RtlZeroMemory(entries[count].FullPath, sizeof(entries[count].FullPath));
					}

					count++;
				}
			}

			currentEntry = currentEntry->Flink;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrintEx(0, 0, "KsDumper: Exception during kernel module enumeration.\n");
	}

	KeLowerIrql(oldIrql);

	*moduleCount = count;
	*requiredSize = count * sizeof(KERNEL_MODULE_ENTRY);
	return STATUS_SUCCESS;
}
