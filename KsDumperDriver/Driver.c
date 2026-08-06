#include "NTUndocumented.h"
#include "ProcessLister.h"
#include "ExportScanner.h"
#include "UserModeBridge.h"
#include <intrin.h>

// Valid 4-char ASCII pool tag
#define KSDUMP_POOL_TAG 'DpKs'

// Maximum IOCTL buffer size to prevent integer overflow attacks (256 MB)
#define MAX_IOCTL_BUFFER_SIZE (256 * 1024 * 1024)

// User-mode address space limit (x64)
#define USER_MODE_MAX_ADDRESS ((PVOID)0x00007FFFFFFEFFFF)

// Minimum PID threshold - processes below this are system-critical and cannot be targeted
#define MIN_ALLOWED_PID 4

UNICODE_STRING deviceName, symLink;

// Returns TRUE if the PID is a system-critical process that should not be targeted
static BOOLEAN IsCriticalProcess(INT32 processId)
{
	// Block System (PID 4), smss, csrss, wininit, winlogon, services, lsass
	if (processId <= MIN_ALLOWED_PID)
		return TRUE;
	return FALSE;
}

// Validates that a target address is within user-mode space
static BOOLEAN IsUserModeAddress(PVOID address)
{
	return address != NULL && address <= USER_MODE_MAX_ADDRESS;
}

NTSTATUS CopyVirtualMemory(PEPROCESS targetProcess, PVOID sourceAddress, PVOID targetAddress, SIZE_T size)
{
	SIZE_T readBytes = 0;
	return MmCopyVirtualMemory(targetProcess, sourceAddress, PsGetCurrentProcess(), targetAddress, size, UserMode, &readBytes);
}

NTSTATUS WriteVirtualMemory(PEPROCESS targetProcess, PVOID targetAddress, PVOID sourceBuffer, SIZE_T size)
{
	SIZE_T writtenBytes = 0;
	return MmCopyVirtualMemory(PsGetCurrentProcess(), sourceBuffer, targetProcess, targetAddress, size, UserMode, &writtenBytes);
}

// Validates that a size value won't cause integer overflow
static BOOLEAN IsValidBufferSize(INT32 size)
{
	return size > 0 && size < MAX_IOCTL_BUFFER_SIZE;
}

NTSTATUS IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	NTSTATUS status;
	ULONG bytesIO = 0;
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;

	if (controlCode == IO_COPY_MEMORY)
	{
		if (stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(KERNEL_COPY_MEMORY_OPERATION))
		{
			PKERNEL_COPY_MEMORY_OPERATION request = (PKERNEL_COPY_MEMORY_OPERATION)Irp->AssociatedIrp.SystemBuffer;
			PEPROCESS targetProcess;

			// Validate parameters before doing anything
			if (request->targetProcessId && request->bufferSize > 0 &&
				request->bufferSize < MAX_IOCTL_BUFFER_SIZE && request->bufferAddress != NULL &&
				IsUserModeAddress(request->targetAddress) && !IsCriticalProcess(request->targetProcessId))
			{
				if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(LONG_PTR)request->targetProcessId, &targetProcess)))
				{
					NTSTATUS copyStatus = STATUS_UNSUCCESSFUL;
					__try
					{
						ProbeForWrite(request->bufferAddress, request->bufferSize, sizeof(UCHAR));
						copyStatus = CopyVirtualMemory(targetProcess, request->targetAddress, request->bufferAddress, request->bufferSize);
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						copyStatus = GetExceptionCode();
						DbgPrintEx(0, 0, "KsDumper: Access violation during memory copy (PID %d, addr 0x%p, size %d).\n",
							request->targetProcessId, request->targetAddress, request->bufferSize);
					}
					ObDereferenceObject(targetProcess);

					status = NT_SUCCESS(copyStatus) ? STATUS_SUCCESS : STATUS_PARTIAL_COPY;
				}
				else
				{
					status = STATUS_INVALID_CID;
				}
			}
			else
			{
				status = STATUS_INVALID_PARAMETER;
			}

			bytesIO = sizeof(KERNEL_COPY_MEMORY_OPERATION);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytesIO = 0;
		}
	}
	else if (controlCode == IO_WRITE_MEMORY)
	{
		if (stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(KERNEL_COPY_MEMORY_OPERATION))
		{
			PKERNEL_COPY_MEMORY_OPERATION request = (PKERNEL_COPY_MEMORY_OPERATION)Irp->AssociatedIrp.SystemBuffer;
			PEPROCESS targetProcess;

			if (request->targetProcessId && request->bufferSize > 0 &&
				request->bufferSize < MAX_IOCTL_BUFFER_SIZE && request->bufferAddress != NULL &&
				IsUserModeAddress(request->targetAddress) && !IsCriticalProcess(request->targetProcessId))
			{
				if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(LONG_PTR)request->targetProcessId, &targetProcess)))
				{
					NTSTATUS writeStatus = STATUS_UNSUCCESSFUL;
					__try
					{
						ProbeForRead(request->bufferAddress, request->bufferSize, sizeof(UCHAR));
						writeStatus = WriteVirtualMemory(targetProcess, request->targetAddress, request->bufferAddress, request->bufferSize);
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						writeStatus = GetExceptionCode();
					}
					ObDereferenceObject(targetProcess);

					status = NT_SUCCESS(writeStatus) ? STATUS_SUCCESS : STATUS_PARTIAL_COPY;
				}
				else
				{
					status = STATUS_INVALID_CID;
				}
			}
			else
			{
				status = STATUS_INVALID_PARAMETER;
			}

			bytesIO = sizeof(KERNEL_COPY_MEMORY_OPERATION);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytesIO = 0;
		}
	}
	else if (controlCode == IO_GET_PROCESS_LIST)
	{
		if (stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(KERNEL_PROCESS_LIST_OPERATION) &&
			stack->Parameters.DeviceIoControl.OutputBufferLength == sizeof(KERNEL_PROCESS_LIST_OPERATION))
		{
			PKERNEL_PROCESS_LIST_OPERATION request = (PKERNEL_PROCESS_LIST_OPERATION)Irp->AssociatedIrp.SystemBuffer;

			__try
			{
				if (request->bufferAddress && IsValidBufferSize(request->bufferSize))
					ProbeForWrite(request->bufferAddress, request->bufferSize, sizeof(UCHAR));

				GetProcessList(request->bufferAddress, request->bufferSize, &request->bufferSize, &request->processCount);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				status = GetExceptionCode();
				Irp->IoStatus.Status = status;
				Irp->IoStatus.Information = 0;
				IoCompleteRequest(Irp, IO_NO_INCREMENT);
				return status;
			}

			status = STATUS_SUCCESS;
			bytesIO = sizeof(KERNEL_PROCESS_LIST_OPERATION);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytesIO = 0;
		}
	}
	else if (controlCode == IO_GET_MODULE_LIST)
	{
		if (stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(KERNEL_MODULE_LIST_OPERATION) &&
			stack->Parameters.DeviceIoControl.OutputBufferLength == sizeof(KERNEL_MODULE_LIST_OPERATION))
		{
			PKERNEL_MODULE_LIST_OPERATION request = (PKERNEL_MODULE_LIST_OPERATION)Irp->AssociatedIrp.SystemBuffer;

			if (!request->targetProcessId || IsCriticalProcess(request->targetProcessId))
			{
				status = STATUS_INVALID_PARAMETER;
				bytesIO = 0;
			}
			else
			{
				__try
				{
					if (request->bufferAddress && IsValidBufferSize(request->bufferSize))
						ProbeForWrite(request->bufferAddress, request->bufferSize, sizeof(UCHAR));

					GetModuleList((HANDLE)(LONG_PTR)request->targetProcessId, request->bufferAddress, request->bufferSize, &request->bufferSize, &request->moduleCount);
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					status = GetExceptionCode();
					Irp->IoStatus.Status = status;
					Irp->IoStatus.Information = 0;
					IoCompleteRequest(Irp, IO_NO_INCREMENT);
					return status;
				}

				status = STATUS_SUCCESS;
				bytesIO = sizeof(KERNEL_MODULE_LIST_OPERATION);
			}
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytesIO = 0;
		}
	}
	else if (controlCode == IO_UNPROTECT_PROCESS)
	{
		if (stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(KERNEL_UNPROTECT_OPERATION) &&
			stack->Parameters.DeviceIoControl.OutputBufferLength == sizeof(KERNEL_UNPROTECT_OPERATION))
		{
			PKERNEL_UNPROTECT_OPERATION request = (PKERNEL_UNPROTECT_OPERATION)Irp->AssociatedIrp.SystemBuffer;

			__try
			{
				if (request->targetProcessId && !IsCriticalProcess(request->targetProcessId))
					UnprotectProcess((HANDLE)(LONG_PTR)request->targetProcessId, &request->status);
				else
					request->status = 0;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				request->status = 3; // exception during unprotect
			}

			status = STATUS_SUCCESS;
			bytesIO = sizeof(KERNEL_UNPROTECT_OPERATION);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytesIO = 0;
		}
	}
	else if (controlCode == IO_CHECK_TABLES_READY)
	{
		if (stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(KERNEL_TABLE_CHECK_OPERATION) &&
			stack->Parameters.DeviceIoControl.OutputBufferLength == sizeof(KERNEL_TABLE_CHECK_OPERATION))
		{
			PKERNEL_TABLE_CHECK_OPERATION request = (PKERNEL_TABLE_CHECK_OPERATION)Irp->AssociatedIrp.SystemBuffer;

			__try
			{
				if (request->targetProcessId)
					CheckTablesReady((HANDLE)(LONG_PTR)request->targetProcessId, &request->status);
				else
					request->status = TABLES_NO_IMPORTS;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				request->status = TABLES_NOT_READY;
			}

			status = STATUS_SUCCESS;
			bytesIO = sizeof(KERNEL_TABLE_CHECK_OPERATION);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytesIO = 0;
		}
	}
	else if (controlCode == IO_GET_EXPORT_MAP)
	{
		if (stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(EXPORT_MAP_OPERATION) &&
			stack->Parameters.DeviceIoControl.OutputBufferLength == sizeof(EXPORT_MAP_OPERATION))
		{
			PEXPORT_MAP_OPERATION request = (PEXPORT_MAP_OPERATION)Irp->AssociatedIrp.SystemBuffer;

			if (!request->targetProcessId || IsCriticalProcess(request->targetProcessId))
			{
				status = STATUS_INVALID_PARAMETER;
				bytesIO = 0;
			}
			else
			{
				__try
				{
					if (request->bufferAddress && IsValidBufferSize(request->bufferSize))
						ProbeForWrite(request->bufferAddress, request->bufferSize, sizeof(UCHAR));

					GetExportMap((HANDLE)(LONG_PTR)request->targetProcessId, request->bufferAddress, request->bufferSize, &request->requiredSize, &request->moduleCount);
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					status = GetExceptionCode();
					Irp->IoStatus.Status = status;
					Irp->IoStatus.Information = 0;
					IoCompleteRequest(Irp, IO_NO_INCREMENT);
					return status;
				}

				status = STATUS_SUCCESS;
				bytesIO = sizeof(EXPORT_MAP_OPERATION);
			}
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytesIO = 0;
		}
	}
	else if (controlCode == IO_SUSPEND_PROCESS)
	{
		if (stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(KERNEL_SUSPEND_OPERATION) &&
			stack->Parameters.DeviceIoControl.OutputBufferLength == sizeof(KERNEL_SUSPEND_OPERATION))
		{
			PKERNEL_SUSPEND_OPERATION request = (PKERNEL_SUSPEND_OPERATION)Irp->AssociatedIrp.SystemBuffer;

			__try
			{
				if (request->targetProcessId && !IsCriticalProcess(request->targetProcessId))
					SuspendProcessThreads((HANDLE)(LONG_PTR)request->targetProcessId, &request->threadCount);
				else
					request->threadCount = 0;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				request->threadCount = -1;
			}

			status = STATUS_SUCCESS;
			bytesIO = sizeof(KERNEL_SUSPEND_OPERATION);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytesIO = 0;
		}
	}
	else if (controlCode == IO_RESUME_PROCESS)
	{
		if (stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(KERNEL_SUSPEND_OPERATION) &&
			stack->Parameters.DeviceIoControl.OutputBufferLength == sizeof(KERNEL_SUSPEND_OPERATION))
		{
			PKERNEL_SUSPEND_OPERATION request = (PKERNEL_SUSPEND_OPERATION)Irp->AssociatedIrp.SystemBuffer;

			__try
			{
				if (request->targetProcessId && !IsCriticalProcess(request->targetProcessId))
					ResumeProcessThreads((HANDLE)(LONG_PTR)request->targetProcessId, &request->threadCount);
				else
					request->threadCount = 0;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				request->threadCount = -1;
			}

			status = STATUS_SUCCESS;
			bytesIO = sizeof(KERNEL_SUSPEND_OPERATION);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytesIO = 0;
		}
	}
	else if (controlCode == IO_DUMP_STRINGS)
	{
		if (stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(KERNEL_STRING_DUMP_OPERATION) &&
			stack->Parameters.DeviceIoControl.OutputBufferLength == sizeof(KERNEL_STRING_DUMP_OPERATION))
		{
			PKERNEL_STRING_DUMP_OPERATION request = (PKERNEL_STRING_DUMP_OPERATION)Irp->AssociatedIrp.SystemBuffer;

			if (!request->targetProcessId || IsCriticalProcess(request->targetProcessId))
			{
				status = STATUS_INVALID_PARAMETER;
				bytesIO = 0;
			}
			else
			{
				__try
				{
					if (request->bufferAddress && IsValidBufferSize(request->bufferSize))
						ProbeForWrite(request->bufferAddress, request->bufferSize, sizeof(UCHAR));

					DumpProcessStrings(
					(HANDLE)(LONG_PTR)request->targetProcessId,
					request->minStringLength,
					request->bufferAddress,
					request->bufferSize,
					&request->requiredSize,
					&request->stringCount);
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					status = GetExceptionCode();
					Irp->IoStatus.Status = status;
					Irp->IoStatus.Information = 0;
					IoCompleteRequest(Irp, IO_NO_INCREMENT);
					return status;
				}

				status = STATUS_SUCCESS;
				bytesIO = sizeof(KERNEL_STRING_DUMP_OPERATION);
			}
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytesIO = 0;
		}
	}
	else if (controlCode == IO_ENUM_REGIONS)
	{
		if (stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(KERNEL_ENUM_REGIONS_OPERATION) &&
			stack->Parameters.DeviceIoControl.OutputBufferLength == sizeof(KERNEL_ENUM_REGIONS_OPERATION))
		{
			PKERNEL_ENUM_REGIONS_OPERATION request = (PKERNEL_ENUM_REGIONS_OPERATION)Irp->AssociatedIrp.SystemBuffer;

			if (!request->targetProcessId || IsCriticalProcess(request->targetProcessId))
			{
				status = STATUS_INVALID_PARAMETER;
				bytesIO = 0;
			}
			else
			{
				__try
				{
					if (request->bufferAddress && IsValidBufferSize(request->bufferSize))
						ProbeForWrite(request->bufferAddress, request->bufferSize, sizeof(UCHAR));

					EnumProcessRegions(
					(HANDLE)(LONG_PTR)request->targetProcessId,
					request->bufferAddress,
					request->bufferSize,
					&request->requiredSize,
					&request->regionCount);
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					status = GetExceptionCode();
					Irp->IoStatus.Status = status;
					Irp->IoStatus.Information = 0;
					IoCompleteRequest(Irp, IO_NO_INCREMENT);
					return status;
				}

				status = STATUS_SUCCESS;
				bytesIO = sizeof(KERNEL_ENUM_REGIONS_OPERATION);
			}
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytesIO = 0;
		}
	}
	else if (controlCode == IO_FIND_PATTERN)
	{
		if (stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(KERNEL_PATTERN_SCAN_OPERATION) &&
			stack->Parameters.DeviceIoControl.OutputBufferLength == sizeof(KERNEL_PATTERN_SCAN_OPERATION))
		{
			PKERNEL_PATTERN_SCAN_OPERATION request = (PKERNEL_PATTERN_SCAN_OPERATION)Irp->AssociatedIrp.SystemBuffer;

			// Validate: prevent integer overflow in maxResults * sizeof(UINT64)
			if (request->maxResults <= 0 || request->maxResults > 100000 ||
				request->patternLength <= 0 || request->patternLength > 4096 ||
				!request->targetProcessId || IsCriticalProcess(request->targetProcessId))
			{
				status = STATUS_INVALID_PARAMETER;
				bytesIO = 0;
			}
			else
			{
				__try
				{
					if (request->patternAddress && request->patternLength > 0)
						ProbeForRead(request->patternAddress, request->patternLength, sizeof(UCHAR));
					if (request->resultsAddress && request->maxResults > 0)
						ProbeForWrite(request->resultsAddress, (SIZE_T)request->maxResults * sizeof(UINT64), sizeof(UCHAR));

					ScanProcessPattern(
						(HANDLE)(LONG_PTR)request->targetProcessId,
						(PUCHAR)request->patternAddress,
						request->patternLength,
						request->wildcardByte,
						(PUINT64)request->resultsAddress,
						request->maxResults,
						&request->matchCount);
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					status = GetExceptionCode();
					Irp->IoStatus.Status = status;
					Irp->IoStatus.Information = 0;
					IoCompleteRequest(Irp, IO_NO_INCREMENT);
					return status;
				}

				status = STATUS_SUCCESS;
				bytesIO = sizeof(KERNEL_PATTERN_SCAN_OPERATION);
			}
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytesIO = 0;
		}
	}
	else if (controlCode == IO_READ_IL2CPP_METADATA)
	{
		if (stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(KERNEL_IL2CPP_METADATA_OPERATION) &&
			stack->Parameters.DeviceIoControl.OutputBufferLength == sizeof(KERNEL_IL2CPP_METADATA_OPERATION))
		{
			PKERNEL_IL2CPP_METADATA_OPERATION request = (PKERNEL_IL2CPP_METADATA_OPERATION)Irp->AssociatedIrp.SystemBuffer;

			if (!request->targetProcessId || IsCriticalProcess(request->targetProcessId))
			{
				status = STATUS_INVALID_PARAMETER;
				bytesIO = 0;
			}
			else
			{
				__try
				{
					if (request->bufferAddress && IsValidBufferSize(request->bufferSize))
						ProbeForWrite(request->bufferAddress, request->bufferSize, sizeof(UCHAR));

					DumpIl2CppMetadata(
					(HANDLE)(LONG_PTR)request->targetProcessId,
					request->bufferAddress,
					request->bufferSize,
					&request->metadataSize,
					&request->metadataAddress);
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					status = GetExceptionCode();
					Irp->IoStatus.Status = status;
					Irp->IoStatus.Information = 0;
					IoCompleteRequest(Irp, IO_NO_INCREMENT);
					return status;
				}

				status = STATUS_SUCCESS;
				bytesIO = sizeof(KERNEL_IL2CPP_METADATA_OPERATION);
			}
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytesIO = 0;
		}
	}
	else if (controlCode == IO_KILL_PROCESS_BY_NAME)
	{
		if (stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(KERNEL_KILL_PROCESS_OPERATION) &&
			stack->Parameters.DeviceIoControl.OutputBufferLength == sizeof(KERNEL_KILL_PROCESS_OPERATION))
		{
			PKERNEL_KILL_PROCESS_OPERATION request = (PKERNEL_KILL_PROCESS_OPERATION)Irp->AssociatedIrp.SystemBuffer;

			__try
			{
				KillProcessByName(request->processName, &request->killedPid, &request->status);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				request->status = 2;
				request->killedPid = -1;
			}

			status = STATUS_SUCCESS;
			bytesIO = sizeof(KERNEL_KILL_PROCESS_OPERATION);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytesIO = 0;
		}
	}
	else if (controlCode == IO_UNLOAD_DRIVER_BY_NAME)
	{
		if (stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(KERNEL_UNLOAD_DRIVER_OPERATION) &&
			stack->Parameters.DeviceIoControl.OutputBufferLength == sizeof(KERNEL_UNLOAD_DRIVER_OPERATION))
		{
			PKERNEL_UNLOAD_DRIVER_OPERATION request = (PKERNEL_UNLOAD_DRIVER_OPERATION)Irp->AssociatedIrp.SystemBuffer;

			__try
			{
				UnloadDriverByName(request->driverName, &request->status);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				request->status = 2;
			}

			status = STATUS_SUCCESS;
			bytesIO = sizeof(KERNEL_UNLOAD_DRIVER_OPERATION);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytesIO = 0;
		}
	}
	else if (controlCode == IO_UNLOAD_MODULE)
	{
		if (stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(KERNEL_UNLOAD_MODULE_OPERATION) &&
			stack->Parameters.DeviceIoControl.OutputBufferLength == sizeof(KERNEL_UNLOAD_MODULE_OPERATION))
		{
			PKERNEL_UNLOAD_MODULE_OPERATION request = (PKERNEL_UNLOAD_MODULE_OPERATION)Irp->AssociatedIrp.SystemBuffer;

			__try
			{
				if (request->targetProcessId && request->moduleBaseAddress)
					UnloadModule((HANDLE)(LONG_PTR)request->targetProcessId, request->moduleBaseAddress, &request->status);
				else
					request->status = 2;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				request->status = 2;
			}

			status = STATUS_SUCCESS;
			bytesIO = sizeof(KERNEL_UNLOAD_MODULE_OPERATION);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytesIO = 0;
		}
	}
	else if (controlCode == IO_LSASS_READ_MEMORY)
	{
		if (stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(KERNEL_LSASS_READ_OPERATION) &&
			stack->Parameters.DeviceIoControl.OutputBufferLength == sizeof(KERNEL_LSASS_READ_OPERATION))
		{
			PKERNEL_LSASS_READ_OPERATION request = (PKERNEL_LSASS_READ_OPERATION)Irp->AssociatedIrp.SystemBuffer;

			__try
			{
				if (request->bufferAddress && IsValidBufferSize(request->bufferSize))
					ProbeForWrite(request->bufferAddress, request->bufferSize, sizeof(UCHAR));

				LsassReadMemory(
					(HANDLE)(LONG_PTR)request->targetProcessId,
					request->targetAddress,
					request->bufferAddress,
					request->bufferSize,
					&request->status);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				status = GetExceptionCode();
				Irp->IoStatus.Status = status;
				Irp->IoStatus.Information = 0;
				IoCompleteRequest(Irp, IO_NO_INCREMENT);
				return status;
			}

			status = STATUS_SUCCESS;
			bytesIO = sizeof(KERNEL_LSASS_READ_OPERATION);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytesIO = 0;
		}
	}
	else if (controlCode == IO_ENUM_DRIVERS)
	{
		if (stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(KERNEL_DRIVER_LIST_OPERATION) &&
			stack->Parameters.DeviceIoControl.OutputBufferLength == sizeof(KERNEL_DRIVER_LIST_OPERATION))
		{
			PKERNEL_DRIVER_LIST_OPERATION request = (PKERNEL_DRIVER_LIST_OPERATION)Irp->AssociatedIrp.SystemBuffer;

			__try
			{
				if (request->bufferAddress && IsValidBufferSize(request->bufferSize))
					ProbeForWrite(request->bufferAddress, request->bufferSize, sizeof(UCHAR));

				EnumerateLoadedDrivers(request->bufferAddress, request->bufferSize, &request->requiredSize, &request->driverCount);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				status = GetExceptionCode();
				Irp->IoStatus.Status = status;
				Irp->IoStatus.Information = 0;
				IoCompleteRequest(Irp, IO_NO_INCREMENT);
				return status;
			}

			status = STATUS_SUCCESS;
			bytesIO = sizeof(KERNEL_DRIVER_LIST_OPERATION);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytesIO = 0;
		}
	}
	else if (controlCode == IO_GET_THREAD_CONTEXT)
	{
		if (stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(KERNEL_THREAD_CONTEXT_OPERATION) &&
			stack->Parameters.DeviceIoControl.OutputBufferLength == sizeof(KERNEL_THREAD_CONTEXT_OPERATION))
		{
			PKERNEL_THREAD_CONTEXT_OPERATION request = (PKERNEL_THREAD_CONTEXT_OPERATION)Irp->AssociatedIrp.SystemBuffer;

			if (!request->targetProcessId || IsCriticalProcess(request->targetProcessId))
			{
				status = STATUS_INVALID_PARAMETER;
				bytesIO = 0;
			}
			else
			{
				__try
				{
					if (request->contextBuffer && request->contextSize > 0 && request->contextSize <= 2048)
						ProbeForWrite(request->contextBuffer, request->contextSize, sizeof(UCHAR));

					KernelGetThreadContext(
						(HANDLE)(LONG_PTR)request->targetProcessId,
						(HANDLE)(LONG_PTR)request->threadId,
						request->contextBuffer,
						request->contextSize,
						request->contextFlags,
						&request->status);
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					request->status = 2;
				}

				status = STATUS_SUCCESS;
				bytesIO = sizeof(KERNEL_THREAD_CONTEXT_OPERATION);
			}
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytesIO = 0;
		}
	}
	else if (controlCode == IO_SET_THREAD_CONTEXT)
	{
		if (stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(KERNEL_THREAD_CONTEXT_OPERATION) &&
			stack->Parameters.DeviceIoControl.OutputBufferLength == sizeof(KERNEL_THREAD_CONTEXT_OPERATION))
		{
			PKERNEL_THREAD_CONTEXT_OPERATION request = (PKERNEL_THREAD_CONTEXT_OPERATION)Irp->AssociatedIrp.SystemBuffer;

			if (!request->targetProcessId || IsCriticalProcess(request->targetProcessId))
			{
				status = STATUS_INVALID_PARAMETER;
				bytesIO = 0;
			}
			else
			{
				__try
				{
					if (request->contextBuffer && request->contextSize > 0 && request->contextSize <= 2048)
						ProbeForRead(request->contextBuffer, request->contextSize, sizeof(UCHAR));

					KernelSetThreadContext(
						(HANDLE)(LONG_PTR)request->targetProcessId,
						(HANDLE)(LONG_PTR)request->threadId,
						request->contextBuffer,
						request->contextSize,
						&request->status);
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					request->status = 2;
				}

				status = STATUS_SUCCESS;
				bytesIO = sizeof(KERNEL_THREAD_CONTEXT_OPERATION);
			}
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytesIO = 0;
		}
	}
	else if (controlCode == IO_DEBUG_ACTIVE_PROCESS)
	{
		if (stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(KERNEL_DEBUG_OPERATION) &&
			stack->Parameters.DeviceIoControl.OutputBufferLength == sizeof(KERNEL_DEBUG_OPERATION))
		{
			PKERNEL_DEBUG_OPERATION request = (PKERNEL_DEBUG_OPERATION)Irp->AssociatedIrp.SystemBuffer;

			__try
			{
				if (request->targetProcessId && !IsCriticalProcess(request->targetProcessId))
					KernelDebugAttach((HANDLE)(LONG_PTR)request->targetProcessId, &request->status);
				else
					request->status = 2;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				request->status = 2;
			}

			status = STATUS_SUCCESS;
			bytesIO = sizeof(KERNEL_DEBUG_OPERATION);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytesIO = 0;
		}
	}
	else if (controlCode == IO_DEBUG_WAIT_EVENT)
	{
		if (stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(KERNEL_DEBUG_WAIT_OPERATION) &&
			stack->Parameters.DeviceIoControl.OutputBufferLength == sizeof(KERNEL_DEBUG_WAIT_OPERATION))
		{
			PKERNEL_DEBUG_WAIT_OPERATION request = (PKERNEL_DEBUG_WAIT_OPERATION)Irp->AssociatedIrp.SystemBuffer;

			__try
			{
				if (request->eventBuffer && request->bufferSize > 0)
					ProbeForWrite(request->eventBuffer, request->bufferSize, sizeof(UCHAR));

				KernelDebugWaitEvent(
					request->timeoutMs,
					request->eventBuffer,
					request->bufferSize,
					&request->eventCode,
					&request->threadId,
					&request->eventAddress,
					&request->exceptionCode,
					&request->status);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				request->status = 3;
			}

			status = STATUS_SUCCESS;
			bytesIO = sizeof(KERNEL_DEBUG_WAIT_OPERATION);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytesIO = 0;
		}
	}
	else if (controlCode == IO_DEBUG_CONTINUE)
	{
		if (stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(KERNEL_DEBUG_CONTINUE_OPERATION) &&
			stack->Parameters.DeviceIoControl.OutputBufferLength == sizeof(KERNEL_DEBUG_CONTINUE_OPERATION))
		{
			PKERNEL_DEBUG_CONTINUE_OPERATION request = (PKERNEL_DEBUG_CONTINUE_OPERATION)Irp->AssociatedIrp.SystemBuffer;

			__try
			{
				KernelDebugContinue(request->threadId, request->continueStatus, &request->status);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				request->status = 2;
			}

			status = STATUS_SUCCESS;
			bytesIO = sizeof(KERNEL_DEBUG_CONTINUE_OPERATION);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytesIO = 0;
		}
	}
	else if (controlCode == IO_ENUM_KERNEL_CALLBACKS)
	{
		if (stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(KERNEL_CALLBACK_OPERATION) &&
			stack->Parameters.DeviceIoControl.OutputBufferLength == sizeof(KERNEL_CALLBACK_OPERATION))
		{
			PKERNEL_CALLBACK_OPERATION request = (PKERNEL_CALLBACK_OPERATION)Irp->AssociatedIrp.SystemBuffer;

			__try
			{
				if (request->bufferAddress && IsValidBufferSize(request->bufferSize))
					ProbeForWrite(request->bufferAddress, request->bufferSize, sizeof(UCHAR));

				EnumKernelCallbacks(request->bufferAddress, request->bufferSize,
					&request->callbackCount, &request->removedCount, request->removeCallbacks);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				request->callbackCount = 0;
				request->removedCount = 0;
			}

			status = STATUS_SUCCESS;
			bytesIO = sizeof(KERNEL_CALLBACK_OPERATION);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytesIO = 0;
		}
	}
	else if (controlCode == IO_CLONE_PROCESS)
	{
		if (stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(KERNEL_CLONE_PROCESS_OPERATION) &&
			stack->Parameters.DeviceIoControl.OutputBufferLength == sizeof(KERNEL_CLONE_PROCESS_OPERATION))
		{
			PKERNEL_CLONE_PROCESS_OPERATION request = (PKERNEL_CLONE_PROCESS_OPERATION)Irp->AssociatedIrp.SystemBuffer;

			__try
			{
				if (request->targetProcessId && !IsCriticalProcess(request->targetProcessId))
					CloneProcess((HANDLE)(LONG_PTR)request->targetProcessId, &request->clonedProcessId, &request->status);
				else
					request->status = 2;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				request->status = 2;
				request->clonedProcessId = -1;
			}

			status = STATUS_SUCCESS;
			bytesIO = sizeof(KERNEL_CLONE_PROCESS_OPERATION);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytesIO = 0;
		}
	}
	else if (controlCode == IO_ENUM_VAD)
	{
		if (stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(KERNEL_VAD_OPERATION) &&
			stack->Parameters.DeviceIoControl.OutputBufferLength == sizeof(KERNEL_VAD_OPERATION))
		{
			PKERNEL_VAD_OPERATION request = (PKERNEL_VAD_OPERATION)Irp->AssociatedIrp.SystemBuffer;

			if (!request->targetProcessId || IsCriticalProcess(request->targetProcessId))
			{
				status = STATUS_INVALID_PARAMETER;
				bytesIO = 0;
			}
			else
			{
				__try
				{
					if (request->bufferAddress && IsValidBufferSize(request->bufferSize))
						ProbeForWrite(request->bufferAddress, request->bufferSize, sizeof(UCHAR));

					EnumVadTree((HANDLE)(LONG_PTR)request->targetProcessId,
						request->bufferAddress, request->bufferSize,
						&request->requiredSize, &request->vadCount);
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					status = GetExceptionCode();
					Irp->IoStatus.Status = status;
					Irp->IoStatus.Information = 0;
					IoCompleteRequest(Irp, IO_NO_INCREMENT);
					return status;
				}

				status = STATUS_SUCCESS;
				bytesIO = sizeof(KERNEL_VAD_OPERATION);
			}
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytesIO = 0;
		}
	}
	else if (controlCode == IO_ENUM_HANDLES)
	{
		if (stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(KERNEL_HANDLE_OPERATION) &&
			stack->Parameters.DeviceIoControl.OutputBufferLength == sizeof(KERNEL_HANDLE_OPERATION))
		{
			PKERNEL_HANDLE_OPERATION request = (PKERNEL_HANDLE_OPERATION)Irp->AssociatedIrp.SystemBuffer;

			__try
			{
				if (request->bufferAddress && IsValidBufferSize(request->bufferSize))
					ProbeForWrite(request->bufferAddress, request->bufferSize, sizeof(UCHAR));

				EnumHandles((HANDLE)(LONG_PTR)request->targetProcessId,
					request->bufferAddress, request->bufferSize,
					&request->requiredSize, &request->handleCount);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				status = GetExceptionCode();
				Irp->IoStatus.Status = status;
				Irp->IoStatus.Information = 0;
				IoCompleteRequest(Irp, IO_NO_INCREMENT);
				return status;
			}

			status = STATUS_SUCCESS;
			bytesIO = sizeof(KERNEL_HANDLE_OPERATION);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytesIO = 0;
		}
	}
	else if (controlCode == IO_ENUM_KERNEL_MODULES)
	{
		if (stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(KERNEL_MODULE_ENUM_OPERATION) &&
			stack->Parameters.DeviceIoControl.OutputBufferLength == sizeof(KERNEL_MODULE_ENUM_OPERATION))
		{
			PKERNEL_MODULE_ENUM_OPERATION request = (PKERNEL_MODULE_ENUM_OPERATION)Irp->AssociatedIrp.SystemBuffer;

			__try
			{
				if (request->bufferAddress && IsValidBufferSize(request->bufferSize))
					ProbeForWrite(request->bufferAddress, request->bufferSize, sizeof(UCHAR));

				EnumKernelModules(request->bufferAddress, request->bufferSize,
					&request->requiredSize, &request->moduleCount);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				status = GetExceptionCode();
				Irp->IoStatus.Status = status;
				Irp->IoStatus.Information = 0;
				IoCompleteRequest(Irp, IO_NO_INCREMENT);
				return status;
			}

			status = STATUS_SUCCESS;
			bytesIO = sizeof(KERNEL_MODULE_ENUM_OPERATION);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytesIO = 0;
		}
	}
	else
	{
		status = STATUS_INVALID_PARAMETER;
		bytesIO = 0;
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = bytesIO;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}

NTSTATUS UnsupportedDispatch(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

NTSTATUS CreateDispatch(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

NTSTATUS CloseDispatch(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

NTSTATUS Unload(IN PDRIVER_OBJECT DriverObject)
{
	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(DriverObject->DeviceObject);
	return STATUS_SUCCESS;
}

NTSTATUS RealDriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS status;
	PDEVICE_OBJECT deviceObject;

	RtlInitUnicodeString(&deviceName, L"\\Device\\KsDumper");
	RtlInitUnicodeString(&symLink, L"\\DosDevices\\KsDumper");

	status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &deviceObject);

	if (!NT_SUCCESS(status))
		return status;

	status = IoCreateSymbolicLink(&symLink, &deviceName);

	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(deviceObject);
		return status;
	}

	deviceObject->Flags |= DO_BUFFERED_IO;

	for (ULONG t = 0; t <= IRP_MJ_MAXIMUM_FUNCTION; t++)
		DriverObject->MajorFunction[t] = &UnsupportedDispatch;

	DriverObject->MajorFunction[IRP_MJ_CREATE] = &CreateDispatch;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = &CloseDispatch;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &IoControl;
	DriverObject->DriverUnload = &Unload;
	deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	if (DriverObject == NULL)
	{
		UNICODE_STRING driverName;
		RtlInitUnicodeString(&driverName, L"\\Driver\\KsDumper");
		return IoCreateDriver(&driverName, (PDRIVER_INITIALIZE)&RealDriverEntry);
	}

	return RealDriverEntry(DriverObject, RegistryPath);
}
