#pragma once
#include <ntddk.h>

NTSTATUS GetExportMap(HANDLE processId, PVOID outputBuffer, INT32 bufferSize, PINT32 requiredSize, PINT32 moduleCount);
