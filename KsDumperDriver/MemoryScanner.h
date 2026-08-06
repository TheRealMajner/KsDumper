#pragma once
#include <ntddk.h>

// --- Memory Region Enumeration ---

#pragma pack(push, 1)
typedef struct _REGION_ENTRY_PACKED
{
	UINT64 BaseAddress;
	UINT64 RegionSize;
	UINT32 Protect;
	UINT32 State;
	UINT32 Type;
} REGION_ENTRY_PACKED, *PREGION_ENTRY_PACKED;
#pragma pack(pop)

typedef struct _KERNEL_ENUM_REGIONS_OPERATION
{
	INT32 targetProcessId;
	PVOID bufferAddress;
	INT32 bufferSize;
	INT32 requiredSize;
	INT32 regionCount;
} KERNEL_ENUM_REGIONS_OPERATION, *PKERNEL_ENUM_REGIONS_OPERATION;

// --- Pattern Scanning ---

typedef struct _KERNEL_PATTERN_SCAN_OPERATION
{
	INT32 targetProcessId;
	PVOID patternAddress;    // Pointer to pattern bytes in user-mode
	INT32 patternLength;
	UINT8 wildcardByte;      // Byte value used as wildcard (e.g. 0xCC)
	PVOID resultsAddress;    // Pointer to UINT64[] in user-mode
	INT32 maxResults;
	INT32 matchCount;        // Output: matches found
} KERNEL_PATTERN_SCAN_OPERATION, *PKERNEL_PATTERN_SCAN_OPERATION;

// --- Il2Cpp Metadata Dump ---

typedef struct _KERNEL_IL2CPP_METADATA_OPERATION
{
	INT32 targetProcessId;
	PVOID bufferAddress;     // User-allocated output buffer
	INT32 bufferSize;
	INT32 metadataSize;     // Output: size of metadata (or required size)
	UINT64 metadataAddress; // Output: virtual address of metadata in target
} KERNEL_IL2CPP_METADATA_OPERATION, *PKERNEL_IL2CPP_METADATA_OPERATION;

// Function declarations
NTSTATUS EnumProcessRegions(HANDLE processId, PVOID bufferAddress, INT32 bufferSize, PINT32 requiredSize, PINT32 regionCount);
NTSTATUS ScanProcessPattern(HANDLE processId, PUCHAR pattern, INT32 patternLength, UINT8 wildcard, PUINT64 results, INT32 maxResults, PINT32 matchCount);
NTSTATUS DumpIl2CppMetadata(HANDLE processId, PVOID bufferAddress, INT32 bufferSize, PINT32 metadataSize, PUINT64 metadataAddress);
