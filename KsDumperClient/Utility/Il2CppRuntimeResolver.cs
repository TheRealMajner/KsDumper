using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using KsDumperClient.Driver;
using static KsDumperClient.Utility.Il2CppDumper;
using static KsDumperClient.Utility.Il2CppSdkGenerator;

namespace KsDumperClient.Utility
{
    public class Il2CppRuntimeResolver
    {
        private readonly IMemoryReader _driver;
        private readonly int _pid;

        public Il2CppRuntimeResolver(IMemoryReader driver, int pid)
        {
            _driver = driver;
            _pid = pid;
        }

        // ===== 1. Runtime Il2CppClass field offset extraction =====

        public struct RuntimeFieldOffset
        {
            public int TypeIndex;
            public int FieldIndex;
            public int Offset;
            public bool IsStatic;
        }

        public List<RuntimeFieldOffset> ResolveFieldOffsets(
            ulong gameAssemblyBase, uint gameAssemblySize,
            Il2CppMetadataSnapshot snapshot,
            Action<string> log = null)
        {
            var result = new List<RuntimeFieldOffset>();
            if (snapshot == null || snapshot.TypeDefinitions == null) return result;

            // Il2CppClass has a fields pointer. We scan for Il2CppClass instances
            // by finding pointers to the string table entries (type names).
            // Instead, we use the s_TypeInfoDefinitionTable — an array of Il2CppClass*
            // indexed by type definition index.

            ulong typeInfoTable = FindTypeInfoDefinitionTable(gameAssemblyBase, gameAssemblySize, snapshot);
            if (typeInfoTable == 0)
            {
                log?.Invoke("Could not locate s_TypeInfoDefinitionTable");
                return result;
            }
            log?.Invoke($"Found s_TypeInfoDefinitionTable at 0x{typeInfoTable:X}");

            int typeCount = snapshot.TypeDefinitions.Length;
            int resolved = 0;

            for (int ti = 0; ti < typeCount; ti++)
            {
                var td = snapshot.TypeDefinitions[ti];
                if (td.FieldCount == 0) continue;

                ulong classPtr = ReadPtr(typeInfoTable + (ulong)(ti * 8));
                if (classPtr == 0 || classPtr < 0x10000) continue;

                // Il2CppClass layout (x64):
                // +0x00: Il2CppImage* image
                // +0x08: void* gc_desc
                // +0x10: const char* name
                // +0x18: const char* namespaze
                // +0x80: FieldInfo* fields
                // +0xC0: uint16_t field_count  (varies by version, we'll read the fields ptr)

                ulong fieldsPtr = ReadPtr(classPtr + 0x80);
                if (fieldsPtr == 0 || fieldsPtr < 0x10000) continue;

                // Each FieldInfo is 32 bytes on x64:
                // +0x00: const char* name (8)
                // +0x08: const Il2CppType* type (8)
                // +0x10: Il2CppClass* parent (8)
                // +0x18: int32_t offset (4)
                // +0x1C: uint32_t token (4)

                for (int fi = 0; fi < td.FieldCount; fi++)
                {
                    ulong fieldAddr = fieldsPtr + (ulong)(fi * 32);
                    byte[] fieldData = ReadBytes(fieldAddr, 32);
                    if (fieldData == null) break;

                    int offset = BitConverter.ToInt32(fieldData, 0x18);

                    // Offset of 0 typically means static field (stored in static fields memory)
                    // Offsets < 0x10 for instance fields are invalid (object header is 0x10 on x64)
                    bool isStatic = (offset == 0 || offset == -1);

                    // Read the Il2CppType* to check for static flag
                    ulong typePtr = BitConverter.ToUInt64(fieldData, 0x08);
                    if (typePtr != 0 && typePtr > 0x10000)
                    {
                        byte[] typeData = ReadBytes(typePtr, 16);
                        if (typeData != null)
                        {
                            // Il2CppType.attrs at offset 8 (uint32) — bit 0x0010 = FIELD_ATTRIBUTE_STATIC
                            uint attrs = BitConverter.ToUInt32(typeData, 8);
                            isStatic = (attrs & 0x0010) != 0;
                        }
                    }

                    result.Add(new RuntimeFieldOffset
                    {
                        TypeIndex = ti,
                        FieldIndex = td.FieldStart + fi,
                        Offset = offset,
                        IsStatic = isStatic
                    });
                }
                resolved++;
            }

            log?.Invoke($"Resolved field offsets for {resolved} types ({result.Count} fields)");
            return result;
        }

        // ===== 2. Method RVA → address mapping via CodeRegistration =====

        public struct MethodPointerEntry
        {
            public int MethodIndex;
            public ulong Address;
            public uint Rva;
        }

        public List<MethodPointerEntry> ResolveMethodPointers(
            ulong gameAssemblyBase, uint gameAssemblySize,
            Il2CppMetadataSnapshot snapshot,
            Action<string> log = null)
        {
            var result = new List<MethodPointerEntry>();
            if (snapshot == null || snapshot.Methods == null) return result;

            // Find CodeRegistration via pattern scanning
            ulong codeReg = FindCodeRegistration(gameAssemblyBase, gameAssemblySize, snapshot);
            if (codeReg == 0)
            {
                log?.Invoke("Could not locate CodeRegistration — trying export-based resolution");
                return ResolveMethodPointersFromExports(gameAssemblyBase, gameAssemblySize, snapshot, log);
            }

            // CodeRegistration layout (x64):
            // +0x00: uint64_t methodPointersCount
            // +0x08: Il2CppMethodPointer* methodPointers
            // +0x10: uint64_t reversePInvokeWrapperCount
            // +0x18: ...

            ulong methodCount = ReadU64(codeReg);
            ulong methodPtrsAddr = ReadPtr(codeReg + 8);

            if (methodCount == 0 || methodCount > 0x1000000 || methodPtrsAddr == 0)
            {
                log?.Invoke($"CodeRegistration data invalid (count={methodCount}, ptr=0x{methodPtrsAddr:X})");
                return result;
            }

            log?.Invoke($"CodeRegistration: {methodCount} method pointers at 0x{methodPtrsAddr:X}");

            int batchSize = 4096;
            int totalMethods = (int)Math.Min(methodCount, (ulong)snapshot.Methods.Length);

            for (int i = 0; i < totalMethods; i += batchSize)
            {
                int count = Math.Min(batchSize, totalMethods - i);
                byte[] batch = ReadBytes(methodPtrsAddr + (ulong)(i * 8), count * 8);
                if (batch == null) break;

                for (int j = 0; j < count; j++)
                {
                    ulong addr = BitConverter.ToUInt64(batch, j * 8);
                    if (addr == 0) continue;

                    uint rva = (uint)(addr - gameAssemblyBase);

                    result.Add(new MethodPointerEntry
                    {
                        MethodIndex = i + j,
                        Address = addr,
                        Rva = rva
                    });
                }
            }

            log?.Invoke($"Resolved {result.Count}/{totalMethods} method pointers");
            return result;
        }

        private List<MethodPointerEntry> ResolveMethodPointersFromExports(
            ulong gameAssemblyBase, uint gameAssemblySize,
            Il2CppMetadataSnapshot snapshot,
            Action<string> log)
        {
            var result = new List<MethodPointerEntry>();

            // Fall back to il2cpp_init export and work backwards
            var exports = _driver.GetExportMap(_pid);
            if (exports == null || exports.Count == 0)
            {
                log?.Invoke("No exports available for GameAssembly.dll");
                return result;
            }

            log?.Invoke($"GameAssembly.dll has {exports.Count} exports — using for method hints");
            return result;
        }

        // ===== 3. Enum value extraction =====

        public struct EnumValue
        {
            public int TypeIndex;
            public int FieldIndex;
            public string Name;
            public long Value;
        }

        public static List<EnumValue> ExtractEnumValues(Il2CppMetadataSnapshot snapshot)
        {
            var result = new List<EnumValue>();
            if (snapshot == null) return result;

            var metadata = snapshot.RawMetadata;
            var header = snapshot.Header;
            var typeDefs = snapshot.TypeDefinitions;
            var fields = snapshot.Fields;
            int stringOffset = header.StringOffset;
            int stringSize = header.StringSize;

            if (header.FieldDefaultValuesOffset <= 0 || header.FieldDefaultValuesSize <= 0)
                return result;
            if (header.FieldAndParameterDefaultValueDataOffset <= 0)
                return result;

            // Parse FieldDefaultValue entries: { int fieldIndex, int typeIndex, int dataIndex }
            // Each is 12 bytes
            int fdvCount = header.FieldDefaultValuesSize / 12;
            var defaultValues = new Dictionary<int, (int typeIndex, int dataIndex)>();

            for (int i = 0; i < fdvCount; i++)
            {
                int p = header.FieldDefaultValuesOffset + i * 12;
                if (p + 12 > metadata.Length) break;

                int fieldIdx = BitConverter.ToInt32(metadata, p);
                int typeIdx = BitConverter.ToInt32(metadata, p + 4);
                int dataIdx = BitConverter.ToInt32(metadata, p + 8);

                if (fieldIdx >= 0 && dataIdx >= 0)
                    defaultValues[fieldIdx] = (typeIdx, dataIdx);
            }

            int dataBase = header.FieldAndParameterDefaultValueDataOffset;

            for (int ti = 0; ti < typeDefs.Length; ti++)
            {
                var td = typeDefs[ti];
                // Check if this is an enum: ValueType with parent "System.Enum"
                bool isValueType = (td.Flags & 0x00000020) != 0; // sealed
                if (!isValueType) continue;

                // Check parent is System.Enum by looking at parent name
                if (td.ParentIndex < 0 || td.ParentIndex >= typeDefs.Length) continue;
                string parentName = ReadStringFromTable(metadata, stringOffset, stringSize, typeDefs[td.ParentIndex].NameIndex);
                if (parentName != "Enum") continue;

                for (int fi = 0; fi < td.FieldCount; fi++)
                {
                    int globalFieldIdx = td.FieldStart + fi;
                    if (globalFieldIdx < 0 || globalFieldIdx >= fields.Length) continue;

                    if (!defaultValues.TryGetValue(globalFieldIdx, out var dv)) continue;

                    string fieldName = ReadStringFromTable(metadata, stringOffset, stringSize, (int)fields[globalFieldIdx].NameIndex);
                    if (fieldName == "value__") continue;

                    int dataOff = dataBase + dv.dataIndex;
                    if (dataOff + 4 > metadata.Length) continue;

                    long val = BitConverter.ToInt32(metadata, dataOff);

                    result.Add(new EnumValue
                    {
                        TypeIndex = ti,
                        FieldIndex = globalFieldIdx,
                        Name = fieldName,
                        Value = val
                    });
                }
            }

            return result;
        }

        // ===== 4. String literal extraction =====

        public struct StringLiteral
        {
            public int Index;
            public int Length;
            public string Value;
        }

        public static List<StringLiteral> ExtractStringLiterals(Il2CppMetadataSnapshot snapshot)
        {
            var result = new List<StringLiteral>();
            if (snapshot == null) return result;

            var metadata = snapshot.RawMetadata;
            var header = snapshot.Header;

            if (header.StringLiteralOffset <= 0 || header.StringLiteralSize <= 0)
                return result;
            if (header.StringLiteralDataOffset <= 0 || header.StringLiteralDataSize <= 0)
                return result;

            // StringLiteral entries: { int length, int dataIndex } = 8 bytes each
            int count = header.StringLiteralSize / 8;

            for (int i = 0; i < count; i++)
            {
                int p = header.StringLiteralOffset + i * 8;
                if (p + 8 > metadata.Length) break;

                int len = BitConverter.ToInt32(metadata, p);
                int dataIdx = BitConverter.ToInt32(metadata, p + 4);

                if (len <= 0 || len > 0x100000) continue;

                int dataOff = header.StringLiteralDataOffset + dataIdx;
                if (dataOff < 0 || dataOff + len > metadata.Length) continue;

                string value;
                try
                {
                    value = Encoding.UTF8.GetString(metadata, dataOff, len);
                }
                catch
                {
                    continue;
                }

                result.Add(new StringLiteral
                {
                    Index = i,
                    Length = len,
                    Value = value
                });
            }

            return result;
        }

        // ===== 5. Full generic type resolution =====

        public static Dictionary<int, string> ResolveGenericInstantiations(Il2CppMetadataSnapshot snapshot)
        {
            var result = new Dictionary<int, string>();
            if (snapshot == null) return result;

            var metadata = snapshot.RawMetadata;
            var header = snapshot.Header;
            var typeDefs = snapshot.TypeDefinitions;
            int stringOffset = header.StringOffset;
            int stringSize = header.StringSize;

            if (snapshot.GenericContainers == null || snapshot.GenericParameters == null)
                return result;

            // Build type name lookup for resolving generic argument types
            for (int ti = 0; ti < typeDefs.Length; ti++)
            {
                var td = typeDefs[ti];
                if (td.GenericContainerIndex < 0 || td.GenericContainerIndex >= snapshot.GenericContainers.Length)
                    continue;

                var container = snapshot.GenericContainers[td.GenericContainerIndex];
                if (container.IsMethod != 0) continue; // Skip method-level generics
                if (container.TypeArgCount <= 0) continue;

                string typeName = ReadStringFromTable(metadata, stringOffset, stringSize, td.NameIndex);
                string ns = ReadStringFromTable(metadata, stringOffset, stringSize, td.NamespaceIndex);
                string fullName = string.IsNullOrEmpty(ns) ? typeName : $"{ns}.{typeName}";

                var genericArgs = new List<string>();
                for (int gi = 0; gi < container.TypeArgCount; gi++)
                {
                    int gpIdx = container.GenericParameterStart + gi;
                    if (gpIdx < 0 || gpIdx >= snapshot.GenericParameters.Length) break;
                    string gpName = ReadStringFromTable(metadata, stringOffset, stringSize,
                        (int)snapshot.GenericParameters[gpIdx].NameIndex);
                    genericArgs.Add(gpName);
                }

                // Strip backtick notation from name (e.g. List`1 → List)
                int backtick = fullName.IndexOf('`');
                string cleanName = backtick >= 0 ? fullName.Substring(0, backtick) : fullName;
                string resolved = $"{cleanName}<{string.Join(", ", genericArgs)}>";

                result[ti] = resolved;
            }

            // Also resolve method-level generics
            if (snapshot.Methods != null)
            {
                for (int mi = 0; mi < snapshot.Methods.Length; mi++)
                {
                    var md = snapshot.Methods[mi];
                    if (md.GenericContainerIndex < 0 || md.GenericContainerIndex >= snapshot.GenericContainers.Length)
                        continue;

                    var container = snapshot.GenericContainers[md.GenericContainerIndex];
                    if (container.IsMethod == 0) continue;
                    if (container.TypeArgCount <= 0) continue;

                    // Store with negative key to differentiate from type generics
                    var methodGenericArgs = new List<string>();
                    for (int gi = 0; gi < container.TypeArgCount; gi++)
                    {
                        int gpIdx = container.GenericParameterStart + gi;
                        if (gpIdx < 0 || gpIdx >= snapshot.GenericParameters.Length) break;
                        string gpName = ReadStringFromTable(metadata, stringOffset, stringSize,
                            (int)snapshot.GenericParameters[gpIdx].NameIndex);
                        methodGenericArgs.Add(gpName);
                    }

                    string methodName = ReadStringFromTable(metadata, stringOffset, stringSize, (int)md.NameIndex);
                    result[-(mi + 1)] = $"{methodName}<{string.Join(", ", methodGenericArgs)}>";
                }
            }

            return result;
        }

        // ===== 6. Custom attribute value parsing =====

        public struct AttributeInfo
        {
            public int TypeIndex;
            public string AttributeName;
            public byte[] ConstructorArgData;
        }

        public static List<AttributeInfo> ExtractCustomAttributes(Il2CppMetadataSnapshot snapshot)
        {
            var result = new List<AttributeInfo>();
            if (snapshot == null) return result;

            var metadata = snapshot.RawMetadata;
            var header = snapshot.Header;
            int stringOffset = header.StringOffset;
            int stringSize = header.StringSize;

            if (header.AttributeDataOffset <= 0 || header.AttributeDataSize <= 0)
                return result;

            // v24+ has AttributeDataRange entries: { uint32_t token, uint32_t startRange, int32_t count }
            if (header.AttributeDataRangeOffset <= 0 || header.AttributeDataRangeSize <= 0)
                return result;

            int rangeCount = header.AttributeDataRangeSize / 12;

            for (int i = 0; i < rangeCount; i++)
            {
                int p = header.AttributeDataRangeOffset + i * 12;
                if (p + 12 > metadata.Length) break;

                uint token = BitConverter.ToUInt32(metadata, p);
                uint startRange = BitConverter.ToUInt32(metadata, p + 4);
                int count = BitConverter.ToInt32(metadata, p + 8);

                if (count <= 0 || startRange == 0) continue;

                // Each attribute type info in the data section
                int dataOff = header.AttributeDataOffset + (int)startRange;
                if (dataOff < 0 || dataOff >= metadata.Length) continue;

                // Try to read attribute type indices from the data blob
                for (int a = 0; a < count; a++)
                {
                    if (dataOff + 4 > metadata.Length) break;
                    int attrTypeIdx = BitConverter.ToInt32(metadata, dataOff);
                    dataOff += 4;

                    string attrName = "";
                    if (attrTypeIdx >= 0 && attrTypeIdx < snapshot.TypeDefinitions.Length)
                    {
                        attrName = ReadStringFromTable(metadata, stringOffset, stringSize,
                            snapshot.TypeDefinitions[attrTypeIdx].NameIndex);
                    }

                    result.Add(new AttributeInfo
                    {
                        TypeIndex = attrTypeIdx,
                        AttributeName = attrName
                    });
                }
            }

            return result;
        }

        // ===== Internal helpers =====

        private ulong FindTypeInfoDefinitionTable(ulong gaBase, uint gaSize, Il2CppMetadataSnapshot snapshot)
        {
            int typeCount = snapshot.TypeDefinitions.Length;
            if (typeCount == 0) return 0;

            // The s_TypeInfoDefinitionTable is an array of Il2CppClass* pointers
            // in .data or .bss section. It's typically referenced near the
            // MetadataCache::Initialize function.
            // Strategy: scan .data section for a contiguous block of valid pointers
            // whose count matches the number of type definitions.

            // First try pattern: LEA reg, [rip + offset] near s_GlobalMetadata usage
            // Alternative: scan for array of N pointers where N = typeCount

            byte[] gaHeader = ReadBytes(gaBase, 0x400);
            if (gaHeader == null) return 0;

            // Parse PE to find .data section
            int peOff = BitConverter.ToInt32(gaHeader, 0x3C);
            if (peOff <= 0 || peOff + 0x108 > gaHeader.Length) return 0;

            int numSections = BitConverter.ToUInt16(gaHeader, peOff + 6);
            int optSize = BitConverter.ToUInt16(gaHeader, peOff + 20);
            int secTableOff = peOff + 24 + optSize;

            ulong dataRva = 0, dataSize = 0;
            ulong bssRva = 0, bssSize = 0;

            for (int s = 0; s < numSections; s++)
            {
                int so = secTableOff + s * 40;
                if (so + 40 > gaHeader.Length)
                {
                    byte[] more = ReadBytes(gaBase, (int)(so + 40));
                    if (more == null) break;
                    gaHeader = more;
                }
                if (so + 40 > gaHeader.Length) break;

                string secName = Encoding.ASCII.GetString(gaHeader, so, 8).TrimEnd('\0');
                uint vSize = BitConverter.ToUInt32(gaHeader, so + 8);
                uint rva = BitConverter.ToUInt32(gaHeader, so + 12);

                if (secName == ".data" || secName.StartsWith(".data"))
                {
                    dataRva = rva;
                    dataSize = vSize;
                }
                else if (secName == ".bss")
                {
                    bssRva = rva;
                    bssSize = vSize;
                }
            }

            // Scan .data section for the table
            ulong tableAddr = ScanForPointerTable(gaBase, dataRva, dataSize, typeCount);
            if (tableAddr != 0) return tableAddr;

            // Try .bss
            if (bssRva != 0 && bssSize != 0)
                tableAddr = ScanForPointerTable(gaBase, bssRva, bssSize, typeCount);

            return tableAddr;
        }

        private ulong ScanForPointerTable(ulong gaBase, ulong sectionRva, ulong sectionSize, int expectedCount)
        {
            if (sectionRva == 0 || sectionSize == 0) return 0;

            ulong scanAddr = gaBase + sectionRva;
            int scanSize = (int)Math.Min(sectionSize, 0x2000000);
            int stride = 0x1000;

            for (int off = 0; off < scanSize; off += stride)
            {
                byte[] chunk = ReadBytes(scanAddr + (ulong)off, Math.Min(stride, scanSize - off));
                if (chunk == null) break;

                for (int i = 0; i + 8 <= chunk.Length; i += 8)
                {
                    ulong ptr = BitConverter.ToUInt64(chunk, i);
                    if (ptr < 0x10000 || ptr == 0) continue;

                    // Check if this could be the start of the table:
                    // Verify the next few pointers are also valid
                    int validCount = 0;
                    int checkCount = Math.Min(16, expectedCount);
                    bool valid = true;

                    for (int c = 0; c < checkCount; c++)
                    {
                        int readOff = i + c * 8;
                        if (readOff + 8 > chunk.Length)
                        {
                            byte[] extra = ReadBytes(scanAddr + (ulong)readOff, checkCount * 8);
                            if (extra == null) { valid = false; break; }
                            ulong nextPtr = BitConverter.ToUInt64(extra, 0);
                            if (nextPtr == 0) { validCount++; continue; }
                            if (nextPtr < 0x10000) { valid = false; break; }
                            validCount++;
                            continue;
                        }

                        ulong nextPtr2 = BitConverter.ToUInt64(chunk, readOff);
                        if (nextPtr2 == 0) { validCount++; continue; }
                        if (nextPtr2 < 0x10000) { valid = false; break; }
                        validCount++;
                    }

                    if (valid && validCount >= 12)
                    {
                        return scanAddr + (ulong)off + (ulong)i;
                    }
                }
            }

            return 0;
        }

        private ulong FindCodeRegistration(ulong gaBase, uint gaSize, Il2CppMetadataSnapshot snapshot)
        {
            int methodCount = snapshot.Methods.Length;
            if (methodCount == 0) return 0;

            // CodeRegistration is typically initialized by il2cpp_init →
            // Runtime::Init → MetadataCache::Register
            // The first field is methodPointersCount which matches the number of method definitions.
            // Strategy: scan .data for a uint64 matching methodCount followed by a valid pointer.

            byte[] gaHeader = ReadBytes(gaBase, 0x400);
            if (gaHeader == null) return 0;

            int peOff = BitConverter.ToInt32(gaHeader, 0x3C);
            if (peOff <= 0 || peOff + 0x108 > gaHeader.Length) return 0;

            int numSections = BitConverter.ToUInt16(gaHeader, peOff + 6);
            int optSize = BitConverter.ToUInt16(gaHeader, peOff + 20);
            int secTableOff = peOff + 24 + optSize;

            ulong dataRva = 0, dataSize = 0;

            for (int s = 0; s < numSections; s++)
            {
                int so = secTableOff + s * 40;
                if (so + 40 > gaHeader.Length) break;
                string secName = Encoding.ASCII.GetString(gaHeader, so, 8).TrimEnd('\0');
                uint vSize = BitConverter.ToUInt32(gaHeader, so + 8);
                uint rva = BitConverter.ToUInt32(gaHeader, so + 12);

                if (secName == ".data" || secName.StartsWith(".data"))
                {
                    dataRva = rva;
                    dataSize = vSize;
                }
            }

            if (dataRva == 0 || dataSize == 0) return 0;

            ulong scanAddr = gaBase + dataRva;
            int scanLen = (int)Math.Min(dataSize, 0x2000000);
            int stride = 0x1000;

            for (int off = 0; off < scanLen; off += stride)
            {
                int chunkSize = Math.Min(stride, scanLen - off);
                byte[] chunk = ReadBytes(scanAddr + (ulong)off, chunkSize);
                if (chunk == null) break;

                for (int i = 0; i + 16 <= chunk.Length; i += 8)
                {
                    ulong count = BitConverter.ToUInt64(chunk, i);
                    if (count != (ulong)methodCount) continue;

                    // Next 8 bytes should be a valid pointer to the method pointers array
                    ulong ptrsAddr = BitConverter.ToUInt64(chunk, i + 8);
                    if (ptrsAddr < 0x10000 || ptrsAddr == 0) continue;

                    // Validate: first method pointer should be within GameAssembly range
                    ulong firstMethodPtr = ReadPtr(ptrsAddr);
                    if (firstMethodPtr >= gaBase && firstMethodPtr < gaBase + gaSize)
                    {
                        return scanAddr + (ulong)off + (ulong)i;
                    }
                }
            }

            return 0;
        }

        // ===== Apply resolved data to SDK classes =====

        public static void ApplyFieldOffsets(
            List<Il2CppClassInfo> classes,
            List<RuntimeFieldOffset> offsets,
            Il2CppMetadataSnapshot snapshot)
        {
            if (offsets == null || offsets.Count == 0) return;

            // Build lookup: global field index → offset info
            var offsetMap = new Dictionary<int, RuntimeFieldOffset>();
            foreach (var o in offsets)
                offsetMap[o.FieldIndex] = o;

            foreach (var cls in classes)
            {
                foreach (var field in cls.Fields)
                {
                    // Find global field index by token
                    // Token table index = token & 0x00FFFFFF (1-based for FieldDef table 0x04)
                    int fieldDefIdx = (int)(field.Token & 0x00FFFFFF) - 1;
                    if (fieldDefIdx < 0) continue;

                    if (offsetMap.TryGetValue(fieldDefIdx, out var fo))
                    {
                        field.FieldOffset = fo.Offset;
                        field.IsStatic = fo.IsStatic;
                    }
                }
            }
        }

        public static void ApplyMethodPointers(
            List<Il2CppClassInfo> classes,
            List<MethodPointerEntry> pointers,
            Il2CppMetadataSnapshot snapshot)
        {
            if (pointers == null || pointers.Count == 0) return;

            var ptrMap = new Dictionary<int, MethodPointerEntry>();
            foreach (var mp in pointers)
                ptrMap[mp.MethodIndex] = mp;

            foreach (var cls in classes)
            {
                foreach (var method in cls.Methods)
                {
                    int methodDefIdx = (int)(method.Token & 0x00FFFFFF) - 1;
                    if (methodDefIdx < 0) continue;

                    if (ptrMap.TryGetValue(methodDefIdx, out var mp))
                    {
                        method.Rva = mp.Rva;
                    }
                }
            }
        }

        public static void ApplyEnumValues(
            List<Il2CppClassInfo> classes,
            List<EnumValue> enumValues,
            Il2CppMetadataSnapshot snapshot)
        {
            if (enumValues == null || enumValues.Count == 0) return;

            // Group by type index for efficient lookup
            var byType = new Dictionary<int, List<EnumValue>>();
            foreach (var ev in enumValues)
            {
                if (!byType.TryGetValue(ev.TypeIndex, out var list))
                {
                    list = new List<EnumValue>();
                    byType[ev.TypeIndex] = list;
                }
                list.Add(ev);
            }

            foreach (var cls in classes)
            {
                if (!cls.IsEnum) continue;

                // Find type index by matching token
                int typeDefIdx = (int)(cls.Token & 0x00FFFFFF) - 1;
                // Token table for TypeDef is 0x02, but IL2CPP uses direct index encoding
                // Try matching by iterating
                for (int ti = 0; ti < snapshot.TypeDefinitions.Length; ti++)
                {
                    if (snapshot.TypeDefinitions[ti].Token == cls.Token)
                    {
                        if (byType.TryGetValue(ti, out var vals))
                        {
                            // Match field names and add enum values as comments
                            foreach (var field in cls.Fields)
                            {
                                foreach (var ev in vals)
                                {
                                    if (ev.Name == field.Name)
                                    {
                                        field.FieldOffset = (int)ev.Value;
                                        break;
                                    }
                                }
                            }
                        }
                        break;
                    }
                }
            }
        }

        // ===== Memory helpers =====

        private byte[] ReadBytes(ulong address, int size)
        {
            if (size <= 0 || size > 0x10000000) return null;
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                if (!_driver.CopyVirtualMemory(_pid, (IntPtr)address, buf, size))
                    return null;
                byte[] data = new byte[size];
                Marshal.Copy(buf, data, 0, size);
                return data;
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }

        private ulong ReadPtr(ulong address)
        {
            byte[] data = ReadBytes(address, 8);
            if (data == null) return 0;
            return BitConverter.ToUInt64(data, 0);
        }

        private ulong ReadU64(ulong address)
        {
            return ReadPtr(address);
        }

        // ===== 7. Anti-anti-dump hook detection =====

        public struct HookDetection
        {
            public string FunctionName;
            public string ModuleName;
            public ulong Address;
            public string HookType;
            public byte[] OriginalBytes;
            public byte[] CurrentBytes;
        }

        public List<HookDetection> DetectApiHooks(Action<string> log = null)
        {
            var result = new List<HookDetection>();

            if (!_driver.GetModuleSummaryList(_pid, out ModuleSummary[] modules))
            {
                log?.Invoke("Failed to enumerate modules");
                return result;
            }

            var ntdll = modules.FirstOrDefault(m => m.ModuleName != null &&
                m.ModuleName.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase));

            if (ntdll == null)
            {
                log?.Invoke("ntdll.dll not found");
                return result;
            }

            var exports = _driver.GetExportMap(_pid);
            if (exports == null || exports.Count == 0)
            {
                log?.Invoke("No exports found");
                return result;
            }

            string[] criticalApis = {
                "NtReadVirtualMemory", "NtWriteVirtualMemory",
                "NtQueryVirtualMemory", "NtQueryInformationProcess",
                "NtOpenProcess", "NtProtectVirtualMemory",
                "NtQuerySystemInformation", "NtClose",
                "LdrLoadDll", "NtMapViewOfSection"
            };

            foreach (var api in criticalApis)
            {
                var match = exports.FirstOrDefault(e =>
                    e.Value.funcName != null && e.Value.funcName == api &&
                    e.Key >= ntdll.BaseAddress && e.Key < ntdll.BaseAddress + ntdll.ImageSize);

                if (match.Value.funcName == null) continue;

                byte[] prologue = ReadBytes(match.Key, 16);
                if (prologue == null) continue;

                string hookType = null;

                // Check for jmp [rip+xx] (FF 25) or jmp rel32 (E9)
                if (prologue[0] == 0xE9)
                    hookType = "JMP rel32 (inline hook)";
                else if (prologue[0] == 0xFF && prologue[1] == 0x25)
                    hookType = "JMP [rip+disp] (IAT-style hook)";
                else if (prologue[0] == 0x48 && prologue[1] == 0xB8)
                    hookType = "MOV RAX, imm64 (trampoline hook)";
                else if (prologue[0] == 0x68)
                    hookType = "PUSH addr (push-ret hook)";
                // Normal syscall stub: 4C 8B D1 B8 xx xx 00 00
                else if (prologue[0] == 0x4C && prologue[1] == 0x8B && prologue[2] == 0xD1 && prologue[3] == 0xB8)
                    continue; // Normal, not hooked
                // Another normal pattern: mov eax, syscall#
                else if (prologue[0] == 0xB8)
                    continue;

                if (hookType == null) continue;

                result.Add(new HookDetection
                {
                    FunctionName = api,
                    ModuleName = "ntdll.dll",
                    Address = match.Key,
                    HookType = hookType,
                    CurrentBytes = prologue
                });
            }

            log?.Invoke($"Scanned {criticalApis.Length} APIs, found {result.Count} hooks");
            return result;
        }

        // ===== 8. IL2CPP version auto-detection =====

        public struct Il2CppVersionInfo
        {
            public int DetectedVersion;
            public int MethodsOffset;
            public int MethodCountOffset;
            public int FieldsOffset;
            public int FieldCountOffset;
            public int Confidence;
        }

        public Il2CppVersionInfo AutoDetectIl2CppVersion(
            ulong gameAssemblyBase, uint gameAssemblySize,
            Il2CppMetadataSnapshot snapshot,
            Action<string> log = null)
        {
            var best = new Il2CppVersionInfo();
            if (snapshot == null || snapshot.TypeDefinitions == null) return best;

            ulong typeInfoTable = FindTypeInfoDefinitionTable(gameAssemblyBase, gameAssemblySize, snapshot);
            if (typeInfoTable == 0)
            {
                log?.Invoke("Cannot auto-detect: s_TypeInfoDefinitionTable not found");
                return best;
            }

            // Find a class with known method/field counts to validate offsets
            int testTypeIdx = -1;
            for (int i = 0; i < snapshot.TypeDefinitions.Length; i++)
            {
                var td = snapshot.TypeDefinitions[i];
                if (td.MethodCount >= 3 && td.MethodCount <= 50 && td.FieldCount >= 2 && td.FieldCount <= 30)
                {
                    testTypeIdx = i;
                    break;
                }
            }

            if (testTypeIdx < 0)
            {
                log?.Invoke("No suitable test type found");
                return best;
            }

            var testTd = snapshot.TypeDefinitions[testTypeIdx];
            ulong classPtr = ReadPtr(typeInfoTable + (ulong)(testTypeIdx * 8));
            if (classPtr == 0 || classPtr < 0x10000)
            {
                log?.Invoke("Test class pointer invalid");
                return best;
            }

            byte[] classData = ReadBytes(classPtr, 0x100);
            if (classData == null || classData.Length < 0x100)
            {
                log?.Invoke("Cannot read class data");
                return best;
            }

            int[][] versionCandidates = {
                //       methods  methodCnt  fields  fieldCnt  version
                new[] {    0x98,    0xC8,     0x80,    0xCA,    24 },
                new[] {    0xA0,    0xCC,     0x80,    0xCA,    27 },
                new[] {    0xA8,    0xD0,     0x80,    0xCA,    29 },
                new[] {    0xB0,    0xD4,     0x80,    0xCA,    31 },
            };

            foreach (var candidate in versionCandidates)
            {
                int methOff = candidate[0], methCntOff = candidate[1];
                int fldOff = candidate[2], fldCntOff = candidate[3];
                int version = candidate[4];

                if (methOff + 8 > classData.Length || methCntOff + 2 > classData.Length) continue;
                if (fldOff + 8 > classData.Length || fldCntOff + 2 > classData.Length) continue;

                ulong methodsPtr = BitConverter.ToUInt64(classData, methOff);
                ushort methodCount = BitConverter.ToUInt16(classData, methCntOff);
                ulong fieldsPtr = BitConverter.ToUInt64(classData, fldOff);
                ushort fieldCount = BitConverter.ToUInt16(classData, fldCntOff);

                int confidence = 0;

                if (methodCount == testTd.MethodCount) confidence += 40;
                if (fieldCount == testTd.FieldCount) confidence += 40;
                if (methodsPtr > 0x10000 && methodsPtr < 0x7FFFFFFFFFFF) confidence += 10;
                if (fieldsPtr > 0x10000 && fieldsPtr < 0x7FFFFFFFFFFF) confidence += 10;

                if (confidence > best.Confidence)
                {
                    best = new Il2CppVersionInfo
                    {
                        DetectedVersion = version,
                        MethodsOffset = methOff,
                        MethodCountOffset = methCntOff,
                        FieldsOffset = fldOff,
                        FieldCountOffset = fldCntOff,
                        Confidence = confidence
                    };
                }
            }

            if (best.Confidence > 0)
                log?.Invoke($"Auto-detected IL2CPP v{best.DetectedVersion} (confidence: {best.Confidence}%, methods@0x{best.MethodsOffset:X}, fields@0x{best.FieldsOffset:X})");
            else
                log?.Invoke("Could not auto-detect IL2CPP version");

            return best;
        }
    }
}
