using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using KsDumperClient.Driver;
using static KsDumperClient.Utility.Il2CppDumper;

namespace KsDumperClient.Utility
{
    public static class Il2CppCodeRegistration
    {
        public class CodeRegInfo
        {
            public ulong CodeRegistrationAddress;
            public ulong MetadataRegistrationAddress;
            public ulong[] MethodPointers;
            public ulong[] TypeInfoPointers;
            public ulong[] GenericMethodPointers;
            public ulong InvokerPointersAddress;
            public int MethodPointerCount;
            public int GenericMethodPointerCount;
            public int TypeInfoCount;
        }

        public class MetadataRegInfo
        {
            public int GenericClassCount;
            public ulong GenericClassesAddress;
            public int GenericInstCount;
            public ulong GenericInstsAddress;
            public int GenericMethodTableCount;
            public ulong GenericMethodTableAddress;
            public int TypesCount;
            public ulong TypesAddress;
            public int MethodSpecsCount;
            public ulong MethodSpecsAddress;
            public int FieldOffsetsCount;
            public ulong FieldOffsetsAddress;
            public int TypeDefinitionsSizesCount;
            public ulong TypeDefinitionsSizesAddress;
            public ulong MetadataUsagesAddress;
        }

        public static CodeRegInfo FindCodeRegistration(
            IMemoryReader driver, int pid,
            ulong gaBase, uint gaSize,
            Il2CppMetadataSnapshot snapshot)
        {
            var result = new CodeRegInfo();

            int expectedMethodCount = snapshot.Methods?.Length ?? 0;
            if (expectedMethodCount == 0) return null;

            // Read .data section from PE header
            byte[] peHeader = ReadMemory(driver, pid, gaBase, 0x1000);
            if (peHeader == null) return null;

            int peOff = BitConverter.ToInt32(peHeader, 0x3C);
            if (peOff < 0 || peOff + 0x108 > peHeader.Length) return null;

            ushort sectionCount = BitConverter.ToUInt16(peHeader, peOff + 6);
            ushort optHeaderSize = BitConverter.ToUInt16(peHeader, peOff + 20);
            int sectionTableOff = peOff + 24 + optHeaderSize;

            ulong dataStart = 0, dataSize = 0;
            for (int s = 0; s < sectionCount; s++)
            {
                int off = sectionTableOff + s * 40;
                if (off + 40 > peHeader.Length) break;

                string sName = System.Text.Encoding.ASCII.GetString(peHeader, off, 8).TrimEnd('\0');
                uint vSize = BitConverter.ToUInt32(peHeader, off + 8);
                uint vAddr = BitConverter.ToUInt32(peHeader, off + 12);

                if (sName == ".data" || sName == ".rdata")
                {
                    if (dataStart == 0 || gaBase + vAddr < dataStart)
                        dataStart = gaBase + vAddr;
                    ulong end = gaBase + vAddr + vSize;
                    if (end > dataStart + dataSize)
                        dataSize = end - dataStart;
                }
            }

            if (dataStart == 0 || dataSize == 0) return null;
            if (dataSize > 0x4000000) dataSize = 0x4000000; // cap at 64MB

            byte[] dataSection = ReadMemory(driver, pid, dataStart, (int)dataSize);
            if (dataSection == null) return null;

            ulong gaEnd = gaBase + gaSize;

            // Scan for CodeRegistration: look for methodPointersCount == expectedMethodCount
            // followed by a valid pointer to methodPointers array
            // v24+: [reversePInvokeWrapperCount, reversePInvokeWrappers, genericMethodPointerCount, genericMethodPointers,
            //        invokerPointersCount, invokerPointers, methodPointersCount (at +0x30 or +0x28), methodPointers]
            // Simpler heuristic: find uint64 == expectedMethodCount followed by valid pointer

            for (int i = 0; i <= dataSection.Length - 16; i += 8)
            {
                long val = BitConverter.ToInt64(dataSection, i);
                if (val != expectedMethodCount) continue;

                ulong ptrVal = BitConverter.ToUInt64(dataSection, i + 8);
                if (ptrVal < gaBase || ptrVal >= gaEnd) continue;

                // Validate: read first few method pointers — they should point into GA
                byte[] testPtrs = ReadMemory(driver, pid, ptrVal, 8 * Math.Min(10, expectedMethodCount));
                if (testPtrs == null) continue;

                int validCount = 0;
                for (int p = 0; p < testPtrs.Length; p += 8)
                {
                    ulong mp = BitConverter.ToUInt64(testPtrs, p);
                    if (mp >= gaBase && mp < gaEnd) validCount++;
                    else if (mp == 0) validCount++; // null entries are common for abstract methods
                }

                if (validCount < Math.Min(5, testPtrs.Length / 8)) continue;

                result.CodeRegistrationAddress = dataStart + (ulong)i;
                result.MethodPointerCount = expectedMethodCount;

                // Read all method pointers
                byte[] allPtrs = ReadMemory(driver, pid, ptrVal, 8 * expectedMethodCount);
                if (allPtrs != null)
                {
                    result.MethodPointers = new ulong[expectedMethodCount];
                    for (int p = 0; p < expectedMethodCount && p * 8 + 8 <= allPtrs.Length; p++)
                        result.MethodPointers[p] = BitConverter.ToUInt64(allPtrs, p * 8);
                }

                // Try to find genericMethodPointers before this entry
                if (i >= 16)
                {
                    long gmCount = BitConverter.ToInt64(dataSection, i - 16);
                    ulong gmPtr = BitConverter.ToUInt64(dataSection, i - 8);
                    if (gmCount > 0 && gmCount < 500000 && gmPtr >= gaBase && gmPtr < gaEnd)
                    {
                        result.GenericMethodPointerCount = (int)gmCount;
                        byte[] gmPtrs = ReadMemory(driver, pid, gmPtr, 8 * (int)gmCount);
                        if (gmPtrs != null)
                        {
                            result.GenericMethodPointers = new ulong[(int)gmCount];
                            for (int p = 0; p < (int)gmCount && p * 8 + 8 <= gmPtrs.Length; p++)
                                result.GenericMethodPointers[p] = BitConverter.ToUInt64(gmPtrs, p * 8);
                        }
                    }
                }

                break;
            }

            if (result.CodeRegistrationAddress == 0) return null;
            return result;
        }

        public static MetadataRegInfo FindMetadataRegistration(
            IMemoryReader driver, int pid,
            ulong gaBase, uint gaSize,
            Il2CppMetadataSnapshot snapshot)
        {
            int expectedTypeCount = snapshot.TypeDefinitions?.Length ?? 0;
            if (expectedTypeCount == 0) return null;

            byte[] peHeader = ReadMemory(driver, pid, gaBase, 0x1000);
            if (peHeader == null) return null;

            int peOff = BitConverter.ToInt32(peHeader, 0x3C);
            ushort sectionCount = BitConverter.ToUInt16(peHeader, peOff + 6);
            ushort optHeaderSize = BitConverter.ToUInt16(peHeader, peOff + 20);
            int sectionTableOff = peOff + 24 + optHeaderSize;

            ulong dataStart = 0, dataSize = 0;
            for (int s = 0; s < sectionCount; s++)
            {
                int off = sectionTableOff + s * 40;
                if (off + 40 > peHeader.Length) break;
                string sName = System.Text.Encoding.ASCII.GetString(peHeader, off, 8).TrimEnd('\0');
                uint vSize = BitConverter.ToUInt32(peHeader, off + 8);
                uint vAddr = BitConverter.ToUInt32(peHeader, off + 12);
                if (sName == ".data" || sName == ".rdata")
                {
                    if (dataStart == 0 || gaBase + vAddr < dataStart) dataStart = gaBase + vAddr;
                    ulong end = gaBase + vAddr + vSize;
                    if (end > dataStart + dataSize) dataSize = end - dataStart;
                }
            }

            if (dataStart == 0) return null;
            if (dataSize > 0x4000000) dataSize = 0x4000000;

            byte[] dataSection = ReadMemory(driver, pid, dataStart, (int)dataSize);
            if (dataSection == null) return null;

            ulong gaEnd = gaBase + gaSize;

            // MetadataRegistration contains typesCount == expectedTypeCount
            // followed by types pointer (array of Il2CppType* pointers)
            for (int i = 0; i <= dataSection.Length - 16; i += 8)
            {
                long val = BitConverter.ToInt64(dataSection, i);
                if (val != expectedTypeCount) continue;

                ulong ptrVal = BitConverter.ToUInt64(dataSection, i + 8);
                if (ptrVal < gaBase || ptrVal >= gaEnd) continue;

                // Validate type pointers
                byte[] testPtrs = ReadMemory(driver, pid, ptrVal, 8 * Math.Min(10, expectedTypeCount));
                if (testPtrs == null) continue;

                int valid = 0;
                for (int p = 0; p < testPtrs.Length; p += 8)
                {
                    ulong tp = BitConverter.ToUInt64(testPtrs, p);
                    if (tp >= gaBase && tp < gaEnd) valid++;
                }
                if (valid < 5) continue;

                var reg = new MetadataRegInfo
                {
                    TypesCount = expectedTypeCount,
                    TypesAddress = ptrVal
                };

                // Read surrounding fields for other registration tables
                if (i >= 16)
                {
                    long fieldOffCount = BitConverter.ToInt64(dataSection, i - 16);
                    ulong fieldOffPtr = BitConverter.ToUInt64(dataSection, i - 8);
                    if (fieldOffCount > 0 && fieldOffCount < 500000 && fieldOffPtr >= gaBase && fieldOffPtr < gaEnd)
                    {
                        reg.FieldOffsetsCount = (int)fieldOffCount;
                        reg.FieldOffsetsAddress = fieldOffPtr;
                    }
                }

                if (i + 16 + 16 <= dataSection.Length)
                {
                    long metaUsageCount = BitConverter.ToInt64(dataSection, i + 16);
                    ulong metaUsagePtr = BitConverter.ToUInt64(dataSection, i + 24);
                    if (metaUsageCount >= 0 && metaUsageCount < 5000000)
                    {
                        reg.MetadataUsagesAddress = metaUsagePtr;
                    }
                }

                return reg;
            }

            return null;
        }

        public static string GenerateReport(CodeRegInfo codeReg, MetadataRegInfo metaReg, ulong gaBase)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - IL2CPP CodeRegistration/MetadataRegistration Report");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"// GameAssembly base: 0x{gaBase:X16}");
            sb.AppendLine();

            if (codeReg != null)
            {
                sb.AppendLine($"CodeRegistration @ 0x{codeReg.CodeRegistrationAddress:X16}");
                sb.AppendLine($"  Method pointers: {codeReg.MethodPointerCount}");
                if (codeReg.GenericMethodPointerCount > 0)
                    sb.AppendLine($"  Generic method pointers: {codeReg.GenericMethodPointerCount}");

                if (codeReg.MethodPointers != null)
                {
                    int nonNull = codeReg.MethodPointers.Count(p => p != 0);
                    sb.AppendLine($"  Non-null method pointers: {nonNull} ({100.0 * nonNull / codeReg.MethodPointers.Length:F1}%)");

                    sb.AppendLine();
                    sb.AppendLine("  First 20 method pointers:");
                    for (int i = 0; i < Math.Min(20, codeReg.MethodPointers.Length); i++)
                    {
                        ulong ptr = codeReg.MethodPointers[i];
                        ulong rva = ptr >= gaBase ? ptr - gaBase : 0;
                        sb.AppendLine($"    [{i,5}] 0x{ptr:X16} (RVA 0x{rva:X})");
                    }
                }
            }
            else
            {
                sb.AppendLine("CodeRegistration: NOT FOUND");
            }

            sb.AppendLine();

            if (metaReg != null)
            {
                sb.AppendLine($"MetadataRegistration:");
                sb.AppendLine($"  Types: {metaReg.TypesCount} @ 0x{metaReg.TypesAddress:X16}");
                if (metaReg.FieldOffsetsCount > 0)
                    sb.AppendLine($"  Field offsets: {metaReg.FieldOffsetsCount} @ 0x{metaReg.FieldOffsetsAddress:X16}");
                if (metaReg.MetadataUsagesAddress != 0)
                    sb.AppendLine($"  Metadata usages @ 0x{metaReg.MetadataUsagesAddress:X16}");
            }
            else
            {
                sb.AppendLine("MetadataRegistration: NOT FOUND");
            }

            return sb.ToString();
        }

        private static byte[] ReadMemory(IMemoryReader driver, int pid, ulong address, int size)
        {
            byte[] buf = new byte[size];
            GCHandle handle = GCHandle.Alloc(buf, GCHandleType.Pinned);
            try
            {
                if (!driver.CopyVirtualMemory(pid, (IntPtr)(long)address, handle.AddrOfPinnedObject(), size))
                    return null;
                return buf;
            }
            finally { handle.Free(); }
        }
    }
}
