using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using KsDumperClient.Driver;

namespace KsDumperClient.Utility
{
    public static class MonoAssemblyPatcher
    {
        public class PatchResult
        {
            public bool Success;
            public string Error;
            public string MethodName;
            public uint RVA;
            public ulong RuntimeAddress;
            public byte[] OriginalBytes;
            public byte[] PatchedBytes;
            public int PatchSize;
        }

        public class PatchOperation
        {
            public string MethodName;
            public uint RVA;
            public PatchType Type;
            public byte[] CustomBytes;
        }

        public enum PatchType
        {
            NopEntireBody,
            ReturnVoid,
            ReturnTrue,
            ReturnFalse,
            ReturnZero,
            ReturnOne,
            CustomBytes,
            ReturnNull,
        }

        public static PatchResult ApplyPatch(
            IMemoryReader driver,
            int processId,
            ulong moduleBase,
            byte[] peData,
            PatchOperation patch)
        {
            var result = new PatchResult
            {
                MethodName = patch.MethodName,
                RVA = patch.RVA
            };

            if (driver == null || peData == null || patch.RVA == 0)
            {
                result.Error = "Invalid parameters";
                return result;
            }

            int fileOffset = RvaToFileOffset(peData, patch.RVA);
            if (fileOffset < 0 || fileOffset >= peData.Length)
            {
                result.Error = $"Invalid RVA 0x{patch.RVA:X}";
                return result;
            }

            // Parse the method body header
            byte headerByte = peData[fileOffset];
            int codeStart;
            int codeSize;

            if ((headerByte & 0x03) == 0x02) // Tiny header
            {
                codeSize = headerByte >> 2;
                codeStart = fileOffset + 1;
            }
            else if ((headerByte & 0x03) == 0x03) // Fat header
            {
                if (fileOffset + 12 > peData.Length)
                {
                    result.Error = "Fat header truncated";
                    return result;
                }
                ushort flagsAndSize = BitConverter.ToUInt16(peData, fileOffset);
                int headerSize = (flagsAndSize >> 12) * 4;
                codeSize = BitConverter.ToInt32(peData, fileOffset + 4);
                codeStart = fileOffset + headerSize;
            }
            else
            {
                result.Error = "Unknown method header format";
                return result;
            }

            if (codeStart + codeSize > peData.Length || codeSize <= 0)
            {
                result.Error = "Method body out of bounds";
                return result;
            }

            // Calculate runtime address from RVA offset into loaded module
            uint codeRva = patch.RVA + (uint)(codeStart - fileOffset);
            result.RuntimeAddress = moduleBase + codeRva;

            // Read original bytes from process memory
            result.OriginalBytes = ReadMemory(driver, processId, result.RuntimeAddress, codeSize);
            if (result.OriginalBytes == null)
            {
                result.Error = "Failed to read method body from memory";
                return result;
            }

            // Generate patch bytes
            byte[] patchBytes;
            switch (patch.Type)
            {
                case PatchType.NopEntireBody:
                    patchBytes = new byte[codeSize];
                    for (int i = 0; i < codeSize - 1; i++)
                        patchBytes[i] = 0x00; // nop
                    patchBytes[codeSize - 1] = 0x2A; // ret
                    break;

                case PatchType.ReturnVoid:
                    patchBytes = GenerateReturnPatch(codeSize, 0x2A); // ret
                    break;

                case PatchType.ReturnTrue:
                case PatchType.ReturnOne:
                    patchBytes = GenerateReturnPatch(codeSize, 0x17, 0x2A); // ldc.i4.1, ret
                    break;

                case PatchType.ReturnFalse:
                case PatchType.ReturnZero:
                    patchBytes = GenerateReturnPatch(codeSize, 0x16, 0x2A); // ldc.i4.0, ret
                    break;

                case PatchType.ReturnNull:
                    patchBytes = GenerateReturnPatch(codeSize, 0x14, 0x2A); // ldnull, ret
                    break;

                case PatchType.CustomBytes:
                    if (patch.CustomBytes == null || patch.CustomBytes.Length > codeSize)
                    {
                        result.Error = patch.CustomBytes == null
                            ? "No custom bytes provided"
                            : $"Custom bytes ({patch.CustomBytes.Length}) exceed method body size ({codeSize})";
                        return result;
                    }
                    patchBytes = new byte[codeSize];
                    for (int i = 0; i < codeSize; i++) patchBytes[i] = 0x00;
                    Array.Copy(patch.CustomBytes, patchBytes, patch.CustomBytes.Length);
                    if (patch.CustomBytes[patch.CustomBytes.Length - 1] != 0x2A)
                        patchBytes[codeSize - 1] = 0x2A; // ensure ret at end
                    break;

                default:
                    result.Error = "Unknown patch type";
                    return result;
            }

            result.PatchedBytes = patchBytes;
            result.PatchSize = patchBytes.Length;

            // Write patched bytes to process memory
            bool written = WriteMemory(driver, processId, result.RuntimeAddress, patchBytes);
            if (!written)
            {
                result.Error = "Failed to write patched bytes to memory";
                return result;
            }

            result.Success = true;
            return result;
        }

        public static PatchResult UndoPatch(IMemoryReader driver, int processId, PatchResult previousPatch)
        {
            var result = new PatchResult
            {
                MethodName = previousPatch.MethodName,
                RVA = previousPatch.RVA,
                RuntimeAddress = previousPatch.RuntimeAddress
            };

            if (previousPatch.OriginalBytes == null)
            {
                result.Error = "No original bytes to restore";
                return result;
            }

            bool written = WriteMemory(driver, processId, previousPatch.RuntimeAddress, previousPatch.OriginalBytes);
            if (!written)
            {
                result.Error = "Failed to restore original bytes";
                return result;
            }

            result.Success = true;
            result.PatchedBytes = previousPatch.OriginalBytes;
            result.PatchSize = previousPatch.OriginalBytes.Length;
            return result;
        }

        public static List<PatchOperation> BuildPatchPlan(MonoSdkGenerator.MonoSdkInfo sdkInfo, string methodNamePattern, PatchType patchType)
        {
            var operations = new List<PatchOperation>();
            if (sdkInfo == null) return operations;

            foreach (var cls in sdkInfo.Classes)
            {
                foreach (var method in cls.Methods)
                {
                    if (method.RVA == 0) continue;

                    string fullName = string.IsNullOrEmpty(cls.Namespace)
                        ? $"{cls.Name}.{method.Name}"
                        : $"{cls.Namespace}.{cls.Name}.{method.Name}";

                    if (MatchesPattern(fullName, methodNamePattern) || MatchesPattern(method.Name, methodNamePattern))
                    {
                        operations.Add(new PatchOperation
                        {
                            MethodName = fullName,
                            RVA = method.RVA,
                            Type = patchType
                        });
                    }
                }
            }

            return operations;
        }

        public static string GeneratePatchReport(List<PatchResult> results)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - Mono Assembly Patch Report");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine();

            int success = 0, failed = 0;
            foreach (var r in results)
            {
                if (r.Success) success++; else failed++;

                string status = r.Success ? "OK" : $"FAILED: {r.Error}";
                sb.AppendLine($"  [{status}] {r.MethodName} @ RVA 0x{r.RVA:X} -> 0x{r.RuntimeAddress:X}");
                if (r.Success)
                    sb.AppendLine($"         Patched {r.PatchSize} bytes");
            }

            sb.AppendLine();
            sb.AppendLine($"// Total: {success} patched, {failed} failed, {results.Count} total");
            return sb.ToString();
        }

        private static byte[] GenerateReturnPatch(int codeSize, params byte[] suffix)
        {
            byte[] patch = new byte[codeSize];
            for (int i = 0; i < codeSize; i++) patch[i] = 0x00; // nop fill
            int start = codeSize - suffix.Length;
            if (start < 0) start = 0;
            for (int i = 0; i < suffix.Length && start + i < codeSize; i++)
                patch[start + i] = suffix[i];
            return patch;
        }

        private static bool MatchesPattern(string text, string pattern)
        {
            if (string.IsNullOrEmpty(pattern) || string.IsNullOrEmpty(text)) return false;

            if (pattern.Contains("*"))
            {
                string[] parts = pattern.Split('*');
                int pos = 0;
                foreach (string part in parts)
                {
                    if (string.IsNullOrEmpty(part)) continue;
                    int idx = text.IndexOf(part, pos, StringComparison.OrdinalIgnoreCase);
                    if (idx < 0) return false;
                    pos = idx + part.Length;
                }
                return true;
            }

            return text.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static byte[] ReadMemory(IMemoryReader driver, int processId, ulong address, int size)
        {
            byte[] buf = new byte[size];
            GCHandle handle = GCHandle.Alloc(buf, GCHandleType.Pinned);
            try
            {
                if (!driver.CopyVirtualMemory(processId, (IntPtr)(long)address, handle.AddrOfPinnedObject(), size))
                    return null;
                return buf;
            }
            finally
            {
                handle.Free();
            }
        }

        private static bool WriteMemory(IMemoryReader driver, int processId, ulong address, byte[] data)
        {
            GCHandle handle = GCHandle.Alloc(data, GCHandleType.Pinned);
            try
            {
                return driver.WriteVirtualMemory(processId, (IntPtr)(long)address, handle.AddrOfPinnedObject(), data.Length);
            }
            finally
            {
                handle.Free();
            }
        }

        private static int RvaToFileOffset(byte[] peData, uint rva)
        {
            if (peData == null || peData.Length < 0x40) return -1;

            int peOffset = BitConverter.ToInt32(peData, 0x3C);
            if (peOffset < 0 || peOffset + 24 > peData.Length) return -1;

            ushort sectionCount = BitConverter.ToUInt16(peData, peOffset + 6);
            ushort optHeaderSize = BitConverter.ToUInt16(peData, peOffset + 20);
            int sectionTableOffset = peOffset + 24 + optHeaderSize;

            for (int s = 0; s < sectionCount; s++)
            {
                int off = sectionTableOffset + s * 40;
                if (off + 40 > peData.Length) break;

                uint virtualSize = BitConverter.ToUInt32(peData, off + 8);
                uint virtualAddr = BitConverter.ToUInt32(peData, off + 12);
                uint rawSize = BitConverter.ToUInt32(peData, off + 16);
                uint rawAddr = BitConverter.ToUInt32(peData, off + 20);

                if (rva >= virtualAddr && rva < virtualAddr + Math.Max(virtualSize, rawSize))
                    return (int)(rawAddr + (rva - virtualAddr));
            }

            return -1;
        }
    }
}
