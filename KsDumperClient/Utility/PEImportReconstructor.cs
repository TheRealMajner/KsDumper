using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using KsDumperClient.Driver;

namespace KsDumperClient.Utility
{
    public static class PEImportReconstructor
    {
        public class ImportEntry
        {
            public string DllName;
            public string FunctionName;
            public int Ordinal;
            public ulong IATAddress;
            public ulong ResolvedAddress;
        }

        public class ReconstructionResult
        {
            public List<ImportEntry> Imports = new List<ImportEntry>();
            public Dictionary<string, List<ImportEntry>> ByDll = new Dictionary<string, List<ImportEntry>>();
            public int TotalIATEntries;
            public int ResolvedEntries;
            public int UnresolvedEntries;
            public int TotalCallTargets;
        }

        public static ReconstructionResult ReconstructImports(
            IMemoryReader driver, int pid,
            ulong moduleBase, uint moduleSize,
            int maxCallTargets = 50000)
        {
            var result = new ReconstructionResult();

            // Build export map from all loaded modules
            var exports = driver.GetExportMap(pid);
            if (exports == null) return result;

            // Read PE header
            byte[] peHeader = ReadMemory(driver, pid, moduleBase, 0x1000);
            if (peHeader == null) return result;

            int peOff = BitConverter.ToInt32(peHeader, 0x3C);
            if (peOff < 0 || peOff + 0x110 > peHeader.Length) return result;

            // Get IAT directory from optional header
            int optMagic = BitConverter.ToUInt16(peHeader, peOff + 24);
            bool is64 = optMagic == 0x20B;

            int iatDirRva = 0, iatDirSize = 0;
            int importDirRva = 0, importDirSize = 0;

            if (is64)
            {
                importDirRva = BitConverter.ToInt32(peHeader, peOff + 24 + 120);
                importDirSize = BitConverter.ToInt32(peHeader, peOff + 24 + 124);
                iatDirRva = BitConverter.ToInt32(peHeader, peOff + 24 + 216);
                iatDirSize = BitConverter.ToInt32(peHeader, peOff + 24 + 220);
            }
            else
            {
                importDirRva = BitConverter.ToInt32(peHeader, peOff + 24 + 104);
                importDirSize = BitConverter.ToInt32(peHeader, peOff + 24 + 108);
                iatDirRva = BitConverter.ToInt32(peHeader, peOff + 24 + 192);
                iatDirSize = BitConverter.ToInt32(peHeader, peOff + 24 + 196);
            }

            // Strategy 1: Read IAT directly and resolve via export map
            if (iatDirRva > 0 && iatDirSize > 0)
            {
                ResolveIAT(driver, pid, moduleBase, iatDirRva, iatDirSize, exports, result, is64);
            }

            // Strategy 2: Scan .text section for CALL [rip+disp] instructions
            // that target the IAT, and cross-reference with exports
            ScanCallTargets(driver, pid, moduleBase, moduleSize, peHeader, peOff,
                exports, result, is64, maxCallTargets);

            // Build per-DLL grouping
            foreach (var imp in result.Imports)
            {
                if (!result.ByDll.ContainsKey(imp.DllName))
                    result.ByDll[imp.DllName] = new List<ImportEntry>();
                result.ByDll[imp.DllName].Add(imp);
            }

            return result;
        }

        private static void ResolveIAT(
            IMemoryReader driver, int pid,
            ulong moduleBase, int iatRva, int iatSize,
            Dictionary<ulong, (string dllName, string funcName)> exports,
            ReconstructionResult result, bool is64)
        {
            int entrySize = is64 ? 8 : 4;
            int entryCount = iatSize / entrySize;
            result.TotalIATEntries = entryCount;

            byte[] iatData = ReadMemory(driver, pid, moduleBase + (ulong)iatRva, iatSize);
            if (iatData == null) return;

            var seen = new HashSet<ulong>();

            for (int i = 0; i < entryCount; i++)
            {
                ulong addr;
                if (is64)
                    addr = BitConverter.ToUInt64(iatData, i * 8);
                else
                    addr = BitConverter.ToUInt32(iatData, i * 4);

                if (addr == 0) continue;

                if (seen.Contains(addr)) continue;
                seen.Add(addr);

                if (exports.TryGetValue(addr, out var exp))
                {
                    result.Imports.Add(new ImportEntry
                    {
                        DllName = exp.dllName,
                        FunctionName = exp.funcName,
                        IATAddress = moduleBase + (ulong)iatRva + (ulong)(i * entrySize),
                        ResolvedAddress = addr
                    });
                    result.ResolvedEntries++;
                }
                else
                {
                    result.UnresolvedEntries++;
                }
            }
        }

        private static void ScanCallTargets(
            IMemoryReader driver, int pid,
            ulong moduleBase, uint moduleSize,
            byte[] peHeader, int peOff,
            Dictionary<ulong, (string dllName, string funcName)> exports,
            ReconstructionResult result, bool is64, int maxTargets)
        {
            // Find .text section
            ushort sectionCount = BitConverter.ToUInt16(peHeader, peOff + 6);
            ushort optHeaderSize = BitConverter.ToUInt16(peHeader, peOff + 20);
            int sectionTableOff = peOff + 24 + optHeaderSize;

            var resolvedAddrs = new HashSet<ulong>(result.Imports.Select(i => i.ResolvedAddress));
            var callTargets = new HashSet<ulong>();

            for (int s = 0; s < sectionCount; s++)
            {
                int off = sectionTableOff + s * 40;
                if (off + 40 > peHeader.Length) break;

                uint chars = BitConverter.ToUInt32(peHeader, off + 36);
                if ((chars & 0x20000000) == 0) continue; // IMAGE_SCN_MEM_EXECUTE

                uint vSize = BitConverter.ToUInt32(peHeader, off + 8);
                uint vAddr = BitConverter.ToUInt32(peHeader, off + 12);
                ulong secStart = moduleBase + vAddr;
                int readSize = (int)Math.Min(vSize, 0x4000000);

                byte[] code = ReadMemory(driver, pid, secStart, readSize);
                if (code == null) continue;

                // Scan for CALL rel32 (E8 xx xx xx xx) and JMP rel32 (E9 xx xx xx xx)
                for (int i = 0; i < code.Length - 5; i++)
                {
                    if (callTargets.Count >= maxTargets) break;

                    if (code[i] == 0xE8 || code[i] == 0xE9)
                    {
                        int disp = BitConverter.ToInt32(code, i + 1);
                        ulong target = secStart + (ulong)(i + 5) + (ulong)disp;

                        if (target < moduleBase || target >= moduleBase + moduleSize)
                        {
                            if (!callTargets.Contains(target))
                            {
                                callTargets.Add(target);
                                result.TotalCallTargets++;

                                if (!resolvedAddrs.Contains(target) && exports.TryGetValue(target, out var exp))
                                {
                                    result.Imports.Add(new ImportEntry
                                    {
                                        DllName = exp.dllName,
                                        FunctionName = exp.funcName,
                                        IATAddress = secStart + (ulong)i,
                                        ResolvedAddress = target
                                    });
                                    result.ResolvedEntries++;
                                    resolvedAddrs.Add(target);
                                }
                            }
                        }
                    }

                    // Also check for FF 15 (CALL [rip+disp32]) - indirect call through IAT
                    if (is64 && i < code.Length - 6 && code[i] == 0xFF && code[i + 1] == 0x15)
                    {
                        int disp = BitConverter.ToInt32(code, i + 2);
                        ulong ptrAddr = secStart + (ulong)(i + 6) + (ulong)disp;

                        if (!callTargets.Contains(ptrAddr))
                        {
                            callTargets.Add(ptrAddr);
                            ulong target = ReadPtr(driver, pid, ptrAddr);
                            if (target != 0 && !resolvedAddrs.Contains(target) && exports.TryGetValue(target, out var exp))
                            {
                                result.Imports.Add(new ImportEntry
                                {
                                    DllName = exp.dllName,
                                    FunctionName = exp.funcName,
                                    IATAddress = ptrAddr,
                                    ResolvedAddress = target
                                });
                                result.ResolvedEntries++;
                                resolvedAddrs.Add(target);
                            }
                        }
                    }
                }
            }
        }

        public static string GenerateReport(ReconstructionResult result)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - PE Import Reconstruction");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"// IAT entries: {result.TotalIATEntries}");
            sb.AppendLine($"// Resolved: {result.ResolvedEntries}");
            sb.AppendLine($"// Unresolved: {result.UnresolvedEntries}");
            sb.AppendLine($"// Call targets scanned: {result.TotalCallTargets}");
            sb.AppendLine($"// DLLs referenced: {result.ByDll.Count}");
            sb.AppendLine();

            foreach (var dll in result.ByDll.OrderBy(d => d.Key))
            {
                sb.AppendLine($"  {dll.Key} ({dll.Value.Count} functions):");
                foreach (var imp in dll.Value.OrderBy(i => i.FunctionName))
                {
                    sb.AppendLine($"    {imp.FunctionName,-40} IAT: 0x{imp.IATAddress:X} -> 0x{imp.ResolvedAddress:X}");
                }
                sb.AppendLine();
            }

            return sb.ToString();
        }

        public static void PatchDumpedPE(string dumpPath, ReconstructionResult result)
        {
            if (!File.Exists(dumpPath)) return;
            byte[] pe = File.ReadAllBytes(dumpPath);
            if (pe.Length < 0x200) return;

            int peOff = BitConverter.ToInt32(pe, 0x3C);
            if (peOff < 0 || peOff + 24 > pe.Length) return;

            ushort optMagic = BitConverter.ToUInt16(pe, peOff + 24);
            bool is64 = optMagic == 0x20B;

            // Build import directory
            var importData = BuildImportDirectory(result, is64);
            if (importData == null || importData.Length == 0) return;

            // Find a place to append the import directory
            // Use the end of the file, aligned to 0x200
            int appendOffset = (pe.Length + 0x1FF) & ~0x1FF;
            int newSize = appendOffset + ((importData.Length + 0x1FF) & ~0x1FF);

            byte[] newPe = new byte[newSize];
            Buffer.BlockCopy(pe, 0, newPe, 0, pe.Length);
            Buffer.BlockCopy(importData, 0, newPe, appendOffset, importData.Length);

            // Update import directory RVA/size in optional header
            // Note: RVA == file offset in this simplified approach
            if (is64)
            {
                BitConverter.GetBytes(appendOffset).CopyTo(newPe, peOff + 24 + 120);
                BitConverter.GetBytes(importData.Length).CopyTo(newPe, peOff + 24 + 124);
            }
            else
            {
                BitConverter.GetBytes(appendOffset).CopyTo(newPe, peOff + 24 + 104);
                BitConverter.GetBytes(importData.Length).CopyTo(newPe, peOff + 24 + 108);
            }

            string outPath = Path.Combine(Path.GetDirectoryName(dumpPath),
                Path.GetFileNameWithoutExtension(dumpPath) + "_fixed" + Path.GetExtension(dumpPath));
            File.WriteAllBytes(outPath, newPe);
        }

        private static byte[] BuildImportDirectory(ReconstructionResult result, bool is64)
        {
            if (result.ByDll.Count == 0) return null;

            using (var ms = new MemoryStream())
            using (var bw = new BinaryWriter(ms))
            {
                // Each import descriptor is 20 bytes
                int descSize = (result.ByDll.Count + 1) * 20;
                int stringsOff = descSize;

                // Collect all DLL names and function names
                var stringPositions = new Dictionary<string, int>();
                int currentStrOff = stringsOff;

                foreach (var dll in result.ByDll)
                {
                    stringPositions[dll.Key] = currentStrOff;
                    currentStrOff += dll.Key.Length + 1;

                    foreach (var imp in dll.Value)
                    {
                        if (!stringPositions.ContainsKey(imp.FunctionName))
                        {
                            stringPositions[imp.FunctionName] = currentStrOff;
                            currentStrOff += 2 + imp.FunctionName.Length + 1; // hint + name + null
                        }
                    }
                }

                // Write descriptors (placeholder RVAs)
                foreach (var dll in result.ByDll)
                {
                    bw.Write(0); // OriginalFirstThunk (placeholder)
                    bw.Write(0); // TimeDateStamp
                    bw.Write(-1); // ForwarderChain
                    bw.Write(stringPositions[dll.Key]); // Name RVA
                    bw.Write(0); // FirstThunk (placeholder)
                }
                // Null terminator descriptor
                bw.Write(0); bw.Write(0); bw.Write(0); bw.Write(0); bw.Write(0);

                // Write strings
                foreach (var dll in result.ByDll)
                {
                    bw.Write(Encoding.ASCII.GetBytes(dll.Key));
                    bw.Write((byte)0);

                    foreach (var imp in dll.Value)
                    {
                        bw.Write((ushort)0); // Hint
                        bw.Write(Encoding.ASCII.GetBytes(imp.FunctionName));
                        bw.Write((byte)0);
                    }
                }

                return ms.ToArray();
            }
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

        private static ulong ReadPtr(IMemoryReader driver, int pid, ulong address)
        {
            byte[] buf = ReadMemory(driver, pid, address, 8);
            if (buf == null) return 0;
            return BitConverter.ToUInt64(buf, 0);
        }
    }
}
