using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using KsDumperClient.Driver;

namespace KsDumperClient.Utility
{
    public static class MonoJitTableExtractor
    {
        public class JitMethodEntry
        {
            public ulong MethodPointer;
            public ulong CodeStart;
            public int CodeSize;
            public string ClassName;
            public string MethodName;
            public string FullName;
            public uint Token;
        }

        public class JitTableDump
        {
            public List<JitMethodEntry> Methods = new List<JitMethodEntry>();
            public int TotalEntries;
            public int ResolvedEntries;
            public ulong JitTableAddress;
        }

        // MonoJitInfoTable offsets (x64)
        private const int kJitTable_NumEntries = 0x00;
        private const int kJitTable_Entries = 0x10;

        // MonoJitInfo offsets (x64)
        private const int kJitInfo_Method = 0x00;
        private const int kJitInfo_NextJitCodeHash = 0x08;
        private const int kJitInfo_CodeStart = 0x10;
        private const int kJitInfo_UnwindInfo = 0x18;
        private const int kJitInfo_CodeSize = 0x20;

        // MonoMethod offsets
        private const int kMethod_Flags = 0x00;
        private const int kMethod_ImplFlags = 0x02;
        private const int kMethod_Slot = 0x04;
        private const int kMethod_Name = 0x18;
        private const int kMethod_Klass = 0x10;
        private const int kMethod_Token = 0x28;

        // MonoClass offsets
        private const int kClass_Name = 0x48;
        private const int kClass_Namespace = 0x50;

        public static JitTableDump ExtractJitTable(
            IMemoryReader driver, int pid,
            ulong monoBase, uint monoSize,
            int maxMethods = 10000)
        {
            var result = new JitTableDump();

            // Find mono_jit_info_table via mono_domain_get_jit_info or by scanning
            ulong jitTable = FindJitInfoTable(driver, pid, monoBase, monoSize);
            if (jitTable == 0) return result;

            result.JitTableAddress = jitTable;

            // Read table header
            byte[] tableHeader = ReadMemory(driver, pid, jitTable, 0x20);
            if (tableHeader == null) return result;

            int numEntries = BitConverter.ToInt32(tableHeader, kJitTable_NumEntries);
            if (numEntries <= 0 || numEntries > 1000000) return result;

            result.TotalEntries = numEntries;

            // The jit info table is a hash table with chunks
            // Each chunk contains MonoJitInfo* entries
            // Scan the table entries array
            int entriesToRead = Math.Min(numEntries, maxMethods);
            int ptrArraySize = entriesToRead * 8;
            byte[] entryPtrs = ReadMemory(driver, pid, jitTable + kJitTable_Entries, ptrArraySize);
            if (entryPtrs == null) return result;

            var seen = new HashSet<ulong>();

            for (int i = 0; i < entriesToRead; i++)
            {
                ulong jitInfoPtr = BitConverter.ToUInt64(entryPtrs, i * 8);
                if (jitInfoPtr == 0) continue;

                // Walk the hash chain
                ulong current = jitInfoPtr;
                int chainLen = 0;
                while (current != 0 && chainLen < 100 && result.Methods.Count < maxMethods)
                {
                    if (seen.Contains(current)) break;
                    seen.Add(current);

                    var entry = ReadJitEntry(driver, pid, current);
                    if (entry != null)
                    {
                        result.Methods.Add(entry);
                        result.ResolvedEntries++;
                    }

                    // Follow hash chain
                    ulong next = ReadPtr(driver, pid, current + kJitInfo_NextJitCodeHash);
                    current = next;
                    chainLen++;
                }
            }

            return result;
        }

        private static ulong FindJitInfoTable(IMemoryReader driver, int pid, ulong monoBase, uint monoSize)
        {
            // Strategy 1: Find via mono_jit_info_table_find export
            var exports = driver.GetExportMap(pid);
            if (exports != null)
            {
                // Look for mono_domain_get which returns the root domain
                // Then read domain->jit_info_table
                foreach (var kvp in exports)
                {
                    if (kvp.Value.funcName == "mono_get_root_domain")
                    {
                        ulong funcAddr = kvp.Key;
                        byte[] funcBody = ReadMemory(driver, pid, funcAddr, 32);
                        if (funcBody == null) break;

                        for (int i = 0; i <= funcBody.Length - 7; i++)
                        {
                            if (funcBody[i] == 0x48 && funcBody[i + 1] == 0x8B && funcBody[i + 2] == 0x05)
                            {
                                int disp = BitConverter.ToInt32(funcBody, i + 3);
                                ulong ptrAddr = funcAddr + (ulong)(i + 7) + (ulong)disp;
                                ulong domain = ReadPtr(driver, pid, ptrAddr);
                                if (domain == 0) continue;

                                // MonoDomain->jit_info_table is typically around offset 0xD0-0x100
                                // Try known offsets
                                int[] jitTableOffsets = { 0xD8, 0xE0, 0xE8, 0xD0, 0xF0, 0xF8 };
                                foreach (int off in jitTableOffsets)
                                {
                                    ulong tableCandidate = ReadPtr(driver, pid, domain + (ulong)off);
                                    if (tableCandidate == 0) continue;

                                    // Validate: first field should be a reasonable entry count
                                    byte[] header = ReadMemory(driver, pid, tableCandidate, 16);
                                    if (header == null) continue;

                                    int count = BitConverter.ToInt32(header, 0);
                                    if (count > 0 && count < 1000000)
                                        return tableCandidate;
                                }
                            }
                        }
                        break;
                    }
                }
            }

            // Strategy 2: Pattern scan in mono .data section
            byte[] peHeader = ReadMemory(driver, pid, monoBase, 0x1000);
            if (peHeader == null) return 0;

            int peOff = BitConverter.ToInt32(peHeader, 0x3C);
            ushort sectionCount = BitConverter.ToUInt16(peHeader, peOff + 6);
            ushort optHeaderSize = BitConverter.ToUInt16(peHeader, peOff + 20);
            int sectionTableOff = peOff + 24 + optHeaderSize;

            for (int s = 0; s < sectionCount; s++)
            {
                int off = sectionTableOff + s * 40;
                if (off + 40 > peHeader.Length) break;
                string sName = Encoding.ASCII.GetString(peHeader, off, 8).TrimEnd('\0');
                if (sName != ".data") continue;

                uint vSize = BitConverter.ToUInt32(peHeader, off + 8);
                uint vAddr = BitConverter.ToUInt32(peHeader, off + 12);
                ulong dataStart = monoBase + vAddr;
                int dataSize = (int)Math.Min(vSize, 0x200000);

                byte[] data = ReadMemory(driver, pid, dataStart, dataSize);
                if (data == null) continue;

                for (int i = 0; i <= data.Length - 8; i += 8)
                {
                    ulong candidate = BitConverter.ToUInt64(data, i);
                    if (candidate < 0x10000 || candidate > 0x7FFFFFFFFFFF) continue;

                    byte[] header = ReadMemory(driver, pid, candidate, 16);
                    if (header == null) continue;

                    int count = BitConverter.ToInt32(header, 0);
                    if (count > 100 && count < 500000)
                    {
                        // Validate first entry pointer
                        ulong firstEntry = ReadPtr(driver, pid, candidate + kJitTable_Entries);
                        if (firstEntry != 0 && firstEntry > 0x10000)
                            return candidate;
                    }
                }
            }

            return 0;
        }

        private static JitMethodEntry ReadJitEntry(IMemoryReader driver, int pid, ulong jitInfoAddr)
        {
            byte[] data = ReadMemory(driver, pid, jitInfoAddr, 0x28);
            if (data == null) return null;

            ulong methodPtr = BitConverter.ToUInt64(data, kJitInfo_Method);
            ulong codeStart = BitConverter.ToUInt64(data, kJitInfo_CodeStart);
            int codeSize = BitConverter.ToInt32(data, kJitInfo_CodeSize);

            if (methodPtr == 0 || codeStart == 0 || codeSize <= 0 || codeSize > 0x1000000)
                return null;

            var entry = new JitMethodEntry
            {
                MethodPointer = methodPtr,
                CodeStart = codeStart,
                CodeSize = codeSize
            };

            // Read method name
            ulong namePtr = ReadPtr(driver, pid, methodPtr + kMethod_Name);
            entry.MethodName = namePtr != 0 ? ReadCString(driver, pid, namePtr, 128) : "<unknown>";

            // Read token
            byte[] tokenData = ReadMemory(driver, pid, methodPtr + kMethod_Token, 4);
            if (tokenData != null)
                entry.Token = BitConverter.ToUInt32(tokenData, 0);

            // Read class name
            ulong klassPtr = ReadPtr(driver, pid, methodPtr + kMethod_Klass);
            if (klassPtr != 0)
            {
                ulong classNamePtr = ReadPtr(driver, pid, klassPtr + kClass_Name);
                entry.ClassName = classNamePtr != 0 ? ReadCString(driver, pid, classNamePtr, 128) : "";

                ulong classNsPtr = ReadPtr(driver, pid, klassPtr + kClass_Namespace);
                string ns = classNsPtr != 0 ? ReadCString(driver, pid, classNsPtr, 128) : "";

                string fullClass = string.IsNullOrEmpty(ns) ? entry.ClassName : $"{ns}.{entry.ClassName}";
                entry.FullName = $"{fullClass}.{entry.MethodName}";
            }
            else
            {
                entry.FullName = entry.MethodName ?? "<unknown>";
            }

            return entry;
        }

        public static string GenerateReport(JitTableDump dump, string search = null)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - Mono JIT Table Dump");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"// JIT table address: 0x{dump.JitTableAddress:X16}");
            sb.AppendLine($"// Total entries: {dump.TotalEntries}");
            sb.AppendLine($"// Resolved: {dump.ResolvedEntries}");
            sb.AppendLine();

            var methods = dump.Methods.AsEnumerable();
            if (!string.IsNullOrEmpty(search))
            {
                methods = methods.Where(m =>
                    m.FullName != null && m.FullName.IndexOf(search, StringComparison.OrdinalIgnoreCase) >= 0);
            }

            foreach (var m in methods.OrderBy(m => m.FullName))
            {
                sb.AppendLine($"  {m.FullName} // code: 0x{m.CodeStart:X16} size: {m.CodeSize} token: 0x{m.Token:X8}");
            }

            return sb.ToString();
        }

        public static Dictionary<string, ulong> GetCodeAddressMap(JitTableDump dump)
        {
            var map = new Dictionary<string, ulong>();
            foreach (var m in dump.Methods)
            {
                if (!string.IsNullOrEmpty(m.FullName) && !map.ContainsKey(m.FullName))
                    map[m.FullName] = m.CodeStart;
            }
            return map;
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

        private static string ReadCString(IMemoryReader driver, int pid, ulong address, int maxLen)
        {
            byte[] buf = ReadMemory(driver, pid, address, maxLen);
            if (buf == null) return null;
            int len = Array.IndexOf(buf, (byte)0);
            if (len < 0) len = maxLen;
            if (len == 0) return "";
            try { return Encoding.UTF8.GetString(buf, 0, len); }
            catch { return null; }
        }
    }
}
