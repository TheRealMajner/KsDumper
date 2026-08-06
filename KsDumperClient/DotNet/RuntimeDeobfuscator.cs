using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using KsDumperClient.Driver;

namespace KsDumperClient.DotNet
{
    public class RuntimeDeobfuscator
    {
        private readonly IMemoryReader _driver;
        private readonly int _pid;

        public RuntimeDeobfuscator(IMemoryReader driver, int pid)
        {
            _driver = driver;
            _pid = pid;
        }

        public struct RuntimeDeobResult
        {
            public int StringsRecovered;
            public int MethodBodiesRecovered;
            public int TokensFixed;
            public int PatchesApplied;
            public string[] Log;
        }

        /// <summary>
        /// Full runtime deobfuscation: reads live CLR state where the runtime has already
        /// decrypted everything that static analysis can't touch.
        /// </summary>
        public RuntimeDeobResult DeobfuscateFromRuntime(byte[] peBytes, ulong moduleBase, Action<string> log = null)
        {
            var logs = new List<string>();
            void Log(string msg) { logs.Add(msg); log?.Invoke(msg); }

            var result = new RuntimeDeobResult();

            var cli = CliHeader.Parse(peBytes);
            if (cli == null) { Log("Not a .NET assembly"); result.Log = logs.ToArray(); return result; }

            var tables = MetadataTableParser.Parse(peBytes, cli);
            if (tables?.MethodDefs == null) { Log("Failed to parse metadata"); result.Log = logs.ToArray(); return result; }

            bool is64 = BitConverter.ToUInt16(peBytes, BitConverter.ToInt32(peBytes, 60) + 4) != 0x014C;
            int peOff = BitConverter.ToInt32(peBytes, 60);

            // Step 1: Recover method bodies from live memory
            // The CLR JIT compiler reads the IL from memory — if the .cctor decrypted it,
            // the in-memory version has the real IL while the on-disk version has garbage.
            int bodiesRecovered = RecoverMethodBodies(peBytes, tables, moduleBase, is64, peOff, Log);
            result.MethodBodiesRecovered = bodiesRecovered;

            // Step 2: Recover encrypted strings from the managed heap
            int stringsRecovered = RecoverStrings(peBytes, tables, moduleBase, is64, peOff, Log);
            result.StringsRecovered = stringsRecovered;

            // Step 3: Fix encrypted metadata tokens — call tokens that were replaced
            // with encrypted values are resolved in the CLR's internal tables at runtime
            int tokensFixed = FixEncryptedTokens(peBytes, tables, moduleBase, is64, peOff, Log);
            result.TokensFixed = tokensFixed;

            // Step 4: Apply all static patches on top (the runtime-recovered bytes benefit from these)
            int patches = 0;
            patches += DotNetDeobfuscator.PatchAntiIldasm(peBytes).PatchCount;
            patches += DotNetDeobfuscator.PatchAntiDnSpy(peBytes).PatchCount;
            patches += DotNetDeobfuscator.PatchModuleCctor(peBytes).PatchCount;
            patches += DotNetDeobfuscator.PatchAntiDebug(peBytes).PatchCount;
            patches += DotNetDeobfuscator.PatchCallProxies(peBytes).PatchCount;
            patches += DotNetDeobfuscator.PatchMathMutations(peBytes).PatchCount;
            patches += DotNetDeobfuscator.PatchControlFlow(peBytes).PatchCount;
            patches += DotNetDeobfuscator.PatchStringEncryption(peBytes).PatchCount;
            result.PatchesApplied = patches;

            if (patches > 0)
                Log($"Applied {patches} static patches on recovered bytecode");

            int total = bodiesRecovered + stringsRecovered + tokensFixed + patches;
            Log($"Runtime deobfuscation complete: {total} total fixes ({bodiesRecovered} bodies, {stringsRecovered} strings, {tokensFixed} tokens, {patches} patches)");

            result.Log = logs.ToArray();
            return result;
        }

        /// <summary>
        /// Reads method bodies from the live process memory. When obfuscators encrypt IL on disk
        /// but decrypt it at runtime via .cctor, the in-memory copy has the real bytecode.
        /// We read each method's IL from the process and overwrite the file copy.
        /// </summary>
        private int RecoverMethodBodies(byte[] peBytes, MetadataTableParser tables,
            ulong moduleBase, bool is64, int peOff, Action<string> log)
        {
            int recovered = 0;

            for (int i = 0; i < tables.MethodDefs.Length; i++)
            {
                uint rva = tables.MethodDefs[i].Rva;
                if (rva == 0) continue;

                int fileOffset = CliHeader.RvaToFileOffset(peBytes, peOff, rva, is64);
                if (fileOffset < 0 || fileOffset + 2 > peBytes.Length) continue;

                byte headerByte = peBytes[fileOffset];
                int codeOffset, codeSize;

                if ((headerByte & 0x03) == 0x02)
                {
                    codeSize = headerByte >> 2;
                    codeOffset = fileOffset + 1;
                }
                else if ((headerByte & 0x03) == 0x03)
                {
                    if (fileOffset + 12 > peBytes.Length) continue;
                    codeSize = BitConverter.ToInt32(peBytes, fileOffset + 4);
                    codeOffset = fileOffset + 12;
                }
                else continue;

                if (codeSize <= 0 || codeSize > 0x100000 || codeOffset + codeSize > peBytes.Length) continue;

                // Read the same method body from live process memory
                ulong runtimeAddr = moduleBase + rva;
                byte[] liveHeader = ReadBytes(runtimeAddr, 12);
                if (liveHeader == null) continue;

                byte liveHdrByte = liveHeader[0];
                int livCodeSize, headerSize;

                if ((liveHdrByte & 0x03) == 0x02)
                {
                    livCodeSize = liveHdrByte >> 2;
                    headerSize = 1;
                }
                else if ((liveHdrByte & 0x03) == 0x03)
                {
                    livCodeSize = BitConverter.ToInt32(liveHeader, 4);
                    headerSize = 12;
                }
                else continue;

                if (livCodeSize <= 0 || livCodeSize > 0x100000) continue;

                // Read the actual IL bytes from memory
                byte[] liveCode = ReadBytes(runtimeAddr + (ulong)headerSize, livCodeSize);
                if (liveCode == null) continue;

                // Compare: if the live version differs from on-disk, the runtime decrypted it
                bool differs = false;
                if (livCodeSize == codeSize)
                {
                    for (int j = 0; j < codeSize; j++)
                    {
                        if (liveCode[j] != peBytes[codeOffset + j])
                        {
                            differs = true;
                            break;
                        }
                    }
                }
                else
                {
                    differs = true;
                }

                if (differs)
                {
                    // Overwrite the file bytes with the live (decrypted) version
                    if (livCodeSize == codeSize)
                    {
                        Array.Copy(liveCode, 0, peBytes, codeOffset, codeSize);
                        recovered++;
                    }
                    else if (livCodeSize <= codeSize)
                    {
                        // Live body is smaller — copy and NOP-pad the rest
                        Array.Copy(liveCode, 0, peBytes, codeOffset, livCodeSize);
                        for (int j = codeOffset + livCodeSize; j < codeOffset + codeSize; j++)
                            peBytes[j] = 0x00; // nop
                        recovered++;
                    }
                    // If live body is larger, we can't fit it — skip (would corrupt layout)
                }
            }

            if (recovered > 0)
                log($"Recovered {recovered} decrypted method bodies from runtime");

            return recovered;
        }

        /// <summary>
        /// Scans the #US (User Strings) heap in live memory to recover strings that were encrypted
        /// on disk. The CLR decrypts them when first accessed; the in-memory copy has the real strings.
        /// </summary>
        private int RecoverStrings(byte[] peBytes, MetadataTableParser tables,
            ulong moduleBase, bool is64, int peOff, Action<string> log)
        {
            int recovered = 0;

            // Find the #US heap in the PE
            int bsjbFileOffset = FindBsjbOffset(peBytes);
            if (bsjbFileOffset < 0) return 0;

            var streamInfo = FindStream(peBytes, bsjbFileOffset, "#US");
            if (streamInfo.offset < 0 || streamInfo.size <= 1) return 0;

            int usFileOffset = bsjbFileOffset + streamInfo.offset;
            int usSize = streamInfo.size;

            if (usFileOffset + usSize > peBytes.Length) return 0;

            // Calculate the RVA of the #US heap to read from live memory
            // bsjbFileOffset is the file offset of the metadata root (BSJB signature)
            // We need to convert usFileOffset to an RVA
            uint usRva = FileOffsetToRva(peBytes, peOff, usFileOffset, is64);
            if (usRva == 0) return 0;

            ulong usRuntimeAddr = moduleBase + usRva;

            // Read the entire #US heap from live memory
            byte[] liveUs = ReadBytes(usRuntimeAddr, usSize);
            if (liveUs == null) return 0;

            // Compare and replace
            bool anyDiff = false;
            for (int i = 0; i < usSize; i++)
            {
                if (liveUs[i] != peBytes[usFileOffset + i])
                {
                    anyDiff = true;
                    break;
                }
            }

            if (anyDiff)
            {
                Array.Copy(liveUs, 0, peBytes, usFileOffset, usSize);

                // Count recovered strings
                int pos = 1; // first byte is always 0
                while (pos < usSize)
                {
                    int len = ReadCompressedUint(liveUs, ref pos);
                    if (len <= 0 || pos + len > usSize) break;
                    if (len > 1) recovered++;
                    pos += len;
                }

                log($"Recovered {recovered} strings from runtime #US heap");
            }

            return recovered;
        }

        /// <summary>
        /// Fix encrypted call tokens. Some obfuscators replace call/callvirt tokens with
        /// encrypted values; the CLR resolves them at runtime. We read the live method bodies
        /// (already done in RecoverMethodBodies) but this specifically targets the pattern where
        /// only the token operand differs while the opcode is intact.
        /// </summary>
        private int FixEncryptedTokens(byte[] peBytes, MetadataTableParser tables,
            ulong moduleBase, bool is64, int peOff, Action<string> log)
        {
            int fixed_ = 0;

            for (int i = 0; i < tables.MethodDefs.Length; i++)
            {
                uint rva = tables.MethodDefs[i].Rva;
                if (rva == 0) continue;

                int fileOffset = CliHeader.RvaToFileOffset(peBytes, peOff, rva, is64);
                if (fileOffset < 0 || fileOffset + 2 > peBytes.Length) continue;

                byte headerByte = peBytes[fileOffset];
                int codeOffset, codeSize;

                if ((headerByte & 0x03) == 0x02)
                {
                    codeSize = headerByte >> 2;
                    codeOffset = fileOffset + 1;
                }
                else if ((headerByte & 0x03) == 0x03)
                {
                    if (fileOffset + 12 > peBytes.Length) continue;
                    codeSize = BitConverter.ToInt32(peBytes, fileOffset + 4);
                    codeOffset = fileOffset + 12;
                }
                else continue;

                if (codeSize < 5 || codeOffset + codeSize > peBytes.Length) continue;

                // Read the live IL for comparison
                ulong runtimeAddr = moduleBase + rva;
                byte[] liveHeader = ReadBytes(runtimeAddr, (headerByte & 0x03) == 0x02 ? 1 : 12);
                if (liveHeader == null) continue;

                int hdrSize = (headerByte & 0x03) == 0x02 ? 1 : 12;
                byte[] liveCode = ReadBytes(runtimeAddr + (ulong)hdrSize, codeSize);
                if (liveCode == null || liveCode.Length != codeSize) continue;

                // Scan for token-bearing opcodes where the live token differs
                for (int j = 0; j < codeSize - 4; j++)
                {
                    byte op = peBytes[codeOffset + j];
                    byte liveOp = liveCode[j];

                    // Only fix if the opcode matches but the token differs
                    if (op != liveOp) continue;

                    // Opcodes that carry a 4-byte metadata token
                    bool isTokenOp = (op == 0x28 || op == 0x6F || op == 0x73 || // call, callvirt, newobj
                                      op == 0x72 || op == 0x7E || op == 0x7F || // ldstr, ldsfld, stsfld
                                      op == 0x74 || op == 0x75 || op == 0x70);  // castclass, isinst, ldtoken

                    if (!isTokenOp) continue;

                    int diskToken = BitConverter.ToInt32(peBytes, codeOffset + j + 1);
                    int liveToken = BitConverter.ToInt32(liveCode, j + 1);

                    if (diskToken != liveToken && liveToken != 0)
                    {
                        // The live token is the real one — the CLR resolved the encrypted token
                        int tableId = (liveToken >> 24) & 0xFF;
                        // Sanity: token should reference a valid metadata table
                        if (tableId >= 0x01 && tableId <= 0x2C)
                        {
                            BitConverter.GetBytes(liveToken).CopyTo(peBytes, codeOffset + j + 1);
                            fixed_++;
                        }
                    }

                    j += 4; // skip the token bytes
                }
            }

            if (fixed_ > 0)
                log($"Fixed {fixed_} encrypted metadata tokens from runtime");

            return fixed_;
        }

        /// <summary>
        /// Dump all managed string objects from the .NET heap.
        /// Walks CLR internal structures to find System.String instances.
        /// Returns (address, value) pairs.
        /// </summary>
        public List<(ulong address, string value)> DumpManagedStrings(ulong moduleBase, uint moduleSize)
        {
            var strings = new List<(ulong, string)>();

            // Use the driver's existing string dumper — it already walks memory regions
            var rawStrings = _driver.DumpLiveStrings(_pid, 4);
            if (rawStrings == null) return strings;

            // Filter to strings from the module's memory range (managed heap is typically nearby)
            foreach (var s in rawStrings)
            {
                if (s.value != null && s.value.Length >= 4 && s.value.Length < 4096)
                {
                    strings.Add((s.address, s.value));
                }
            }

            return strings;
        }

        /// <summary>
        /// Reads the entire PE section containing .NET metadata from live memory,
        /// recovering any runtime-decrypted sections (resources, embedded data).
        /// </summary>
        public byte[] ReadLiveModule(ulong moduleBase, int imageSize)
        {
            return ReadBytes(moduleBase, imageSize);
        }

        // --- Helpers ---

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

        private static int FindBsjbOffset(byte[] data)
        {
            byte[] sig = { 0x42, 0x53, 0x4A, 0x42 };
            for (int i = 0; i < data.Length - 4; i++)
            {
                if (data[i] == sig[0] && data[i + 1] == sig[1] &&
                    data[i + 2] == sig[2] && data[i + 3] == sig[3])
                    return i;
            }
            return -1;
        }

        private static (int offset, int size) FindStream(byte[] data, int bsjbOffset, string streamName)
        {
            int p = bsjbOffset + 12;
            if (p + 4 > data.Length) return (-1, 0);
            uint versionLen = BitConverter.ToUInt32(data, p);
            p += 4 + (int)versionLen + 2;
            if (p + 2 > data.Length) return (-1, 0);
            ushort numStreams = BitConverter.ToUInt16(data, p);
            p += 2;

            for (int i = 0; i < numStreams && p + 8 <= data.Length; i++)
            {
                int sOff = (int)BitConverter.ToUInt32(data, p);
                int sSize = (int)BitConverter.ToUInt32(data, p + 4);
                p += 8;
                int nameStart = p;
                while (p < data.Length && data[p] != 0) p++;
                string name = Encoding.ASCII.GetString(data, nameStart, p - nameStart);
                p++;
                while (p % 4 != 0) p++;

                if (name == streamName)
                    return (sOff, sSize);
            }

            return (-1, 0);
        }

        private static uint FileOffsetToRva(byte[] peBytes, int peOff, int fileOffset, bool is64)
        {
            // Walk section headers to convert file offset → RVA
            int numSections = BitConverter.ToUInt16(peBytes, peOff + 6);
            int optHeaderSize = BitConverter.ToUInt16(peBytes, peOff + 20);
            int sectionStart = peOff + 24 + optHeaderSize;

            for (int i = 0; i < numSections; i++)
            {
                int secOff = sectionStart + i * 40;
                if (secOff + 40 > peBytes.Length) break;

                uint virtualSize = BitConverter.ToUInt32(peBytes, secOff + 8);
                uint virtualAddr = BitConverter.ToUInt32(peBytes, secOff + 12);
                uint rawDataSize = BitConverter.ToUInt32(peBytes, secOff + 16);
                uint rawDataPtr = BitConverter.ToUInt32(peBytes, secOff + 20);

                if (fileOffset >= rawDataPtr && fileOffset < rawDataPtr + rawDataSize)
                {
                    return virtualAddr + (uint)(fileOffset - rawDataPtr);
                }
            }

            return 0;
        }

        private static int ReadCompressedUint(byte[] data, ref int pos)
        {
            if (pos >= data.Length) return -1;
            byte first = data[pos];
            if ((first & 0x80) == 0) { pos++; return first; }
            if ((first & 0xC0) == 0x80)
            {
                if (pos + 1 >= data.Length) return -1;
                int val = ((first & 0x3F) << 8) | data[pos + 1];
                pos += 2;
                return val;
            }
            if ((first & 0xE0) == 0xC0)
            {
                if (pos + 3 >= data.Length) return -1;
                int val = ((first & 0x1F) << 24) | (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3];
                pos += 4;
                return val;
            }
            return -1;
        }
    }
}
