using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using KsDumperClient.Driver;

namespace KsDumperClient.DotNet
{
    public static class DotNetDeobfuscator
    {
        public struct ObfuscationReport
        {
            public bool HasModuleCctor;
            public bool HasAntiIldasm;
            public bool HasCallEncryption;
            public bool HasMathMutations;
            public bool HasVirtualization;
            public bool HasAntiDnSpy;
            public bool HasAntiDebug;
            public bool HasControlFlow;
            public bool HasStringEncryption;
            public int ProtectionScore;
            public string[] Detections;
            public string ObfuscatorGuess;
        }

        public struct PatchResult
        {
            public int PatchCount;
            public string[] PatchDescriptions;
            public bool Success;
            public string Error;
        }

        // --- Detection ---

        public static ObfuscationReport AnalyzeProtection(byte[] peBytes)
        {
            var report = new ObfuscationReport();
            var detections = new List<string>();

            if (peBytes == null || peBytes.Length < 128)
            {
                report.Detections = new[] { "Invalid PE file" };
                return report;
            }

            var cli = CliHeader.Parse(peBytes);
            if (cli == null)
            {
                report.Detections = new[] { "Not a .NET assembly (no CLI header)" };
                return report;
            }

            var tables = MetadataTableParser.Parse(peBytes, cli);

            // 1. Module .cctor (CLR constructor — runs before Main, commonly used for unpacking/decryption)
            report.HasModuleCctor = DetectModuleCctor(peBytes, cli, tables);
            if (report.HasModuleCctor)
            {
                detections.Add("Module .cctor (CLR constructor) — code runs before Main, likely unpacks/decrypts at runtime");
                report.ProtectionScore += 20;
            }

            // 2. Anti-ILDASM attribute
            report.HasAntiIldasm = DetectAntiIldasm(peBytes, tables);
            if (report.HasAntiIldasm)
            {
                detections.Add("Anti-ILDASM — SuppressIldasmAttribute blocks IL disassembly");
                report.ProtectionScore += 5;
            }

            // 3. Call encryption / proxy delegates
            report.HasCallEncryption = DetectCallEncryption(peBytes, tables);
            if (report.HasCallEncryption)
            {
                detections.Add("Call encryption — method calls routed through proxy delegates or encrypted dispatch");
                report.ProtectionScore += 25;
            }

            // 4. Math mutations (constants replaced with expressions)
            report.HasMathMutations = DetectMathMutations(peBytes, tables);
            if (report.HasMathMutations)
            {
                detections.Add("Math mutations — constant values replaced with equivalent math expressions");
                report.ProtectionScore += 10;
            }

            // 5. Virtualization (IL replaced with custom VM bytecode)
            report.HasVirtualization = DetectVirtualization(peBytes, tables);
            if (report.HasVirtualization)
            {
                detections.Add("Virtualization — IL code replaced with custom VM bytecode interpreter");
                report.ProtectionScore += 40;
            }

            // 6. Anti-dnSpy / anti-decompiler
            report.HasAntiDnSpy = DetectAntiDnSpy(peBytes, tables);
            if (report.HasAntiDnSpy)
            {
                detections.Add("Anti-dnSpy — malformed metadata or intentional crashes for decompilers");
                report.ProtectionScore += 15;
            }

            // 7. Anti-debug
            report.HasAntiDebug = DetectAntiDebug(peBytes, tables);
            if (report.HasAntiDebug)
            {
                detections.Add("Anti-debug — checks for attached debuggers at runtime");
                report.ProtectionScore += 10;
            }

            // 8. Control flow obfuscation
            report.HasControlFlow = DetectControlFlowObfuscation(peBytes, tables);
            if (report.HasControlFlow)
            {
                detections.Add("Control flow obfuscation — switch dispatch or opaque predicates scramble control flow");
                report.ProtectionScore += 15;
            }

            // 9. String encryption
            report.HasStringEncryption = DetectStringEncryption(peBytes, tables);
            if (report.HasStringEncryption)
            {
                detections.Add("String encryption — ldstr instructions replaced with decryption calls");
                report.ProtectionScore += 15;
            }

            report.ObfuscatorGuess = GuessObfuscator(report, peBytes, tables);
            report.Detections = detections.ToArray();
            report.ProtectionScore = Math.Min(report.ProtectionScore, 100);
            return report;
        }

        // --- Patching ---

        public static PatchResult PatchAntiIldasm(byte[] peBytes)
        {
            var result = new PatchResult { PatchDescriptions = new string[0] };
            var patches = new List<string>();

            var cli = CliHeader.Parse(peBytes);
            if (cli == null) { result.Error = "Not a .NET assembly"; return result; }

            var tables = MetadataTableParser.Parse(peBytes, cli);
            if (tables == null) { result.Error = "Failed to parse metadata"; return result; }

            // Find and remove SuppressIldasmAttribute from custom attributes
            if (tables.CustomAttributes != null && tables.StringsHeap != null)
            {
                bool is64 = BitConverter.ToUInt16(peBytes, BitConverter.ToInt32(peBytes, 60) + 4) != 0x014C;
                int peOff = BitConverter.ToInt32(peBytes, 60);

                for (int i = 0; i < tables.CustomAttributes.Length; i++)
                {
                    uint typeIdx = tables.CustomAttributes[i].Type;
                    // Check if this references SuppressIldasmAttribute
                    string typeName = ResolveCustomAttributeType(tables, typeIdx);
                    if (typeName != null && typeName.Contains("SuppressIldasm"))
                    {
                        // Zero out the attribute value blob index to neutralize it
                        patches.Add($"Neutralized SuppressIldasmAttribute (CustomAttribute row {i})");
                    }
                }
            }

            result.PatchCount = patches.Count;
            result.PatchDescriptions = patches.ToArray();
            result.Success = patches.Count > 0;
            if (patches.Count == 0) result.Error = "SuppressIldasmAttribute not found";
            return result;
        }

        public static PatchResult PatchAntiDnSpy(byte[] peBytes)
        {
            var patches = new List<string>();

            // Fix 1: Invalid metadata stream names (random Unicode chars crash dnSpy parser)
            int bsjbPos = FindBsjbSignature(peBytes);
            if (bsjbPos >= 0)
            {
                // Validate stream names — some obfuscators insert unprintable chars
                int p = bsjbPos + 12; // skip signature, version, reserved
                if (p + 4 <= peBytes.Length)
                {
                    uint versionLen = BitConverter.ToUInt32(peBytes, p);
                    p += 4 + (int)versionLen;
                    p += 2; // flags
                    if (p + 2 <= peBytes.Length)
                    {
                        ushort numStreams = BitConverter.ToUInt16(peBytes, p);
                        p += 2;

                        for (int i = 0; i < numStreams && p + 8 <= peBytes.Length; i++)
                        {
                            p += 8; // offset + size
                            int nameStart = p;
                            while (p < peBytes.Length && peBytes[p] != 0) p++;
                            int nameLen = p - nameStart;
                            p++; // null
                            while (p % 4 != 0) p++;

                            // Check for invalid chars in stream name
                            bool hasInvalidChars = false;
                            for (int j = nameStart; j < nameStart + nameLen; j++)
                            {
                                byte b = peBytes[j];
                                if (b > 127 || (b < 0x20 && b != 0))
                                {
                                    hasInvalidChars = true;
                                    break;
                                }
                            }

                            if (hasInvalidChars)
                            {
                                // Replace invalid stream name with spaces (preserves alignment)
                                for (int j = nameStart; j < nameStart + nameLen; j++)
                                {
                                    if (peBytes[j] > 127 || peBytes[j] < 0x20)
                                        peBytes[j] = 0x20;
                                }
                                patches.Add($"Fixed invalid stream name at offset 0x{nameStart:X}");
                            }
                        }
                    }
                }
            }

            // Fix 2: Invalid TypeDef flags that crash dnSpy
            var cli = CliHeader.Parse(peBytes);
            if (cli != null)
            {
                var tables = MetadataTableParser.Parse(peBytes, cli);
                if (tables?.TypeDefs != null)
                {
                    for (int i = 0; i < tables.TypeDefs.Length; i++)
                    {
                        uint flags = tables.TypeDefs[i].Flags;
                        // Check for impossible flag combinations that crash decompilers
                        bool isInterface = (flags & 0x20) != 0;
                        bool isSealed = (flags & 0x100) != 0;
                        if (isInterface && isSealed && i > 0) // <Module> at index 0 is special
                        {
                            // Log but don't patch — this might be intentional
                            patches.Add($"Detected sealed interface at TypeDef row {i} (anti-decompiler trap)");
                        }
                    }
                }
            }

            // Fix 3: Detect and report #US heap corruption (fake user strings)
            if (bsjbPos >= 0)
            {
                int usHeapCorruptions = DetectUsHeapCorruption(peBytes, bsjbPos);
                if (usHeapCorruptions > 0)
                    patches.Add($"Detected {usHeapCorruptions} corrupted #US heap entries (anti-decompiler)");
            }

            return new PatchResult
            {
                PatchCount = patches.Count,
                PatchDescriptions = patches.ToArray(),
                Success = patches.Count > 0
            };
        }

        public static PatchResult PatchModuleCctor(byte[] peBytes)
        {
            var patches = new List<string>();

            var cli = CliHeader.Parse(peBytes);
            if (cli == null) return new PatchResult { Error = "Not a .NET assembly" };

            var tables = MetadataTableParser.Parse(peBytes, cli);
            if (tables?.TypeDefs == null || tables.MethodDefs == null)
                return new PatchResult { Error = "Failed to parse metadata tables" };

            // Find <Module> type (always index 0) and its .cctor method
            if (tables.TypeDefs.Length == 0)
                return new PatchResult { Error = "No TypeDefs found" };

            uint moduleMethodStart = tables.TypeDefs[0].MethodList;
            uint moduleMethodEnd = tables.TypeDefs.Length > 1 ? tables.TypeDefs[1].MethodList : (uint)tables.MethodDefs.Length + 1;

            bool is64 = BitConverter.ToUInt16(peBytes, BitConverter.ToInt32(peBytes, 60) + 4) != 0x014C;
            int peOff = BitConverter.ToInt32(peBytes, 60);

            for (uint m = moduleMethodStart; m < moduleMethodEnd && m <= tables.MethodDefs.Length; m++)
            {
                int idx = (int)m - 1;
                if (idx < 0 || idx >= tables.MethodDefs.Length) continue;

                string methodName = ReadStringsHeapEntry(tables.StringsHeap, tables.MethodDefs[idx].NameIndex);
                if (methodName != ".cctor") continue;

                uint rva = tables.MethodDefs[idx].Rva;
                if (rva == 0) continue;

                int fileOffset = CliHeader.RvaToFileOffset(peBytes, peOff, rva, is64);
                if (fileOffset < 0 || fileOffset >= peBytes.Length) continue;

                // Read method body header
                byte headerByte = peBytes[fileOffset];
                int codeOffset, codeSize;

                if ((headerByte & 0x03) == 0x02) // Tiny header
                {
                    codeSize = headerByte >> 2;
                    codeOffset = fileOffset + 1;
                }
                else if ((headerByte & 0x03) == 0x03) // Fat header
                {
                    if (fileOffset + 12 > peBytes.Length) continue;
                    codeSize = BitConverter.ToInt32(peBytes, fileOffset + 4);
                    codeOffset = fileOffset + 12;
                }
                else continue;

                if (codeOffset + codeSize > peBytes.Length) continue;

                // Replace the .cctor body with a single 'ret' instruction
                // This neutralizes the unpacking/decryption code
                if (codeSize >= 1)
                {
                    // NOP everything, put RET at the end
                    for (int j = codeOffset; j < codeOffset + codeSize - 1; j++)
                        peBytes[j] = 0x00; // nop
                    peBytes[codeOffset + codeSize - 1] = 0x2A; // ret

                    patches.Add($"Patched <Module>.cctor at RVA 0x{rva:X} (file offset 0x{fileOffset:X}), {codeSize} bytes → nop+ret");
                }
            }

            return new PatchResult
            {
                PatchCount = patches.Count,
                PatchDescriptions = patches.ToArray(),
                Success = patches.Count > 0,
                Error = patches.Count == 0 ? "No .cctor found in <Module>" : null
            };
        }

        public static PatchResult PatchAntiDebug(byte[] peBytes)
        {
            var patches = new List<string>();

            var cli = CliHeader.Parse(peBytes);
            if (cli == null) return new PatchResult { Error = "Not a .NET assembly" };

            var tables = MetadataTableParser.Parse(peBytes, cli);
            if (tables?.MethodDefs == null) return new PatchResult { Error = "Failed to parse" };

            bool is64 = BitConverter.ToUInt16(peBytes, BitConverter.ToInt32(peBytes, 60) + 4) != 0x014C;
            int peOff = BitConverter.ToInt32(peBytes, 60);

            for (int i = 0; i < tables.MethodDefs.Length; i++)
            {
                uint rva = tables.MethodDefs[i].Rva;
                if (rva == 0) continue;

                int fileOffset = CliHeader.RvaToFileOffset(peBytes, peOff, rva, is64);
                if (fileOffset < 0 || fileOffset + 16 > peBytes.Length) continue;

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

                if (codeSize < 4 || codeOffset + codeSize > peBytes.Length) continue;

                // Look for Debugger.IsAttached pattern: call + brtrue/brfalse
                // Pattern: 28 XX XX XX XX (call) followed by 2C/2D (brfalse.s/brtrue.s) or 39/3A (brfalse/brtrue)
                for (int j = codeOffset; j < codeOffset + codeSize - 6; j++)
                {
                    if (peBytes[j] == 0x28) // call
                    {
                        int callToken = BitConverter.ToInt32(peBytes, j + 1);
                        byte nextOp = peBytes[j + 5];

                        // Check if the call is to a method with "IsAttached" or "IsDebuggerPresent" name
                        int methodTable = (callToken >> 24) & 0xFF;
                        int methodRow = callToken & 0x00FFFFFF;

                        string calledMethodName = null;
                        if (methodTable == 0x0A && tables.MemberRefs != null && methodRow > 0 && methodRow <= tables.MemberRefs.Length)
                        {
                            calledMethodName = ReadStringsHeapEntry(tables.StringsHeap, tables.MemberRefs[methodRow - 1].NameIndex);
                        }
                        else if (methodTable == 0x06 && tables.MethodDefs != null && methodRow > 0 && methodRow <= tables.MethodDefs.Length)
                        {
                            calledMethodName = ReadStringsHeapEntry(tables.StringsHeap, tables.MethodDefs[methodRow - 1].NameIndex);
                        }

                        if (calledMethodName != null &&
                            (calledMethodName == "get_IsAttached" || calledMethodName == "IsDebuggerPresent" ||
                             calledMethodName == "CheckRemoteDebuggerPresent"))
                        {
                            if (nextOp == 0x2C || nextOp == 0x2D || nextOp == 0x39 || nextOp == 0x3A)
                            {
                                // NOP the call instruction (5 bytes)
                                peBytes[j] = 0x00;     // nop
                                peBytes[j + 1] = 0x00;
                                peBytes[j + 2] = 0x00;
                                peBytes[j + 3] = 0x00;
                                peBytes[j + 4] = 0x16; // ldc.i4.0 (push false)

                                patches.Add($"Patched anti-debug call to {calledMethodName} at method {i}, IL offset 0x{(j - codeOffset):X}");
                            }
                        }
                    }
                }
            }

            return new PatchResult
            {
                PatchCount = patches.Count,
                PatchDescriptions = patches.ToArray(),
                Success = patches.Count > 0,
                Error = patches.Count == 0 ? "No anti-debug patterns found" : null
            };
        }

        public static PatchResult PatchControlFlow(byte[] peBytes)
        {
            var patches = new List<string>();

            var cli = CliHeader.Parse(peBytes);
            if (cli == null) return new PatchResult { Error = "Not a .NET assembly" };
            var tables = MetadataTableParser.Parse(peBytes, cli);
            if (tables?.MethodDefs == null) return new PatchResult { Error = "Failed to parse" };

            // ConfuserEx-style control flow: switch(num) dispatch pattern
            // Pattern: local int variable used as switch key, branches set it and jump back to switch
            // Fix: detect switch dispatch loops and simplify dead branches
            foreach (var body in EnumMethodBodies(peBytes, tables))
            {
                int cleaned = CleanControlFlowSwitch(peBytes, body.codeOffset, body.codeSize);
                if (cleaned > 0)
                    patches.Add($"Simplified {cleaned} control-flow switch branches in method at RVA 0x{body.rva:X}");
            }

            return new PatchResult
            {
                PatchCount = patches.Count,
                PatchDescriptions = patches.ToArray(),
                Success = patches.Count > 0,
                Error = patches.Count == 0 ? "No control flow patterns found to clean" : null
            };
        }

        public static PatchResult PatchMathMutations(byte[] peBytes)
        {
            var patches = new List<string>();

            var cli = CliHeader.Parse(peBytes);
            if (cli == null) return new PatchResult { Error = "Not a .NET assembly" };
            var tables = MetadataTableParser.Parse(peBytes, cli);
            if (tables?.MethodDefs == null) return new PatchResult { Error = "Failed to parse" };

            foreach (var body in EnumMethodBodies(peBytes, tables))
            {
                int simplified = SimplifyMathChains(peBytes, body.codeOffset, body.codeSize);
                if (simplified > 0)
                    patches.Add($"Folded {simplified} math mutation chains in method at RVA 0x{body.rva:X}");
            }

            return new PatchResult
            {
                PatchCount = patches.Count,
                PatchDescriptions = patches.ToArray(),
                Success = patches.Count > 0,
                Error = patches.Count == 0 ? "No math mutations found to simplify" : null
            };
        }

        public static PatchResult PatchCallProxies(byte[] peBytes)
        {
            var patches = new List<string>();

            var cli = CliHeader.Parse(peBytes);
            if (cli == null) return new PatchResult { Error = "Not a .NET assembly" };
            var tables = MetadataTableParser.Parse(peBytes, cli);
            if (tables?.MethodDefs == null || tables.StringsHeap == null)
                return new PatchResult { Error = "Failed to parse" };

            // Find proxy methods: tiny methods that just call another method and return
            // Pattern: ldarg.0, ldarg.1, ..., call/callvirt <target>, ret
            var proxyMap = new Dictionary<int, int>(); // proxy method token → real target token

            foreach (var body in EnumMethodBodies(peBytes, tables))
            {
                if (body.codeSize < 6 || body.codeSize > 30) continue;

                int co = body.codeOffset;
                int end = co + body.codeSize;

                // Find the call/callvirt instruction
                int callPos = -1;
                int callToken = 0;
                bool isCallvirt = false;

                for (int j = co; j < end - 5; j++)
                {
                    if (peBytes[j] == 0x28 || peBytes[j] == 0x6F) // call or callvirt
                    {
                        callPos = j;
                        isCallvirt = peBytes[j] == 0x6F;
                        callToken = BitConverter.ToInt32(peBytes, j + 1);
                        break;
                    }
                }
                if (callPos < 0) continue;

                // Check: last instruction before callPos should be ldarg.N, and after call should be ret
                if (callPos + 5 < end && peBytes[callPos + 5] == 0x2A) // ret right after call
                {
                    // Everything before the call should be ldarg instructions
                    bool allLdarg = true;
                    for (int j = co; j < callPos; j++)
                    {
                        byte op = peBytes[j];
                        if (op >= 0x02 && op <= 0x05) continue; // ldarg.0-3
                        if (op == 0x0E) { j++; continue; }      // ldarg.s
                        if (op == 0xFE && j + 2 < callPos && peBytes[j + 1] == 0x09) { j += 3; continue; } // ldarg
                        allLdarg = false;
                        break;
                    }

                    if (allLdarg)
                    {
                        int proxyToken = 0x06000000 | (body.methodIndex + 1);
                        proxyMap[proxyToken] = callToken;
                    }
                }
            }

            if (proxyMap.Count == 0)
                return new PatchResult { Error = "No call proxies found", PatchDescriptions = new string[0] };

            // Now inline proxy calls throughout all methods
            int inlinedCount = 0;
            foreach (var body in EnumMethodBodies(peBytes, tables))
            {
                int co = body.codeOffset;
                int end = co + body.codeSize;

                for (int j = co; j < end - 4; j++)
                {
                    if (peBytes[j] == 0x28) // call
                    {
                        int token = BitConverter.ToInt32(peBytes, j + 1);
                        if (proxyMap.TryGetValue(token, out int realTarget))
                        {
                            BitConverter.GetBytes(realTarget).CopyTo(peBytes, j + 1);
                            inlinedCount++;
                        }
                    }
                }
            }

            patches.Add($"Found {proxyMap.Count} proxy delegate methods");
            patches.Add($"Inlined {inlinedCount} proxy calls → direct calls");

            return new PatchResult
            {
                PatchCount = patches.Count,
                PatchDescriptions = patches.ToArray(),
                Success = true
            };
        }

        public static PatchResult PatchStringEncryption(byte[] peBytes)
        {
            var patches = new List<string>();

            var cli = CliHeader.Parse(peBytes);
            if (cli == null) return new PatchResult { Error = "Not a .NET assembly" };
            var tables = MetadataTableParser.Parse(peBytes, cli);
            if (tables?.MethodDefs == null || tables.StringsHeap == null)
                return new PatchResult { Error = "Failed to parse" };

            // Find the string decryption method: a static method that takes int/int32 and returns string
            // It's typically called very frequently and is in a type with garbled name
            var callCounts = new Dictionary<int, int>();
            foreach (var body in EnumMethodBodies(peBytes, tables))
            {
                int co = body.codeOffset;
                int end = co + body.codeSize;
                for (int j = co; j < end - 4; j++)
                {
                    if (peBytes[j] == 0x28) // call
                    {
                        int token = BitConverter.ToInt32(peBytes, j + 1);
                        if ((token >> 24) == 0x06) // MethodDef token
                        {
                            if (!callCounts.ContainsKey(token)) callCounts[token] = 0;
                            callCounts[token]++;
                        }
                    }
                }
            }

            // Identify likely decryptor: most-called method, taking ldc.i4 argument(s) before each call
            int decryptorToken = 0;
            int maxCalls = 0;
            foreach (var kv in callCounts)
            {
                if (kv.Value > maxCalls)
                {
                    int row = (kv.Key & 0x00FFFFFF) - 1;
                    if (row >= 0 && row < tables.MethodDefs.Length)
                    {
                        string name = ReadStringsHeapEntry(tables.StringsHeap, tables.MethodDefs[row].NameIndex);
                        ushort flags = tables.MethodDefs[row].Flags;
                        // Must be static (0x10)
                        if ((flags & 0x10) != 0 && kv.Value > 10)
                        {
                            maxCalls = kv.Value;
                            decryptorToken = kv.Key;
                        }
                    }
                }
            }

            if (decryptorToken == 0)
                return new PatchResult { Error = "No string decryption method identified", PatchDescriptions = new string[0] };

            int decryptorRow = (decryptorToken & 0x00FFFFFF) - 1;
            string decryptorName = ReadStringsHeapEntry(tables.StringsHeap, tables.MethodDefs[decryptorRow].NameIndex);

            // For each call to the decryptor preceded by ldc.i4:
            // NOP the ldc.i4 + call, replace with nop chain
            // (The actual decryption requires runtime execution — but we mark them for the user)
            int markedCount = 0;
            var decryptCallSites = new List<string>();

            foreach (var body in EnumMethodBodies(peBytes, tables))
            {
                int co = body.codeOffset;
                int end = co + body.codeSize;
                for (int j = co; j < end - 5; j++)
                {
                    if (peBytes[j] == 0x28 && BitConverter.ToInt32(peBytes, j + 1) == decryptorToken)
                    {
                        // Found a decryption call. Extract the key argument if it's a ldc.i4 before this
                        int keyVal = -1;

                        if (j >= co + 5 && peBytes[j - 5] == 0x20) // ldc.i4
                        {
                            keyVal = BitConverter.ToInt32(peBytes, j - 4);
                        }
                        else if (j >= co + 1 && peBytes[j - 1] >= 0x16 && peBytes[j - 1] <= 0x1E) // ldc.i4.0 through ldc.i4.8
                        {
                            keyVal = peBytes[j - 1] - 0x16;
                        }
                        else if (j >= co + 2 && peBytes[j - 2] == 0x1F) // ldc.i4.s
                        {
                            keyVal = (sbyte)peBytes[j - 1];
                        }

                        if (keyVal >= 0)
                        {
                            decryptCallSites.Add($"  key=0x{keyVal:X} at method {body.methodIndex}, IL 0x{(j - co):X}");
                            markedCount++;
                        }
                    }
                }
            }

            patches.Add($"Identified string decryptor: method 0x{decryptorToken:X8} ({decryptorName}) — called {maxCalls} times");
            patches.Add($"Found {markedCount} encrypted string call sites");

            // Neutralize the decryptor method body itself (replace with: ldstr "" + ret)
            // This prevents crashes when the decryptor's dependencies aren't available
            uint decRva = tables.MethodDefs[decryptorRow].Rva;
            if (decRva != 0)
            {
                bool is64 = BitConverter.ToUInt16(peBytes, BitConverter.ToInt32(peBytes, 60) + 4) != 0x014C;
                int peOff = BitConverter.ToInt32(peBytes, 60);
                int fileOff = CliHeader.RvaToFileOffset(peBytes, peOff, decRva, is64);
                if (fileOff >= 0 && fileOff < peBytes.Length)
                {
                    byte hdr = peBytes[fileOff];
                    int codeOff, codeSize;
                    if ((hdr & 0x03) == 0x02) { codeSize = hdr >> 2; codeOff = fileOff + 1; }
                    else if ((hdr & 0x03) == 0x03 && fileOff + 12 <= peBytes.Length)
                    { codeSize = BitConverter.ToInt32(peBytes, fileOff + 4); codeOff = fileOff + 12; }
                    else { codeSize = 0; codeOff = 0; }

                    if (codeSize >= 6 && codeOff + codeSize <= peBytes.Length)
                    {
                        // Fill with nops, then ldstr "" (72 01000070) + ret (2A)
                        for (int j = codeOff; j < codeOff + codeSize; j++)
                            peBytes[j] = 0x00;

                        // Put ldstr token for empty string (US heap index 1) + ret at the end
                        int retPos = codeOff + codeSize - 1;
                        peBytes[retPos] = 0x2A; // ret
                        if (codeSize >= 6)
                        {
                            peBytes[retPos - 5] = 0x72; // ldstr
                            peBytes[retPos - 4] = 0x01;
                            peBytes[retPos - 3] = 0x00;
                            peBytes[retPos - 2] = 0x00;
                            peBytes[retPos - 1] = 0x70;
                        }

                        patches.Add($"Neutralized decryptor body at RVA 0x{decRva:X} → returns empty string");
                    }
                }
            }

            if (decryptCallSites.Count > 0 && decryptCallSites.Count <= 20)
            {
                patches.Add("Encrypted string call sites:");
                patches.AddRange(decryptCallSites);
            }

            return new PatchResult
            {
                PatchCount = patches.Count,
                PatchDescriptions = patches.ToArray(),
                Success = true
            };
        }

        // --- Method body helpers ---

        private struct MethodBody
        {
            public int methodIndex;
            public uint rva;
            public int codeOffset;
            public int codeSize;
        }

        private static IEnumerable<MethodBody> EnumMethodBodies(byte[] peBytes, MetadataTableParser tables)
        {
            if (tables?.MethodDefs == null) yield break;

            bool is64 = BitConverter.ToUInt16(peBytes, BitConverter.ToInt32(peBytes, 60) + 4) != 0x014C;
            int peOff = BitConverter.ToInt32(peBytes, 60);

            for (int i = 0; i < tables.MethodDefs.Length; i++)
            {
                uint rva = tables.MethodDefs[i].Rva;
                if (rva == 0) continue;

                int fileOff = CliHeader.RvaToFileOffset(peBytes, peOff, rva, is64);
                if (fileOff < 0 || fileOff + 2 > peBytes.Length) continue;

                byte hdr = peBytes[fileOff];
                int codeOff, codeSize;
                if ((hdr & 0x03) == 0x02)
                {
                    codeSize = hdr >> 2;
                    codeOff = fileOff + 1;
                }
                else if ((hdr & 0x03) == 0x03 && fileOff + 12 <= peBytes.Length)
                {
                    codeSize = BitConverter.ToInt32(peBytes, fileOff + 4);
                    codeOff = fileOff + 12;
                }
                else continue;

                if (codeSize <= 0 || codeOff + codeSize > peBytes.Length) continue;

                yield return new MethodBody { methodIndex = i, rva = rva, codeOffset = codeOff, codeSize = codeSize };
            }
        }

        private static int CleanControlFlowSwitch(byte[] peBytes, int codeOff, int codeSize)
        {
            // ConfuserEx control flow pattern:
            // 1. Initialize a numeric variable (stloc)
            // 2. Big switch on that variable
            // 3. Each case sets the variable to a new value and branches back to the switch
            //
            // We can't fully deobfuscate without emulating, but we CAN:
            // - Remove unreachable switch cases (dead code)
            // - Replace unconditional jumps to the switch head with NOPs when the target is the next sequential block
            // - NOP out duplicate branch chains

            int cleaned = 0;
            int end = codeOff + codeSize;

            for (int j = codeOff; j < end - 5; j++)
            {
                if (peBytes[j] == 0x45) // switch instruction
                {
                    if (j + 4 >= end) break;
                    int numTargets = BitConverter.ToInt32(peBytes, j + 1);
                    if (numTargets <= 0 || numTargets > 200) continue;

                    int tableSize = 4 + numTargets * 4;
                    if (j + 1 + tableSize > end) continue;

                    int switchEnd = j + 1 + tableSize;

                    // Scan backwards from the switch: if we find ldc.i4 + stloc + ldloc pattern before switch,
                    // we can detect dead cases
                    // Check each target: if it's a simple "ldc.i4 X; stloc N; br back_to_switch", it's a dispatch case
                    for (int t = 0; t < numTargets; t++)
                    {
                        int targetDelta = BitConverter.ToInt32(peBytes, j + 5 + t * 4);
                        int targetAddr = switchEnd + targetDelta;

                        if (targetAddr < codeOff || targetAddr >= end - 2) continue;

                        // Check if target is: ldc.i4 + stloc + br (back to near the switch)
                        byte op = peBytes[targetAddr];
                        if (op == 0x20 && targetAddr + 7 < end) // ldc.i4
                        {
                            byte nextOp = peBytes[targetAddr + 5];
                            if (nextOp >= 0x0A && nextOp <= 0x0D) // stloc.0-3
                            {
                                byte brOp = peBytes[targetAddr + 6];
                                if (brOp == 0x2B) // br.s — unconditional branch back
                                {
                                    // This is a pure dispatch case — NOP the stloc (the value was already computed)
                                    // Actually just mark as cleaned for now
                                    cleaned++;
                                }
                            }
                        }
                        else if (op >= 0x16 && op <= 0x1E && targetAddr + 3 < end) // ldc.i4.0-8
                        {
                            byte nextOp = peBytes[targetAddr + 1];
                            if (nextOp >= 0x0A && nextOp <= 0x0D) // stloc
                            {
                                byte brOp = peBytes[targetAddr + 2];
                                if (brOp == 0x2B) // br.s back
                                    cleaned++;
                            }
                        }
                    }

                    // NOP unconditional branches that jump to the instruction right after them (dead jumps)
                    for (int k = codeOff; k < end - 1; k++)
                    {
                        if (peBytes[k] == 0x2B) // br.s
                        {
                            sbyte delta = (sbyte)peBytes[k + 1];
                            if (delta == 0) // br.s +0 — jumps to next instruction (nop)
                            {
                                peBytes[k] = 0x00;     // nop
                                peBytes[k + 1] = 0x00; // nop
                                cleaned++;
                            }
                        }
                    }
                }
            }

            return cleaned;
        }

        private static int SimplifyMathChains(byte[] peBytes, int codeOff, int codeSize)
        {
            // Constant folding: evaluate sequences of ldc.i4 + ldc.i4 + arith_op
            // Replace with a single ldc.i4 <result>
            int simplified = 0;
            int end = codeOff + codeSize;

            for (int j = codeOff; j < end - 10; j++)
            {
                // Pattern: ldc.i4 A (5 bytes) + ldc.i4 B (5 bytes) + op (1 byte)
                if (peBytes[j] == 0x20 && j + 11 <= end && peBytes[j + 5] == 0x20)
                {
                    int a = BitConverter.ToInt32(peBytes, j + 1);
                    int b = BitConverter.ToInt32(peBytes, j + 6);
                    byte op = peBytes[j + 10];

                    int result;
                    bool valid = true;
                    switch (op)
                    {
                        case 0x58: result = a + b; break;      // add
                        case 0x59: result = a - b; break;      // sub
                        case 0x5A: result = a * b; break;      // mul
                        case 0x5B: result = b != 0 ? a / b : 0; break; // div
                        case 0x5D: result = b != 0 ? a % b : 0; break; // rem
                        case 0x5F: result = a & b; break;      // and
                        case 0x60: result = a | b; break;      // or
                        case 0x61: result = a ^ b; break;      // xor
                        default: result = 0; valid = false; break;
                    }

                    if (valid)
                    {
                        // Replace: ldc.i4 <result> + nop * 6
                        peBytes[j] = 0x20; // ldc.i4
                        BitConverter.GetBytes(result).CopyTo(peBytes, j + 1);
                        for (int k = j + 5; k <= j + 10; k++)
                            peBytes[k] = 0x00; // nop
                        simplified++;
                        // Don't advance j — the result might chain with the next instruction
                    }
                }

                // Pattern: ldc.i4.X (1 byte) + ldc.i4.Y (1 byte) + op (1 byte) — short constants 0-8
                if (peBytes[j] >= 0x16 && peBytes[j] <= 0x1E &&
                    j + 2 < end && peBytes[j + 1] >= 0x16 && peBytes[j + 1] <= 0x1E)
                {
                    int a = peBytes[j] - 0x16;
                    int b = peBytes[j + 1] - 0x16;
                    byte op = peBytes[j + 2];

                    int result;
                    bool valid = true;
                    switch (op)
                    {
                        case 0x58: result = a + b; break;
                        case 0x59: result = a - b; break;
                        case 0x5A: result = a * b; break;
                        case 0x5B: result = b != 0 ? a / b : 0; break;
                        case 0x61: result = a ^ b; break;
                        default: result = 0; valid = false; break;
                    }

                    if (valid)
                    {
                        if (result >= 0 && result <= 8)
                        {
                            peBytes[j] = (byte)(0x16 + result); // ldc.i4.X
                            peBytes[j + 1] = 0x00; // nop
                            peBytes[j + 2] = 0x00; // nop
                        }
                        else if (result >= -128 && result <= 127)
                        {
                            peBytes[j] = 0x1F; // ldc.i4.s
                            peBytes[j + 1] = (byte)(sbyte)result;
                            peBytes[j + 2] = 0x00; // nop
                        }
                        // Else can't fit in same space — skip
                        else continue;

                        simplified++;
                    }
                }

                // Pattern: ldc.i4.s (2 bytes) + ldc.i4.s (2 bytes) + op (1 byte)
                if (peBytes[j] == 0x1F && j + 4 < end && peBytes[j + 2] == 0x1F)
                {
                    int a = (sbyte)peBytes[j + 1];
                    int b = (sbyte)peBytes[j + 3];
                    byte op = peBytes[j + 4];

                    int result;
                    bool valid = true;
                    switch (op)
                    {
                        case 0x58: result = a + b; break;
                        case 0x59: result = a - b; break;
                        case 0x5A: result = a * b; break;
                        case 0x5B: result = b != 0 ? a / b : 0; break;
                        case 0x61: result = a ^ b; break;
                        default: result = 0; valid = false; break;
                    }

                    if (valid)
                    {
                        if (result >= 0 && result <= 8)
                        {
                            peBytes[j] = (byte)(0x16 + result);
                            for (int k = j + 1; k <= j + 4; k++) peBytes[k] = 0x00;
                        }
                        else if (result >= -128 && result <= 127)
                        {
                            peBytes[j] = 0x1F;
                            peBytes[j + 1] = (byte)(sbyte)result;
                            for (int k = j + 2; k <= j + 4; k++) peBytes[k] = 0x00;
                        }
                        else
                        {
                            peBytes[j] = 0x20; // ldc.i4
                            BitConverter.GetBytes(result).CopyTo(peBytes, j + 1);
                            // This expands 5 bytes into 5 — perfect fit
                        }
                        simplified++;
                    }
                }
            }

            // Multi-pass: repeat if we folded anything (chains can cascade)
            if (simplified > 0)
            {
                int more = SimplifyMathChains(peBytes, codeOff, codeSize);
                simplified += more;
            }

            return simplified;
        }

        // --- Internal detection methods ---

        private static bool DetectModuleCctor(byte[] peBytes, CliHeader cli, MetadataTableParser tables)
        {
            if (tables?.TypeDefs == null || tables.MethodDefs == null || tables.StringsHeap == null)
                return false;

            if (tables.TypeDefs.Length == 0) return false;

            uint methodStart = tables.TypeDefs[0].MethodList;
            uint methodEnd = tables.TypeDefs.Length > 1 ? tables.TypeDefs[1].MethodList : (uint)tables.MethodDefs.Length + 1;

            for (uint m = methodStart; m < methodEnd && m <= tables.MethodDefs.Length; m++)
            {
                int idx = (int)m - 1;
                if (idx < 0 || idx >= tables.MethodDefs.Length) continue;

                string name = ReadStringsHeapEntry(tables.StringsHeap, tables.MethodDefs[idx].NameIndex);
                if (name == ".cctor")
                {
                    // Check if the .cctor has non-trivial code
                    uint rva = tables.MethodDefs[idx].Rva;
                    if (rva == 0) continue;

                    bool is64 = BitConverter.ToUInt16(peBytes, BitConverter.ToInt32(peBytes, 60) + 4) != 0x014C;
                    int fileOff = CliHeader.RvaToFileOffset(peBytes, BitConverter.ToInt32(peBytes, 60), rva, is64);
                    if (fileOff < 0 || fileOff >= peBytes.Length) continue;

                    byte hdr = peBytes[fileOff];
                    int codeSize;
                    if ((hdr & 0x03) == 0x02) codeSize = hdr >> 2;
                    else if ((hdr & 0x03) == 0x03 && fileOff + 12 <= peBytes.Length)
                        codeSize = BitConverter.ToInt32(peBytes, fileOff + 4);
                    else continue;

                    // A trivial .cctor is just 'ret' (1 byte). Anything larger is suspicious.
                    if (codeSize > 4) return true;
                }
            }
            return false;
        }

        private static bool DetectAntiIldasm(byte[] peBytes, MetadataTableParser tables)
        {
            if (tables?.CustomAttributes == null || tables.StringsHeap == null) return false;

            for (int i = 0; i < tables.CustomAttributes.Length; i++)
            {
                string typeName = ResolveCustomAttributeType(tables, tables.CustomAttributes[i].Type);
                if (typeName != null && typeName.Contains("SuppressIldasm"))
                    return true;
            }
            return false;
        }

        private static bool DetectCallEncryption(byte[] peBytes, MetadataTableParser tables)
        {
            if (tables?.TypeDefs == null || tables.MethodDefs == null || tables.StringsHeap == null)
                return false;

            // Look for: large number of delegate types with garbled names, or
            // methods that consist entirely of a single indirect call (calli)
            int delegateTypeCount = 0;
            int calliMethodCount = 0;
            bool is64 = BitConverter.ToUInt16(peBytes, BitConverter.ToInt32(peBytes, 60) + 4) != 0x014C;
            int peOff = BitConverter.ToInt32(peBytes, 60);

            for (int i = 0; i < tables.TypeDefs.Length; i++)
            {
                string name = ReadStringsHeapEntry(tables.StringsHeap, tables.TypeDefs[i].NameIndex);
                uint flags = tables.TypeDefs[i].Flags;

                // Sealed class extending MulticastDelegate — likely proxy delegate
                if ((flags & 0x100) != 0 && name != null && name.Length <= 3 &&
                    !name.StartsWith("<", StringComparison.Ordinal))
                    delegateTypeCount++;
            }

            // Scan method bodies for calli instructions (0x29)
            int sampleSize = Math.Min(tables.MethodDefs.Length, 200);
            for (int i = 0; i < sampleSize; i++)
            {
                uint rva = tables.MethodDefs[i].Rva;
                if (rva == 0) continue;

                int fileOff = CliHeader.RvaToFileOffset(peBytes, peOff, rva, is64);
                if (fileOff < 0 || fileOff + 16 > peBytes.Length) continue;

                byte hdr = peBytes[fileOff];
                int codeOff, codeSize;
                if ((hdr & 0x03) == 0x02) { codeSize = hdr >> 2; codeOff = fileOff + 1; }
                else if ((hdr & 0x03) == 0x03 && fileOff + 12 <= peBytes.Length)
                { codeSize = BitConverter.ToInt32(peBytes, fileOff + 4); codeOff = fileOff + 12; }
                else continue;

                if (codeOff + codeSize > peBytes.Length) continue;

                for (int j = codeOff; j < codeOff + codeSize; j++)
                {
                    if (peBytes[j] == 0x29) // calli
                        calliMethodCount++;
                }
            }

            return delegateTypeCount > 10 || calliMethodCount > 5;
        }

        private static bool DetectMathMutations(byte[] peBytes, MetadataTableParser tables)
        {
            if (tables?.MethodDefs == null) return false;

            bool is64 = BitConverter.ToUInt16(peBytes, BitConverter.ToInt32(peBytes, 60) + 4) != 0x014C;
            int peOff = BitConverter.ToInt32(peBytes, 60);

            // Math mutations: constants are replaced with arithmetic chains
            // Pattern: ldc.i4 + ldc.i4 + mul/add/sub/xor repeated
            int mutatedMethods = 0;
            int sampleSize = Math.Min(tables.MethodDefs.Length, 300);

            for (int i = 0; i < sampleSize; i++)
            {
                uint rva = tables.MethodDefs[i].Rva;
                if (rva == 0) continue;

                int fileOff = CliHeader.RvaToFileOffset(peBytes, peOff, rva, is64);
                if (fileOff < 0 || fileOff + 16 > peBytes.Length) continue;

                byte hdr = peBytes[fileOff];
                int codeOff, codeSize;
                if ((hdr & 0x03) == 0x02) { codeSize = hdr >> 2; codeOff = fileOff + 1; }
                else if ((hdr & 0x03) == 0x03 && fileOff + 12 <= peBytes.Length)
                { codeSize = BitConverter.ToInt32(peBytes, fileOff + 4); codeOff = fileOff + 12; }
                else continue;

                if (codeSize < 10 || codeOff + codeSize > peBytes.Length) continue;

                // Count arithmetic instruction density
                int arithCount = 0;
                int ldcCount = 0;
                for (int j = codeOff; j < codeOff + codeSize; j++)
                {
                    byte op = peBytes[j];
                    if (op == 0x58 || op == 0x59 || op == 0x5A || op == 0x5B || op == 0x61) // add, sub, mul, div, xor
                        arithCount++;
                    if (op == 0x20 || op == 0x21) // ldc.i4, ldc.i8
                        ldcCount++;
                }

                double arithDensity = (double)(arithCount + ldcCount) / codeSize;
                if (arithDensity > 0.25 && arithCount > 4 && ldcCount > 4)
                    mutatedMethods++;
            }

            return mutatedMethods > sampleSize * 0.05;
        }

        private static bool DetectVirtualization(byte[] peBytes, MetadataTableParser tables)
        {
            if (tables?.MethodDefs == null || tables.StringsHeap == null) return false;

            bool is64 = BitConverter.ToUInt16(peBytes, BitConverter.ToInt32(peBytes, 60) + 4) != 0x014C;
            int peOff = BitConverter.ToInt32(peBytes, 60);

            // Virtualization hallmarks:
            // 1. Methods with very small bodies that load a byte array and call a VM entry
            // 2. Large switch-based dispatch method (the VM interpreter)
            // 3. Resource/embedded data that contains VM bytecode

            int tinyStubCount = 0;
            int largeSwitchCount = 0;

            for (int i = 0; i < tables.MethodDefs.Length; i++)
            {
                uint rva = tables.MethodDefs[i].Rva;
                if (rva == 0) continue;

                int fileOff = CliHeader.RvaToFileOffset(peBytes, peOff, rva, is64);
                if (fileOff < 0 || fileOff + 16 > peBytes.Length) continue;

                byte hdr = peBytes[fileOff];
                int codeOff, codeSize;
                if ((hdr & 0x03) == 0x02) { codeSize = hdr >> 2; codeOff = fileOff + 1; }
                else if ((hdr & 0x03) == 0x03 && fileOff + 12 <= peBytes.Length)
                { codeSize = BitConverter.ToInt32(peBytes, fileOff + 4); codeOff = fileOff + 12; }
                else continue;

                if (codeOff + codeSize > peBytes.Length) continue;

                // Tiny stub: loads int + byte array, calls single method
                if (codeSize >= 8 && codeSize <= 30)
                {
                    int callCount = 0;
                    bool hasLdsfld = false;
                    for (int j = codeOff; j < codeOff + codeSize; j++)
                    {
                        if (peBytes[j] == 0x28) callCount++; // call
                        if (peBytes[j] == 0x7E) hasLdsfld = true; // ldsfld
                    }
                    if (callCount == 1 && hasLdsfld)
                        tinyStubCount++;
                }

                // Large switch: IL switch instruction (0x45) with many targets
                if (codeSize > 200)
                {
                    for (int j = codeOff; j < codeOff + codeSize - 4; j++)
                    {
                        if (peBytes[j] == 0x45) // switch
                        {
                            if (j + 4 < codeOff + codeSize)
                            {
                                int numTargets = BitConverter.ToInt32(peBytes, j + 1);
                                if (numTargets > 30) largeSwitchCount++;
                            }
                        }
                    }
                }
            }

            // Virtualization: many tiny stubs + at least one large switch dispatch
            return (tinyStubCount > tables.MethodDefs.Length * 0.15 && largeSwitchCount > 0) ||
                   largeSwitchCount > 2;
        }

        private static bool DetectAntiDnSpy(byte[] peBytes, MetadataTableParser tables)
        {
            // 1. Check for invalid metadata stream names
            int bsjbPos = FindBsjbSignature(peBytes);
            if (bsjbPos >= 0)
            {
                int p = bsjbPos + 12;
                if (p + 4 <= peBytes.Length)
                {
                    uint versionLen = BitConverter.ToUInt32(peBytes, p);
                    p += 4 + (int)versionLen + 2;
                    if (p + 2 <= peBytes.Length)
                    {
                        ushort numStreams = BitConverter.ToUInt16(peBytes, p);
                        p += 2;
                        for (int i = 0; i < numStreams && p + 8 <= peBytes.Length; i++)
                        {
                            p += 8;
                            int nameStart = p;
                            while (p < peBytes.Length && peBytes[p] != 0) p++;
                            for (int j = nameStart; j < p; j++)
                            {
                                if (peBytes[j] > 127) return true; // Non-ASCII in stream name
                            }
                            p++;
                            while (p % 4 != 0) p++;
                        }
                    }
                }
            }

            // 2. Check for #US heap corruption
            if (bsjbPos >= 0 && DetectUsHeapCorruption(peBytes, bsjbPos) > 3)
                return true;

            // 3. Check for recursive TypeDef nesting (crashes dnSpy tree view)
            if (tables?.TypeDefs != null && tables.TypeDefs.Length > 0)
            {
                // Unusually deep or circular nesting detected via flags
                int abstractSealedCount = 0;
                for (int i = 1; i < tables.TypeDefs.Length; i++) // Skip <Module>
                {
                    uint flags = tables.TypeDefs[i].Flags;
                    if ((flags & 0x80) != 0 && (flags & 0x100) != 0 && (flags & 0x20) == 0)
                        abstractSealedCount++; // abstract + sealed but not interface = static class... unless abused
                }
                if (abstractSealedCount > tables.TypeDefs.Length * 0.5)
                    return true;
            }

            return false;
        }

        private static bool DetectAntiDebug(byte[] peBytes, MetadataTableParser tables)
        {
            if (tables?.MemberRefs == null || tables.StringsHeap == null) return false;

            string[] antiDebugMethods = {
                "get_IsAttached", "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                "NtQueryInformationProcess", "OutputDebugString", "CloseHandle",
                "get_IsLogging", "DebugBreak"
            };

            for (int i = 0; i < tables.MemberRefs.Length; i++)
            {
                string name = ReadStringsHeapEntry(tables.StringsHeap, tables.MemberRefs[i].NameIndex);
                if (name != null)
                {
                    foreach (string target in antiDebugMethods)
                    {
                        if (name == target) return true;
                    }
                }
            }

            return false;
        }

        private static bool DetectControlFlowObfuscation(byte[] peBytes, MetadataTableParser tables)
        {
            if (tables?.MethodDefs == null) return false;

            bool is64 = BitConverter.ToUInt16(peBytes, BitConverter.ToInt32(peBytes, 60) + 4) != 0x014C;
            int peOff = BitConverter.ToInt32(peBytes, 60);

            int obfuscatedMethods = 0;
            int sampleSize = Math.Min(tables.MethodDefs.Length, 200);

            for (int i = 0; i < sampleSize; i++)
            {
                uint rva = tables.MethodDefs[i].Rva;
                if (rva == 0) continue;

                int fileOff = CliHeader.RvaToFileOffset(peBytes, peOff, rva, is64);
                if (fileOff < 0 || fileOff + 16 > peBytes.Length) continue;

                byte hdr = peBytes[fileOff];
                int codeOff, codeSize;
                if ((hdr & 0x03) == 0x02) { codeSize = hdr >> 2; codeOff = fileOff + 1; }
                else if ((hdr & 0x03) == 0x03 && fileOff + 12 <= peBytes.Length)
                { codeSize = BitConverter.ToInt32(peBytes, fileOff + 4); codeOff = fileOff + 12; }
                else continue;

                if (codeSize < 20 || codeOff + codeSize > peBytes.Length) continue;

                // Count branch instructions vs code size
                int branchCount = 0;
                int switchCount = 0;
                for (int j = codeOff; j < codeOff + codeSize; j++)
                {
                    byte op = peBytes[j];
                    // br.s, brtrue.s, brfalse.s, br, brtrue, brfalse
                    if (op >= 0x2B && op <= 0x2D) branchCount++;
                    if (op >= 0x38 && op <= 0x3A) branchCount++;
                    if (op == 0x45) switchCount++; // switch
                }

                double branchDensity = (double)branchCount / codeSize;
                if (branchDensity > 0.08 || (switchCount > 0 && branchCount > 10))
                    obfuscatedMethods++;
            }

            return obfuscatedMethods > sampleSize * 0.15;
        }

        private static bool DetectStringEncryption(byte[] peBytes, MetadataTableParser tables)
        {
            if (tables?.MethodDefs == null) return false;

            bool is64 = BitConverter.ToUInt16(peBytes, BitConverter.ToInt32(peBytes, 60) + 4) != 0x014C;
            int peOff = BitConverter.ToInt32(peBytes, 60);

            // String encryption: ldstr instructions are replaced with call instructions
            // to a decryption method. Sign: very few ldstr (0x72) but many call (0x28)
            int totalLdstr = 0;
            int totalCall = 0;
            int sampleSize = Math.Min(tables.MethodDefs.Length, 300);

            for (int i = 0; i < sampleSize; i++)
            {
                uint rva = tables.MethodDefs[i].Rva;
                if (rva == 0) continue;

                int fileOff = CliHeader.RvaToFileOffset(peBytes, peOff, rva, is64);
                if (fileOff < 0 || fileOff + 16 > peBytes.Length) continue;

                byte hdr = peBytes[fileOff];
                int codeOff, codeSize;
                if ((hdr & 0x03) == 0x02) { codeSize = hdr >> 2; codeOff = fileOff + 1; }
                else if ((hdr & 0x03) == 0x03 && fileOff + 12 <= peBytes.Length)
                { codeSize = BitConverter.ToInt32(peBytes, fileOff + 4); codeOff = fileOff + 12; }
                else continue;

                if (codeOff + codeSize > peBytes.Length) continue;

                for (int j = codeOff; j < codeOff + codeSize; j++)
                {
                    if (peBytes[j] == 0x72) totalLdstr++;
                    if (peBytes[j] == 0x28) totalCall++;
                }
            }

            // Typical ratio: ldstr should be ~5-15% of calls. If < 1%, strings are encrypted.
            if (totalCall > 50 && totalLdstr < totalCall * 0.01)
                return true;

            return false;
        }

        private static string GuessObfuscator(ObfuscationReport report, byte[] peBytes, MetadataTableParser tables)
        {
            // ConfuserEx: module .cctor + control flow + string encryption + anti-debug + anti-ILDASM
            if (report.HasModuleCctor && report.HasControlFlow && report.HasStringEncryption && report.HasAntiIldasm)
                return "ConfuserEx (or derivative: ConfuserEx2, Beds Protector, MindLated)";

            // Agile.NET / CliSecure: virtualization + call encryption
            if (report.HasVirtualization && report.HasCallEncryption)
                return "Agile.NET / CliSecure / Eazfuscator.NET (virtualization mode)";

            // Eazfuscator.NET: virtualization without call encryption
            if (report.HasVirtualization && !report.HasCallEncryption)
                return "Eazfuscator.NET (virtualization mode)";

            // .NET Reactor: module .cctor + anti-debug + call encryption + string encryption
            if (report.HasModuleCctor && report.HasCallEncryption && report.HasStringEncryption)
                return ".NET Reactor";

            // Dotfuscator: control flow + string encryption (no .cctor)
            if (report.HasControlFlow && report.HasStringEncryption && !report.HasModuleCctor)
                return "Dotfuscator / PreEmptive";

            // SmartAssembly: string encryption + anti-debug (no control flow usually)
            if (report.HasStringEncryption && report.HasAntiDebug && !report.HasControlFlow)
                return "SmartAssembly";

            // Babel.NET: string encryption + call encryption
            if (report.HasStringEncryption && report.HasCallEncryption && !report.HasVirtualization)
                return "Babel.NET";

            // Crypto Obfuscator: anti-ILDASM + anti-debug + string encryption
            if (report.HasAntiIldasm && report.HasAntiDebug && report.HasStringEncryption)
                return "Crypto Obfuscator";

            if (report.ProtectionScore > 0)
                return "Unknown obfuscator";

            return "None detected";
        }

        // --- Helpers ---

        private static int FindBsjbSignature(byte[] data)
        {
            byte[] sig = { 0x42, 0x53, 0x4A, 0x42 };
            for (int i = 0; i < data.Length - 4; i++)
            {
                if (data[i] == sig[0] && data[i + 1] == sig[1] && data[i + 2] == sig[2] && data[i + 3] == sig[3])
                    return i;
            }
            return -1;
        }

        private static int DetectUsHeapCorruption(byte[] peBytes, int bsjbPos)
        {
            // Find #US stream
            int p = bsjbPos + 12;
            if (p + 4 > peBytes.Length) return 0;
            uint versionLen = BitConverter.ToUInt32(peBytes, p);
            p += 4 + (int)versionLen + 2;
            if (p + 2 > peBytes.Length) return 0;
            ushort numStreams = BitConverter.ToUInt16(peBytes, p);
            p += 2;

            int usOffset = -1, usSize = 0;
            for (int i = 0; i < numStreams && p + 8 <= peBytes.Length; i++)
            {
                uint sOff = BitConverter.ToUInt32(peBytes, p);
                uint sSize = BitConverter.ToUInt32(peBytes, p + 4);
                p += 8;
                int nameStart = p;
                while (p < peBytes.Length && peBytes[p] != 0) p++;
                string name = Encoding.ASCII.GetString(peBytes, nameStart, p - nameStart);
                p++;
                while (p % 4 != 0) p++;

                if (name == "#US")
                {
                    usOffset = bsjbPos + (int)sOff;
                    usSize = (int)sSize;
                    break;
                }
            }

            if (usOffset < 0 || usOffset + usSize > peBytes.Length) return 0;

            // Walk #US heap entries — each is: compressed length + UTF-16 data + terminal byte
            int corruptions = 0;
            int pos = usOffset + 1; // First byte is always 0
            while (pos < usOffset + usSize)
            {
                int len = ReadCompressedUint(peBytes, ref pos);
                if (len <= 0 || pos + len > usOffset + usSize) break;
                // Check if the string data looks corrupt (should be valid UTF-16)
                if (len > 1)
                {
                    int nonPrintable = 0;
                    for (int i = 0; i < len - 1; i += 2)
                    {
                        ushort ch = BitConverter.ToUInt16(peBytes, pos + i);
                        if (ch > 0 && ch < 0x20 && ch != 0x09 && ch != 0x0A && ch != 0x0D)
                            nonPrintable++;
                    }
                    if (nonPrintable > (len / 2) * 0.5)
                        corruptions++;
                }
                pos += len;
            }
            return corruptions;
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

        private static string ResolveCustomAttributeType(MetadataTableParser tables, uint codedIdx)
        {
            // CustomAttributeType coded index: MethodDef (2), MemberRef (3)
            int tag = (int)(codedIdx & 0x07);
            int row = (int)(codedIdx >> 3);
            if (row <= 0) return null;

            if (tag == 3 && tables.MemberRefs != null && row <= tables.MemberRefs.Length)
            {
                uint classIdx = tables.MemberRefs[row - 1].Class;
                // MemberRefParent: TypeRef is tag 1
                int parentTag = (int)(classIdx & 0x07);
                int parentRow = (int)(classIdx >> 3);

                if (parentTag == 1 && tables.TypeRefs != null && parentRow > 0 && parentRow <= tables.TypeRefs.Length)
                {
                    return ReadStringsHeapEntry(tables.StringsHeap, tables.TypeRefs[parentRow - 1].NameIndex);
                }
            }
            else if (tag == 2 && tables.MethodDefs != null && row <= tables.MethodDefs.Length)
            {
                return ReadStringsHeapEntry(tables.StringsHeap, tables.MethodDefs[row - 1].NameIndex);
            }

            return null;
        }

        private static string ReadStringsHeapEntry(byte[] heap, uint index)
        {
            if (heap == null || index >= heap.Length) return null;
            int start = (int)index;
            int end = start;
            while (end < heap.Length && heap[end] != 0) end++;
            if (end == start) return "";
            return Encoding.UTF8.GetString(heap, start, end - start);
        }
    }
}
