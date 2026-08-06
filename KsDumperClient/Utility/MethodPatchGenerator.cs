using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using KsDumperClient.Driver;

namespace KsDumperClient.Utility
{
    public static class MethodPatchGenerator
    {
        public class PatchTemplate
        {
            public string Name;
            public string Description;
            public ulong Address;
            public int OriginalSize;
            public byte[] OriginalBytes;
            public byte[] PatchBytes;
            public string CEScript;
            public string FridaScript;
            public string RawHex;
        }

        public class PatchResult
        {
            public ulong MethodAddress;
            public string MethodName;
            public int MethodSize;
            public List<PatchTemplate> Templates = new List<PatchTemplate>();
        }

        public static PatchResult GeneratePatches(
            IMemoryReader driver, int pid,
            ulong methodAddress, string methodName = null,
            string moduleName = "GameAssembly.dll",
            int maxRead = 256)
        {
            var result = new PatchResult
            {
                MethodAddress = methodAddress,
                MethodName = methodName ?? $"sub_{methodAddress:X}"
            };

            byte[] code = ReadMemory(driver, pid, methodAddress, maxRead);
            if (code == null) return result;

            // Find method size (scan for ret or int3 sequence)
            int methodSize = maxRead;
            for (int i = 1; i < code.Length; i++)
            {
                if (code[i] == 0xC3 || (code[i] == 0xCC && i > 4))
                {
                    methodSize = i + 1;
                    break;
                }
            }
            result.MethodSize = methodSize;

            // 1. NOP entire method (keeps ret at end)
            result.Templates.Add(GenerateNopPatch(methodAddress, code, methodSize, moduleName));

            // 2. Return true (xor eax,eax; inc eax; ret = mov eax,1; ret)
            result.Templates.Add(GenerateReturnValuePatch(methodAddress, code, methodSize, moduleName, 1, "Return True (1)"));

            // 3. Return false (xor eax,eax; ret)
            result.Templates.Add(GenerateReturnValuePatch(methodAddress, code, methodSize, moduleName, 0, "Return False (0)"));

            // 4. Return custom int
            result.Templates.Add(GenerateReturnIntPatch(methodAddress, code, methodSize, moduleName, 999, "Return Custom Int (999)"));

            // 5. Return max float (for infinite health/ammo patterns)
            result.Templates.Add(GenerateReturnFloatPatch(methodAddress, code, methodSize, moduleName));

            // 6. Skip first conditional jump (force always/never taken)
            var jmpPatch = GenerateSkipJumpPatch(code, methodAddress, methodSize, moduleName);
            if (jmpPatch != null)
                result.Templates.Add(jmpPatch);

            // 7. Redirect to another method
            result.Templates.Add(GenerateRedirectPatch(methodAddress, code, moduleName));

            return result;
        }

        private static PatchTemplate GenerateNopPatch(ulong addr, byte[] code, int size, string moduleName)
        {
            int nopCount = size - 1; // Keep final ret
            byte[] original = new byte[nopCount];
            Buffer.BlockCopy(code, 0, original, 0, nopCount);

            byte[] patch = new byte[nopCount];
            for (int i = 0; i < nopCount; i++) patch[i] = 0x90;

            return new PatchTemplate
            {
                Name = "NOP Method",
                Description = $"NOP out {nopCount} bytes, keeping ret at end",
                Address = addr,
                OriginalSize = nopCount,
                OriginalBytes = original,
                PatchBytes = patch,
                RawHex = BytesToHex(patch),
                CEScript = GenerateCEScript(addr, patch, original, moduleName, "NOP Method"),
                FridaScript = GenerateFridaMemWrite(addr, patch, moduleName, "NOP Method")
            };
        }

        private static PatchTemplate GenerateReturnValuePatch(ulong addr, byte[] code, int size, string moduleName, int value, string name)
        {
            byte[] patch;
            if (value == 0)
            {
                // xor eax, eax; ret
                patch = new byte[] { 0x31, 0xC0, 0xC3 };
            }
            else if (value == 1)
            {
                // xor eax, eax; inc eax; ret (or mov eax, 1; ret)
                patch = new byte[] { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 };
            }
            else
            {
                // mov eax, value; ret
                byte[] valBytes = BitConverter.GetBytes(value);
                patch = new byte[] { 0xB8, valBytes[0], valBytes[1], valBytes[2], valBytes[3], 0xC3 };
            }

            int patchLen = patch.Length;
            byte[] original = new byte[patchLen];
            Buffer.BlockCopy(code, 0, original, 0, Math.Min(patchLen, code.Length));

            return new PatchTemplate
            {
                Name = name,
                Description = $"Overwrite method start with mov eax,{value}; ret",
                Address = addr,
                OriginalSize = patchLen,
                OriginalBytes = original,
                PatchBytes = patch,
                RawHex = BytesToHex(patch),
                CEScript = GenerateCEScript(addr, patch, original, moduleName, name),
                FridaScript = GenerateFridaMemWrite(addr, patch, moduleName, name)
            };
        }

        private static PatchTemplate GenerateReturnIntPatch(ulong addr, byte[] code, int size, string moduleName, int value, string name)
        {
            return GenerateReturnValuePatch(addr, code, size, moduleName, value, name);
        }

        private static PatchTemplate GenerateReturnFloatPatch(ulong addr, byte[] code, int size, string moduleName)
        {
            // For SSE: push float_value; movss xmm0, [rsp]; add rsp, 8; ret
            // Simpler: mov eax, float_bits; movd xmm0, eax; ret
            float maxFloat = 999999f;
            byte[] floatBytes = BitConverter.GetBytes(maxFloat);

            byte[] patch = new byte[]
            {
                0xB8, floatBytes[0], floatBytes[1], floatBytes[2], floatBytes[3], // mov eax, float_bits
                0x66, 0x0F, 0x6E, 0xC0, // movd xmm0, eax
                0xC3 // ret
            };

            int patchLen = patch.Length;
            byte[] original = new byte[patchLen];
            Buffer.BlockCopy(code, 0, original, 0, Math.Min(patchLen, code.Length));

            return new PatchTemplate
            {
                Name = "Return Max Float",
                Description = $"Returns {maxFloat}f via xmm0 (mov eax,float; movd xmm0,eax; ret)",
                Address = addr,
                OriginalSize = patchLen,
                OriginalBytes = original,
                PatchBytes = patch,
                RawHex = BytesToHex(patch),
                CEScript = GenerateCEScript(addr, patch, original, moduleName, "Return Max Float"),
                FridaScript = GenerateFridaMemWrite(addr, patch, moduleName, "Return Max Float")
            };
        }

        private static PatchTemplate GenerateSkipJumpPatch(byte[] code, ulong addr, int size, string moduleName)
        {
            // Find first conditional jump
            for (int i = 0; i < Math.Min(size, code.Length) - 2; i++)
            {
                byte op = code[i];

                // Short Jcc: 70-7F rel8
                if (op >= 0x70 && op <= 0x7F)
                {
                    byte[] original = { code[i], code[i + 1] };
                    byte[] nopPatch = { 0x90, 0x90 }; // NOP out = never taken
                    byte[] jmpPatch = { 0xEB, code[i + 1] }; // JMP short = always taken

                    string jccName = GetJccName(op - 0x70);
                    return new PatchTemplate
                    {
                        Name = $"Skip {jccName} (NOP)",
                        Description = $"NOP out first conditional jump ({jccName} at +0x{i:X}), making it never taken. Change to EB for always taken.",
                        Address = addr + (ulong)i,
                        OriginalSize = 2,
                        OriginalBytes = original,
                        PatchBytes = nopPatch,
                        RawHex = $"NOP: {BytesToHex(nopPatch)} / JMP: {BytesToHex(jmpPatch)}",
                        CEScript = GenerateCEScript(addr + (ulong)i, nopPatch, original, moduleName, $"Skip {jccName}"),
                        FridaScript = GenerateFridaMemWrite(addr + (ulong)i, nopPatch, moduleName, $"Skip {jccName}")
                    };
                }

                // Near Jcc: 0F 80-8F rel32
                if (op == 0x0F && i + 5 < code.Length && (code[i + 1] & 0xF0) == 0x80)
                {
                    byte[] original = new byte[6];
                    Buffer.BlockCopy(code, i, original, 0, 6);
                    byte[] nopPatch = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };

                    string jccName = GetJccName(code[i + 1] - 0x80);
                    return new PatchTemplate
                    {
                        Name = $"Skip {jccName} (NOP)",
                        Description = $"NOP out first near conditional jump ({jccName} at +0x{i:X})",
                        Address = addr + (ulong)i,
                        OriginalSize = 6,
                        OriginalBytes = original,
                        PatchBytes = nopPatch,
                        RawHex = BytesToHex(nopPatch),
                        CEScript = GenerateCEScript(addr + (ulong)i, nopPatch, original, moduleName, $"Skip {jccName}"),
                        FridaScript = GenerateFridaMemWrite(addr + (ulong)i, nopPatch, moduleName, $"Skip {jccName}")
                    };
                }
            }

            return null;
        }

        private static PatchTemplate GenerateRedirectPatch(ulong addr, byte[] code, string moduleName)
        {
            // JMP rel32 to a placeholder target
            byte[] patch = new byte[] { 0xE9, 0x00, 0x00, 0x00, 0x00 }; // JMP +0 (placeholder)
            byte[] original = new byte[5];
            Buffer.BlockCopy(code, 0, original, 0, Math.Min(5, code.Length));

            return new PatchTemplate
            {
                Name = "Redirect (Template)",
                Description = "JMP rel32 to another address. Replace bytes 1-4 with (target - (addr + 5)) as little-endian int32.",
                Address = addr,
                OriginalSize = 5,
                OriginalBytes = original,
                PatchBytes = patch,
                RawHex = "E9 ?? ?? ?? ?? (calculate: target_addr - (this_addr + 5))",
                CEScript = $"// Redirect {moduleName}+0x{addr:X}\n// Calculate offset: target - (0x{addr:X} + 5)\n// jmp target",
                FridaScript = GenerateFridaRedirect(addr, moduleName)
            };
        }

        private static string GenerateCEScript(ulong addr, byte[] patch, byte[] original, string moduleName, string name)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"// {name}");
            sb.AppendLine("[ENABLE]");
            sb.AppendLine($"// {moduleName}+{addr:X}");

            sb.Append($"{moduleName}+{addr:X}:");
            sb.AppendLine();
            sb.Append("db ");
            sb.AppendLine(string.Join(" ", patch.Select(b => b.ToString("X2"))));

            sb.AppendLine();
            sb.AppendLine("[DISABLE]");
            sb.Append($"{moduleName}+{addr:X}:");
            sb.AppendLine();
            sb.Append("db ");
            sb.AppendLine(string.Join(" ", original.Select(b => b.ToString("X2"))));

            return sb.ToString();
        }

        private static string GenerateFridaMemWrite(ulong addr, byte[] patch, string moduleName, string name)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"// {name}");
            sb.AppendLine($"var base = Module.findBaseAddress('{moduleName}');");
            sb.AppendLine($"var addr = base.add(0x{addr:X});");
            sb.AppendLine("Memory.protect(addr, {0}, 'rwx');".Replace("{0}", patch.Length.ToString()));
            sb.Append("addr.writeByteArray([");
            sb.Append(string.Join(", ", patch.Select(b => $"0x{b:X2}")));
            sb.AppendLine("]);");

            return sb.ToString();
        }

        private static string GenerateFridaRedirect(ulong addr, string moduleName)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// Redirect method to custom implementation");
            sb.AppendLine($"var base = Module.findBaseAddress('{moduleName}');");
            sb.AppendLine($"var target = base.add(0x{addr:X});");
            sb.AppendLine("Interceptor.replace(target, new NativeCallback(function() {");
            sb.AppendLine("  // Custom implementation here");
            sb.AppendLine("  return 1; // return value");
            sb.AppendLine("}, 'int', []));");

            return sb.ToString();
        }

        private static string GetJccName(int code)
        {
            string[] names = { "JO", "JNO", "JB", "JNB", "JE", "JNE", "JBE", "JA",
                               "JS", "JNS", "JP", "JNP", "JL", "JGE", "JLE", "JG" };
            if (code >= 0 && code < names.Length) return names[code];
            return $"Jcc_{code:X}";
        }

        private static string BytesToHex(byte[] bytes)
        {
            return string.Join(" ", bytes.Select(b => b.ToString("X2")));
        }

        public static string GenerateReport(PatchResult result)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - Method Patch Template Generator");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"// Method: {result.MethodName}");
            sb.AppendLine($"// Address: 0x{result.MethodAddress:X16}");
            sb.AppendLine($"// Size: {result.MethodSize} bytes");
            sb.AppendLine($"// Templates: {result.Templates.Count}");
            sb.AppendLine();

            foreach (var tmpl in result.Templates)
            {
                sb.AppendLine($"=== {tmpl.Name} ===");
                sb.AppendLine($"  {tmpl.Description}");
                sb.AppendLine($"  Original: {BytesToHex(tmpl.OriginalBytes)}");
                sb.AppendLine($"  Patch:    {tmpl.RawHex}");
                sb.AppendLine();
                sb.AppendLine("  -- CE Auto Assembler --");
                sb.AppendLine(tmpl.CEScript);
                sb.AppendLine("  -- Frida --");
                sb.AppendLine(tmpl.FridaScript);
                sb.AppendLine();
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
