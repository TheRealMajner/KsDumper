using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using KsDumperClient.Driver;

namespace KsDumperClient.Utility
{
    public static class Il2CppNativeDisassembler
    {
        public class NativeInstruction
        {
            public ulong Address;
            public int Size;
            public byte[] Bytes;
            public string Mnemonic;
            public string Operands;
        }

        public class DisassemblyResult
        {
            public ulong StartAddress;
            public int TotalBytes;
            public List<NativeInstruction> Instructions = new List<NativeInstruction>();
            public List<ulong> CallTargets = new List<ulong>();
            public List<ulong> JumpTargets = new List<ulong>();
            public bool IsThunk; // short method that just jumps elsewhere
        }

        // x86-64 opcode prefix bytes
        private static readonly HashSet<byte> Prefixes = new HashSet<byte>
        {
            0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF0, 0xF2, 0xF3
        };

        public static DisassemblyResult DisassembleMethod(
            IMemoryReader driver, int pid,
            ulong methodAddress, int maxBytes = 512)
        {
            var result = new DisassemblyResult { StartAddress = methodAddress };

            byte[] code = ReadMemory(driver, pid, methodAddress, maxBytes);
            if (code == null) return result;

            result.TotalBytes = code.Length;
            int offset = 0;

            while (offset < code.Length && result.Instructions.Count < 200)
            {
                var instr = DecodeInstruction(code, offset, methodAddress + (ulong)offset);
                if (instr == null) break;

                result.Instructions.Add(instr);

                // Track call/jump targets
                if (instr.Mnemonic == "call" && instr.Operands.StartsWith("0x"))
                {
                    if (ulong.TryParse(instr.Operands.Substring(2), System.Globalization.NumberStyles.HexNumber, null, out ulong target))
                        result.CallTargets.Add(target);
                }
                else if ((instr.Mnemonic == "jmp" || instr.Mnemonic.StartsWith("j")) && instr.Operands.StartsWith("0x"))
                {
                    if (ulong.TryParse(instr.Operands.Substring(2), System.Globalization.NumberStyles.HexNumber, null, out ulong target))
                        result.JumpTargets.Add(target);
                }

                // Stop at return
                if (instr.Mnemonic == "ret" || instr.Mnemonic == "int3")
                {
                    // Check if this is a thunk (very short)
                    if (result.Instructions.Count <= 3 && result.CallTargets.Count == 0 && result.JumpTargets.Count > 0)
                        result.IsThunk = true;
                    break;
                }

                offset += instr.Size;
            }

            return result;
        }

        public static string FormatDisassembly(DisassemblyResult result, string methodName = null)
        {
            var sb = new StringBuilder();
            if (methodName != null)
                sb.AppendLine($"// {methodName}");
            sb.AppendLine($"// Address: 0x{result.StartAddress:X16}");
            if (result.IsThunk)
                sb.AppendLine("// [THUNK - redirects to another function]");
            sb.AppendLine();

            foreach (var instr in result.Instructions)
            {
                string bytes = BitConverter.ToString(instr.Bytes).Replace("-", " ");
                string operands = string.IsNullOrEmpty(instr.Operands) ? "" : " " + instr.Operands;
                sb.AppendLine($"  0x{instr.Address:X}: {bytes,-24} {instr.Mnemonic}{operands}");
            }

            if (result.CallTargets.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("// Call targets:");
                foreach (var t in result.CallTargets.Distinct())
                    sb.AppendLine($"//   0x{t:X16}");
            }

            return sb.ToString();
        }

        public static string DisassembleMultipleMethods(
            IMemoryReader driver, int pid,
            Dictionary<string, ulong> methodAddresses,
            int maxMethods = 100)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - IL2CPP Native Disassembly");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"// Methods: {Math.Min(methodAddresses.Count, maxMethods)}");
            sb.AppendLine();

            int count = 0;
            foreach (var kvp in methodAddresses)
            {
                if (count >= maxMethods) break;
                if (kvp.Value == 0) continue;

                var result = DisassembleMethod(driver, pid, kvp.Value);
                sb.AppendLine(FormatDisassembly(result, kvp.Key));
                sb.AppendLine();
                count++;
            }

            return sb.ToString();
        }

        // ===== x86-64 Decoder (lightweight, covers common instructions) =====

        private static NativeInstruction DecodeInstruction(byte[] code, int offset, ulong address)
        {
            if (offset >= code.Length) return null;

            int start = offset;
            var instr = new NativeInstruction { Address = address };

            // Skip prefixes
            bool hasRex = false;
            byte rex = 0;
            bool has66 = false;
            bool hasF2 = false;
            bool hasF3 = false;

            while (offset < code.Length && Prefixes.Contains(code[offset]))
            {
                if (code[offset] == 0x66) has66 = true;
                if (code[offset] == 0xF2) hasF2 = true;
                if (code[offset] == 0xF3) hasF3 = true;
                offset++;
            }

            // REX prefix
            if (offset < code.Length && (code[offset] & 0xF0) == 0x40)
            {
                hasRex = true;
                rex = code[offset];
                offset++;
            }

            if (offset >= code.Length)
            {
                instr.Mnemonic = "db";
                instr.Size = offset - start;
                instr.Bytes = CopyBytes(code, start, instr.Size);
                return instr;
            }

            byte op = code[offset++];
            bool rexW = hasRex && (rex & 0x08) != 0;

            switch (op)
            {
                // NOP
                case 0x90:
                    instr.Mnemonic = "nop";
                    break;

                // RET
                case 0xC3:
                    instr.Mnemonic = "ret";
                    break;
                case 0xC2:
                    instr.Mnemonic = "ret";
                    if (offset + 2 <= code.Length)
                    {
                        ushort imm = BitConverter.ToUInt16(code, offset);
                        instr.Operands = $"0x{imm:X}";
                        offset += 2;
                    }
                    break;

                // INT3
                case 0xCC:
                    instr.Mnemonic = "int3";
                    break;

                // PUSH r64
                case 0x50: case 0x51: case 0x52: case 0x53:
                case 0x54: case 0x55: case 0x56: case 0x57:
                    instr.Mnemonic = "push";
                    instr.Operands = GetReg64(op - 0x50, hasRex && (rex & 0x01) != 0);
                    break;

                // POP r64
                case 0x58: case 0x59: case 0x5A: case 0x5B:
                case 0x5C: case 0x5D: case 0x5E: case 0x5F:
                    instr.Mnemonic = "pop";
                    instr.Operands = GetReg64(op - 0x58, hasRex && (rex & 0x01) != 0);
                    break;

                // MOV r64, imm64
                case 0xB8: case 0xB9: case 0xBA: case 0xBB:
                case 0xBC: case 0xBD: case 0xBE: case 0xBF:
                    instr.Mnemonic = "mov";
                    string reg = rexW ? GetReg64(op - 0xB8, hasRex && (rex & 0x01) != 0) : GetReg32(op - 0xB8, hasRex && (rex & 0x01) != 0);
                    if (rexW && offset + 8 <= code.Length)
                    {
                        ulong imm64 = BitConverter.ToUInt64(code, offset);
                        instr.Operands = $"{reg}, 0x{imm64:X}";
                        offset += 8;
                    }
                    else if (offset + 4 <= code.Length)
                    {
                        uint imm32 = BitConverter.ToUInt32(code, offset);
                        instr.Operands = $"{reg}, 0x{imm32:X}";
                        offset += 4;
                    }
                    break;

                // CALL rel32
                case 0xE8:
                    instr.Mnemonic = "call";
                    if (offset + 4 <= code.Length)
                    {
                        int rel = BitConverter.ToInt32(code, offset);
                        offset += 4;
                        ulong target = address + (ulong)(offset - start) + (ulong)rel;
                        instr.Operands = $"0x{target:X}";
                    }
                    break;

                // JMP rel32
                case 0xE9:
                    instr.Mnemonic = "jmp";
                    if (offset + 4 <= code.Length)
                    {
                        int rel = BitConverter.ToInt32(code, offset);
                        offset += 4;
                        ulong target = address + (ulong)(offset - start) + (ulong)rel;
                        instr.Operands = $"0x{target:X}";
                    }
                    break;

                // JMP rel8
                case 0xEB:
                    instr.Mnemonic = "jmp";
                    if (offset < code.Length)
                    {
                        sbyte rel = (sbyte)code[offset++];
                        ulong target = address + (ulong)(offset - start) + (ulong)rel;
                        instr.Operands = $"0x{target:X}";
                    }
                    break;

                // Jcc rel8 (short conditional jumps)
                case 0x70: case 0x71: case 0x72: case 0x73:
                case 0x74: case 0x75: case 0x76: case 0x77:
                case 0x78: case 0x79: case 0x7A: case 0x7B:
                case 0x7C: case 0x7D: case 0x7E: case 0x7F:
                    instr.Mnemonic = GetJccMnemonic(op - 0x70);
                    if (offset < code.Length)
                    {
                        sbyte rel = (sbyte)code[offset++];
                        ulong target = address + (ulong)(offset - start) + (ulong)rel;
                        instr.Operands = $"0x{target:X}";
                    }
                    break;

                // SUB RSP, imm8 (common prologue)
                case 0x83:
                    if (offset < code.Length)
                    {
                        byte modrm = code[offset++];
                        int regField = (modrm >> 3) & 7;
                        string[] ops83 = { "add", "or", "adc", "sbb", "and", "sub", "xor", "cmp" };
                        instr.Mnemonic = ops83[regField];
                        if (offset < code.Length)
                        {
                            sbyte imm = (sbyte)code[offset++];
                            string rm = DecodeModRM_R64(modrm, rex);
                            instr.Operands = $"{rm}, 0x{(byte)imm:X}";
                        }
                    }
                    break;

                // MOV r/m, r or MOV r, r/m patterns
                case 0x89:
                case 0x8B:
                    instr.Mnemonic = "mov";
                    if (offset < code.Length)
                    {
                        byte modrm = code[offset++];
                        offset = SkipModRM(code, offset, modrm);
                        instr.Operands = "..."; // simplified
                    }
                    break;

                // LEA
                case 0x8D:
                    instr.Mnemonic = "lea";
                    if (offset < code.Length)
                    {
                        byte modrm = code[offset++];
                        offset = SkipModRM(code, offset, modrm);
                        instr.Operands = "...";
                    }
                    break;

                // TEST
                case 0x85:
                    instr.Mnemonic = "test";
                    if (offset < code.Length)
                    {
                        byte modrm = code[offset++];
                        offset = SkipModRM(code, offset, modrm);
                        instr.Operands = "...";
                    }
                    break;

                // XOR r, r/m
                case 0x31: case 0x33:
                    instr.Mnemonic = "xor";
                    if (offset < code.Length)
                    {
                        byte modrm = code[offset++];
                        offset = SkipModRM(code, offset, modrm);
                        instr.Operands = "...";
                    }
                    break;

                // CMP
                case 0x39: case 0x3B: case 0x3D:
                    instr.Mnemonic = "cmp";
                    if (op == 0x3D && offset + 4 <= code.Length)
                    {
                        uint imm = BitConverter.ToUInt32(code, offset);
                        offset += 4;
                        instr.Operands = $"eax, 0x{imm:X}";
                    }
                    else if (offset < code.Length)
                    {
                        byte modrm = code[offset++];
                        offset = SkipModRM(code, offset, modrm);
                        instr.Operands = "...";
                    }
                    break;

                // Two-byte opcodes (0F xx)
                case 0x0F:
                    if (offset < code.Length)
                    {
                        byte op2 = code[offset++];
                        // Jcc rel32 (near conditional jumps)
                        if (op2 >= 0x80 && op2 <= 0x8F)
                        {
                            instr.Mnemonic = GetJccMnemonic(op2 - 0x80);
                            if (offset + 4 <= code.Length)
                            {
                                int rel = BitConverter.ToInt32(code, offset);
                                offset += 4;
                                ulong target = address + (ulong)(offset - start) + (ulong)rel;
                                instr.Operands = $"0x{target:X}";
                            }
                        }
                        else if (op2 == 0x1F) // NOP with ModR/M
                        {
                            instr.Mnemonic = "nop";
                            if (offset < code.Length)
                            {
                                byte modrm = code[offset++];
                                offset = SkipModRM(code, offset, modrm);
                            }
                        }
                        else if (op2 == 0xB6 || op2 == 0xB7 || op2 == 0xBE || op2 == 0xBF)
                        {
                            instr.Mnemonic = op2 == 0xB6 ? "movzx" : op2 == 0xB7 ? "movzx" : op2 == 0xBE ? "movsx" : "movsx";
                            if (offset < code.Length)
                            {
                                byte modrm = code[offset++];
                                offset = SkipModRM(code, offset, modrm);
                                instr.Operands = "...";
                            }
                        }
                        else
                        {
                            instr.Mnemonic = $"0F {op2:X2}";
                            if (offset < code.Length && NeedModRM(op2))
                            {
                                byte modrm = code[offset++];
                                offset = SkipModRM(code, offset, modrm);
                            }
                        }
                    }
                    break;

                // FF group (call/jmp indirect, push, inc, dec)
                case 0xFF:
                    if (offset < code.Length)
                    {
                        byte modrm = code[offset++];
                        int regField = (modrm >> 3) & 7;
                        string[] ffOps = { "inc", "dec", "call", "call far", "jmp", "jmp far", "push", "???" };
                        instr.Mnemonic = ffOps[regField];
                        offset = SkipModRM(code, offset, modrm);
                        instr.Operands = "[...]";
                    }
                    break;

                default:
                    instr.Mnemonic = $"db 0x{op:X2}";
                    // Try to skip ModR/M if needed
                    if (NeedsModRM(op) && offset < code.Length)
                    {
                        byte modrm = code[offset++];
                        offset = SkipModRM(code, offset, modrm);
                    }
                    break;
            }

            instr.Size = offset - start;
            instr.Bytes = CopyBytes(code, start, instr.Size);
            return instr;
        }

        private static string GetJccMnemonic(int idx)
        {
            string[] names = { "jo", "jno", "jb", "jnb", "jz", "jnz", "jbe", "jnbe",
                               "js", "jns", "jp", "jnp", "jl", "jnl", "jle", "jnle" };
            return idx >= 0 && idx < names.Length ? names[idx] : $"j{idx:X}";
        }

        private static string GetReg64(int idx, bool rexB)
        {
            int r = idx + (rexB ? 8 : 0);
            string[] regs = { "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                              "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" };
            return r < regs.Length ? regs[r] : $"r{r}";
        }

        private static string GetReg32(int idx, bool rexB)
        {
            int r = idx + (rexB ? 8 : 0);
            string[] regs = { "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
                              "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d" };
            return r < regs.Length ? regs[r] : $"r{r}d";
        }

        private static string DecodeModRM_R64(byte modrm, byte rex)
        {
            int rm = modrm & 7;
            bool rexB = (rex & 0x01) != 0;
            return GetReg64(rm, rexB);
        }

        private static int SkipModRM(byte[] code, int offset, byte modrm)
        {
            int mod = (modrm >> 6) & 3;
            int rm = modrm & 7;

            if (mod == 3) return offset; // register direct

            if (rm == 4 && offset < code.Length) offset++; // SIB byte

            if (mod == 0 && rm == 5) offset += 4; // RIP-relative (disp32)
            else if (mod == 1) offset += 1; // disp8
            else if (mod == 2) offset += 4; // disp32

            return Math.Min(offset, code.Length);
        }

        private static bool NeedModRM(byte op2)
        {
            // Most 0F xx instructions need ModR/M
            if (op2 >= 0x80 && op2 <= 0x8F) return false; // Jcc rel32
            return true;
        }

        private static bool NeedsModRM(byte op)
        {
            // Simplified check for single-byte opcodes that need ModR/M
            if (op >= 0x00 && op <= 0x3F) return (op & 0x07) < 6;
            if (op >= 0x80 && op <= 0x8F) return true;
            if (op == 0xC6 || op == 0xC7) return true;
            if (op == 0xF6 || op == 0xF7) return true;
            if (op == 0xFE || op == 0xFF) return true;
            return false;
        }

        private static byte[] CopyBytes(byte[] src, int offset, int count)
        {
            count = Math.Min(count, src.Length - offset);
            if (count <= 0) return new byte[0];
            byte[] result = new byte[count];
            Array.Copy(src, offset, result, 0, count);
            return result;
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
