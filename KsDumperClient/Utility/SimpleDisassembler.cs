using System;
using System.Collections.Generic;
using System.Text;

namespace KsDumperClient.Utility
{
    public static class SimpleDisassembler
    {
        public struct Instruction
        {
            public ulong Address;
            public byte[] Bytes;
            public string Mnemonic;
            public string Operands;
            public int Length;
            public string Category; // CALL, JMP, RET, INT, PUSH, POP, MOV, etc.
            public ulong TargetAddress; // For CALL/JMP: resolved target address (0 if not applicable)
        }

        private static readonly string[] RegNames64 = { "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" };
        private static readonly string[] RegNames32 = { "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d" };

        private static readonly Dictionary<byte, (string mnemonic, int immSize)> OneByteOps = new Dictionary<byte, (string, int)>
        {
            // PUSH/POP registers
            { 0x50, ("push", 0) }, { 0x51, ("push", 0) }, { 0x52, ("push", 0) }, { 0x53, ("push", 0) },
            { 0x54, ("push", 0) }, { 0x55, ("push", 0) }, { 0x56, ("push", 0) }, { 0x57, ("push", 0) },
            { 0x58, ("pop", 0) }, { 0x59, ("pop", 0) }, { 0x5A, ("pop", 0) }, { 0x5B, ("pop", 0) },
            { 0x5C, ("pop", 0) }, { 0x5D, ("pop", 0) }, { 0x5E, ("pop", 0) }, { 0x5F, ("pop", 0) },
            // PUSH immediate
            { 0x68, ("push", 4) }, { 0x6A, ("push", 1) },
            // NOP, INT, RET
            { 0x90, ("nop", 0) },
            { 0xC3, ("ret", 0) }, { 0xC2, ("ret", 2) },
            { 0xCB, ("retf", 0) }, { 0xCA, ("retf", 2) },
            { 0xCC, ("int3", 0) }, { 0xCD, ("int", 1) },
            // CALL/JMP
            { 0xE8, ("call", 4) }, { 0xE9, ("jmp", 4) }, { 0xEB, ("jmp short", 1) },
            // Jcc short
            { 0x70, ("jo", 1) }, { 0x71, ("jno", 1) }, { 0x72, ("jb", 1) }, { 0x73, ("jnb", 1) },
            { 0x74, ("je", 1) }, { 0x75, ("jne", 1) }, { 0x76, ("jbe", 1) }, { 0x77, ("ja", 1) },
            { 0x78, ("js", 1) }, { 0x79, ("jns", 1) }, { 0x7A, ("jp", 1) }, { 0x7B, ("jnp", 1) },
            { 0x7C, ("jl", 1) }, { 0x7D, ("jge", 1) }, { 0x7E, ("jle", 1) }, { 0x7F, ("jg", 1) },
            // INC/DEC (x86 only, x64 uses REX prefix space)
            { 0x40, ("inc", 0) }, { 0x41, ("inc", 0) }, { 0x42, ("inc", 0) }, { 0x43, ("inc", 0) },
            { 0x44, ("inc", 0) }, { 0x45, ("inc", 0) }, { 0x46, ("inc", 0) }, { 0x47, ("inc", 0) },
            { 0x48, ("dec", 0) }, { 0x49, ("dec", 0) }, { 0x4A, ("dec", 0) }, { 0x4B, ("dec", 0) },
            { 0x4C, ("dec", 0) }, { 0x4D, ("dec", 0) }, { 0x4E, ("dec", 0) }, { 0x4F, ("dec", 0) },
            // XCHG
            { 0x91, ("xchg", 0) }, { 0x92, ("xchg", 0) }, { 0x93, ("xchg", 0) },
            { 0x94, ("xchg", 0) }, { 0x95, ("xchg", 0) }, { 0x96, ("xchg", 0) }, { 0x97, ("xchg", 0) },
            // Misc
            { 0xF4, ("hlt", 0) }, { 0xF8, ("clc", 0) }, { 0xF9, ("stc", 0) },
            { 0xFA, ("cli", 0) }, { 0xFB, ("sti", 0) }, { 0xFC, ("cld", 0) }, { 0xFD, ("std", 0) },
            { 0x9E, ("sahf", 0) }, { 0x9F, ("lahf", 0) },
            { 0x98, ("cwde", 0) }, { 0x99, ("cdq", 0) },
        };

        public static List<Instruction> Disassemble(byte[] code, ulong baseAddress, int maxInstructions = 100, bool is64bit = true)
        {
            var result = new List<Instruction>();
            int offset = 0;

            while (offset < code.Length && result.Count < maxInstructions)
            {
                var instr = DecodeInstruction(code, offset, baseAddress + (ulong)offset, is64bit);
                if (instr.Length == 0) break;
                result.Add(instr);
                offset += instr.Length;
            }

            return result;
        }

        /// <summary>
        /// Returns the target address of a CALL or JMP instruction, or 0 if not applicable.
        /// </summary>
        public static ulong GetJumpTarget(Instruction instr)
        {
            return instr.TargetAddress;
        }

        private static Instruction DecodeInstruction(byte[] code, int offset, ulong address, bool is64bit)
        {
            if (offset >= code.Length) return new Instruction { Length = 0 };

            int pos = offset;
            bool hasRex = false;
            byte rexW = 0;
            byte rexB = 0;

            // Check REX prefix (x64)
            if (is64bit && code[pos] >= 0x40 && code[pos] <= 0x4F)
            {
                hasRex = true;
                rexW = (byte)((code[pos] >> 3) & 1);
                rexB = (byte)(code[pos] & 1);
                pos++;
                if (pos >= code.Length) return FallbackInstruction(code, offset, address, 1);
            }

            byte op = code[pos];
            pos++;

            // One-byte opcodes
            if (OneByteOps.TryGetValue(op, out var info))
            {
                // In x64 mode, 0x40-0x4F are REX prefixes, not INC/DEC
                if (is64bit && op >= 0x40 && op <= 0x4F)
                    return FallbackInstruction(code, offset, address, pos - offset);

                int totalLen = pos - offset + info.immSize;
                if (totalLen > code.Length - offset) return FallbackInstruction(code, offset, address, totalLen);

                string operands = "";
                string category = Categorize(info.mnemonic);
                ulong targetAddr = 0;

                if (info.immSize == 1)
                {
                    sbyte imm = (sbyte)code[pos];
                    if (info.mnemonic.StartsWith("j") || info.mnemonic == "call" || info.mnemonic == "jmp short")
                    {
                        targetAddr = address + (ulong)totalLen + (ulong)imm;
                        operands = $"0x{targetAddr:X}";
                    }
                    else
                        operands = $"0x{(byte)imm:X2}";
                }
                else if (info.immSize == 2)
                {
                    operands = $"0x{BitConverter.ToUInt16(code, pos):X4}";
                }
                else if (info.immSize == 4)
                {
                    int imm = BitConverter.ToInt32(code, pos);
                    if (info.mnemonic == "call" || info.mnemonic == "jmp")
                    {
                        targetAddr = address + (ulong)totalLen + (ulong)imm;
                        operands = $"0x{targetAddr:X}";
                    }
                    else if (info.mnemonic == "push")
                        operands = $"0x{(uint)imm:X8}";
                    else
                        operands = $"0x{(uint)imm:X8}";
                }
                else
                {
                    // Register operand
                    int regIdx = (op & 0x07) + (rexB * 8);
                    string[] regs = rexW != 0 ? RegNames64 : RegNames32;
                    if (regIdx < regs.Length)
                        operands = regs[regIdx];
                }

                byte[] bytes = new byte[totalLen];
                Array.Copy(code, offset, bytes, 0, totalLen);

                return new Instruction
                {
                    Address = address, Bytes = bytes, Mnemonic = info.mnemonic,
                    Operands = operands, Length = totalLen, Category = category,
                    TargetAddress = targetAddr
                };
            }

            // 0F xx two-byte opcodes
            if (op == 0x0F && pos < code.Length)
            {
                byte op2 = code[pos]; pos++;
                string mnemonic = "";
                int immSize = 0;
                ulong targetAddr = 0;

                if (op2 >= 0x80 && op2 <= 0x8F)
                {
                    string[] jccNames = { "jo", "jno", "jb", "jnb", "je", "jne", "jbe", "ja", "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg" };
                    mnemonic = jccNames[op2 - 0x80];
                    immSize = 4;
                }
                else if (op2 == 0x05) mnemonic = "syscall";
                else if (op2 == 0x34) mnemonic = "sysenter";
                else if (op2 == 0x31) mnemonic = "rdtsc";
                else if (op2 == 0xA2) mnemonic = "cpuid";
                else if (op2 == 0x30) mnemonic = "wrmsr";
                else if (op2 == 0x32) mnemonic = "rdmsr";
                else if (op2 == 0x1F) { mnemonic = "nop"; immSize = 0; pos += 2; } // 0F 1F /0 multi-byte nop
                else if (op2 == 0xB6) { mnemonic = "movzx"; immSize = 0; } // MOVZX r, r/m8
                else if (op2 == 0xB7) { mnemonic = "movzx"; immSize = 0; } // MOVZX r, r/m16
                else if (op2 == 0xBE) { mnemonic = "movsx"; immSize = 0; } // MOVSX r, r/m8
                else if (op2 == 0xBF) { mnemonic = "movsx"; immSize = 0; } // MOVSX r, r/m16
                else if (op2 == 0xAF) { mnemonic = "imul"; immSize = 0; } // IMUL r, r/m
                else if (op2 >= 0x90 && op2 <= 0x9F)
                {
                    string[] setccNames = { "seto", "setno", "setb", "setnb", "sete", "setne", "setbe", "seta", "sets", "setns", "setp", "setnp", "setl", "setge", "setle", "setg" };
                    mnemonic = setccNames[op2 - 0x90];
                    immSize = 0; pos++; // ModR/M byte
                }
                else mnemonic = $"0F_{op2:X2}";

                int totalLen = pos - offset + immSize;
                if (totalLen > code.Length - offset) return FallbackInstruction(code, offset, address, Math.Min(totalLen, code.Length - offset));

                string operands = "";
                if (immSize == 4 && mnemonic.StartsWith("j"))
                {
                    int imm = BitConverter.ToInt32(code, pos);
                    targetAddr = address + (ulong)totalLen + (ulong)imm;
                    operands = $"0x{targetAddr:X}";
                }

                byte[] bytes = new byte[totalLen];
                Array.Copy(code, offset, bytes, 0, totalLen);

                return new Instruction
                {
                    Address = address, Bytes = bytes, Mnemonic = mnemonic,
                    Operands = operands, Length = totalLen, Category = Categorize(mnemonic),
                    TargetAddress = targetAddr
                };
            }

            // LEA (0x8D)
            if (op == 0x8D)
            {
                int modrm = pos < code.Length ? code[pos] : 0;
                pos++;
                int mod = (modrm >> 6) & 3;
                int regIdx = ((modrm >> 3) & 7) + (rexB * 8);
                int extraBytes = GetModRMExtraBytes(mod, modrm, code, pos);
                int totalLen = pos - offset + extraBytes;
                totalLen = Math.Min(totalLen, code.Length - offset);
                byte[] bytes = new byte[totalLen];
                Array.Copy(code, offset, bytes, 0, totalLen);
                string[] regs = rexW != 0 ? RegNames64 : RegNames32;
                string regName = regIdx < regs.Length ? regs[regIdx] : $"r{regIdx}";
                return new Instruction { Address = address, Bytes = bytes, Mnemonic = "lea", Operands = $"{regName}, [mem]", Length = totalLen, Category = "MOV" };
            }

            // TEST (0x85, 0xA9, 0xF7)
            if (op == 0x85 || op == 0xA9 || op == 0xF6 || op == 0xF7)
            {
                string mn = "test";
                if (op == 0xF6 || op == 0xF7)
                {
                    int modrm = pos < code.Length ? code[pos] : 0;
                    int regOp = (modrm >> 3) & 7;
                    string[] grpOps = { "test", "test", "not", "neg", "mul", "imul", "div", "idiv" };
                    mn = grpOps[regOp];
                }
                int modrmByte = pos < code.Length ? code[pos] : 0;
                pos++;
                int mod = (modrmByte >> 6) & 3;
                int extraBytes = GetModRMExtraBytes(mod, modrmByte, code, pos);
                int immBytes = 0;
                if (op == 0xA9) immBytes = 4;
                else if (op == 0xF6 || op == 0xF7)
                {
                    int regOp = (modrmByte >> 3) & 7;
                    if (regOp <= 1) immBytes = op == 0xF6 ? 1 : 4;
                }
                int totalLen = pos - offset + extraBytes + immBytes;
                totalLen = Math.Min(totalLen, code.Length - offset);
                byte[] bytes = new byte[totalLen];
                Array.Copy(code, offset, bytes, 0, totalLen);
                return new Instruction { Address = address, Bytes = bytes, Mnemonic = mn, Operands = "r/m, r/imm", Length = totalLen, Category = "ALU" };
            }

            // Common ModR/M instructions: ADD/OR/ADC/SBB/AND/SUB/XOR/CMP r/m, imm (0x80-0x83)
            if (op >= 0x80 && op <= 0x83)
            {
                int modrm = pos < code.Length ? code[pos] : 0;
                pos++;
                int mod = (modrm >> 6) & 3;
                int reg = (modrm >> 3) & 7;
                string[] ops = { "add", "or", "adc", "sbb", "and", "sub", "xor", "cmp" };
                string mn = ops[reg];
                int extraBytes = GetModRMExtraBytes(mod, modrm, code, pos);
                int immBytes = op <= 0x81 ? (hasRex && rexW != 0 ? 4 : 4) : 1;
                int totalLen = pos - offset + extraBytes + immBytes;
                totalLen = Math.Min(totalLen, code.Length - offset);
                byte[] bytes = new byte[totalLen];
                Array.Copy(code, offset, bytes, 0, totalLen);
                return new Instruction { Address = address, Bytes = bytes, Mnemonic = mn, Operands = "r/m, imm", Length = totalLen, Category = "ALU" };
            }

            // MOV r/m, r (0x89) or MOV r, r/m (0x8B)
            if (op == 0x89 || op == 0x8B)
            {
                int modrm = pos < code.Length ? code[pos] : 0;
                pos++;
                int mod = (modrm >> 6) & 3;
                int regIdx = ((modrm >> 3) & 7) + (rexB * 8);
                int extraBytes = GetModRMExtraBytes(mod, modrm, code, pos);
                int totalLen = pos - offset + extraBytes;
                totalLen = Math.Min(totalLen, code.Length - offset);
                byte[] bytes = new byte[totalLen];
                Array.Copy(code, offset, bytes, 0, totalLen);
                string[] regs = rexW != 0 ? RegNames64 : RegNames32;
                string regName = regIdx < regs.Length ? regs[regIdx] : $"r{regIdx}";
                string dir = op == 0x89 ? $"{regName}, r/m" : $"r/m, {regName}";
                return new Instruction { Address = address, Bytes = bytes, Mnemonic = "mov", Operands = dir, Length = totalLen, Category = "MOV" };
            }

            // XOR r/m, r (0x31) or XOR r, r/m (0x33)
            if (op == 0x31 || op == 0x33 || op == 0x30 || op == 0x32 ||
                op == 0x01 || op == 0x03 || op == 0x00 || op == 0x02 ||
                op == 0x21 || op == 0x23 || op == 0x20 || op == 0x22)
            {
                string[] aluOps = { "add", "add", "add", "add", "or", "or", "or", "or",
                                    "and", "and", "and", "and", "sub", "sub", "sub", "sub",
                                    "xor", "xor", "xor", "xor", "cmp", "cmp", "cmp", "cmp" };
                string mn = aluOps[(op >> 1) & 0x0F];
                int modrm = pos < code.Length ? code[pos] : 0;
                pos++;
                int mod = (modrm >> 6) & 3;
                int extraBytes = GetModRMExtraBytes(mod, modrm, code, pos);
                int totalLen = pos - offset + extraBytes;
                totalLen = Math.Min(totalLen, code.Length - offset);
                byte[] bytes = new byte[totalLen];
                Array.Copy(code, offset, bytes, 0, totalLen);
                return new Instruction { Address = address, Bytes = bytes, Mnemonic = mn, Operands = "r/m, r", Length = totalLen, Category = "ALU" };
            }

            // MOV r, imm (0xB8-0xBF)
            if (op >= 0xB8 && op <= 0xBF)
            {
                int immSize = (hasRex && rexW != 0) ? 8 : 4;
                int totalLen = pos - offset + immSize;
                if (totalLen > code.Length - offset) return FallbackInstruction(code, offset, address, totalLen);

                int regIdx = (op - 0xB8) + (rexB * 8);
                string[] regs = (hasRex && rexW != 0) ? RegNames64 : RegNames32;
                string regName = regIdx < regs.Length ? regs[regIdx] : $"r{regIdx}";

                string operands;
                if (immSize == 8)
                    operands = $"{regName}, 0x{BitConverter.ToUInt64(code, pos):X}";
                else
                    operands = $"{regName}, 0x{BitConverter.ToUInt32(code, pos):X8}";

                byte[] bytes = new byte[totalLen];
                Array.Copy(code, offset, bytes, 0, totalLen);
                return new Instruction { Address = address, Bytes = bytes, Mnemonic = "mov", Operands = operands, Length = totalLen, Category = "MOV" };
            }

            return FallbackInstruction(code, offset, address, 1);
        }

        private static int GetModRMExtraBytes(int mod, int modrm, byte[] code, int pos)
        {
            int rm = modrm & 7;
            int extra = 0;
            if (rm == 4 && pos < code.Length) extra++; // SIB byte
            if (mod == 1) extra += 1; // disp8
            else if (mod == 2) extra += 4; // disp32
            else if (mod == 0 && rm == 5) extra += 4; // RIP-relative
            return extra;
        }

        private static Instruction FallbackInstruction(byte[] code, int offset, ulong address, int len)
        {
            len = Math.Min(len, code.Length - offset);
            if (len <= 0) return new Instruction { Length = 0 };
            byte[] bytes = new byte[len];
            Array.Copy(code, offset, bytes, 0, len);
            return new Instruction { Address = address, Bytes = bytes, Mnemonic = "db", Operands = $"0x{code[offset]:X2}", Length = len, Category = "DATA" };
        }

        private static string Categorize(string mnemonic)
        {
            if (mnemonic == "call") return "CALL";
            if (mnemonic.StartsWith("j") || mnemonic == "jmp" || mnemonic == "jmp short") return "JMP";
            if (mnemonic.StartsWith("ret")) return "RET";
            if (mnemonic == "int3" || mnemonic == "int") return "INT";
            if (mnemonic == "nop") return "NOP";
            if (mnemonic == "syscall" || mnemonic == "sysenter") return "SYSCALL";
            if (mnemonic == "push" || mnemonic == "pop") return "STACK";
            if (mnemonic == "mov") return "MOV";
            return "OTHER";
        }
    }
}
