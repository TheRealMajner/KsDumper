using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace KsDumperClient.Utility
{
    public static class Il2CppMetadataDecryptor
    {
        public class DecryptionResult
        {
            public bool WasEncrypted;
            public string Method;
            public byte[] DecryptedMetadata;
            public double OriginalEntropy;
            public double DecryptedEntropy;
            public int KeyLength;
            public byte[] Key;
            public string Details;
        }

        public static DecryptionResult TryDecrypt(byte[] rawMetadata, Action<string> log = null)
        {
            var result = new DecryptionResult();

            if (rawMetadata == null || rawMetadata.Length < 280)
            {
                result.Details = "Data too small";
                return result;
            }

            // Check if already valid
            uint magic = BitConverter.ToUInt32(rawMetadata, 0);
            if (magic == 0xFAB11BAF)
            {
                result.Details = "Already valid (no encryption)";
                return result;
            }

            result.OriginalEntropy = CalculateEntropy(rawMetadata, 0, Math.Min(rawMetadata.Length, 0x10000));
            log?.Invoke($"Original entropy: {result.OriginalEntropy:F4}");

            // 1. Single-byte XOR (already in Il2CppDumper, but try here too for completeness)
            var xorResult = TrySingleByteXor(rawMetadata, log);
            if (xorResult != null)
            {
                result.WasEncrypted = true;
                result.Method = "XOR (single byte)";
                result.DecryptedMetadata = xorResult.Item1;
                result.Key = new byte[] { xorResult.Item2 };
                result.KeyLength = 1;
                result.DecryptedEntropy = CalculateEntropy(result.DecryptedMetadata, 0, Math.Min(result.DecryptedMetadata.Length, 0x10000));
                result.Details = $"XOR key: 0x{xorResult.Item2:X2}";
                return result;
            }

            // 2. Multi-byte XOR (repeating key, common in NetEase/Momo protectors)
            var multiXorResult = TryMultiByteXor(rawMetadata, log);
            if (multiXorResult != null)
            {
                result.WasEncrypted = true;
                result.Method = $"XOR (repeating {multiXorResult.Item2.Length}-byte key)";
                result.DecryptedMetadata = multiXorResult.Item1;
                result.Key = multiXorResult.Item2;
                result.KeyLength = multiXorResult.Item2.Length;
                result.DecryptedEntropy = CalculateEntropy(result.DecryptedMetadata, 0, Math.Min(result.DecryptedMetadata.Length, 0x10000));
                result.Details = $"Key: {BitConverter.ToString(multiXorResult.Item2)}";
                return result;
            }

            // 3. Rolling XOR (key changes each byte)
            var rollingResult = TryRollingXor(rawMetadata, log);
            if (rollingResult != null)
            {
                result.WasEncrypted = true;
                result.Method = "Rolling XOR";
                result.DecryptedMetadata = rollingResult;
                result.DecryptedEntropy = CalculateEntropy(result.DecryptedMetadata, 0, Math.Min(result.DecryptedMetadata.Length, 0x10000));
                result.Details = "Rolling XOR with incrementing key";
                return result;
            }

            // 4. Byte-swap (some protectors swap nibbles or reverse byte order)
            var swapResult = TryByteSwap(rawMetadata, log);
            if (swapResult != null)
            {
                result.WasEncrypted = true;
                result.Method = "Byte swap (nibble)";
                result.DecryptedMetadata = swapResult;
                result.DecryptedEntropy = CalculateEntropy(result.DecryptedMetadata, 0, Math.Min(result.DecryptedMetadata.Length, 0x10000));
                result.Details = "Nibble swap transformation";
                return result;
            }

            // 5. Header-only encryption (some protectors encrypt only the first N bytes)
            var headerResult = TryHeaderOnlyDecrypt(rawMetadata, log);
            if (headerResult != null)
            {
                result.WasEncrypted = true;
                result.Method = "Header-only XOR";
                result.DecryptedMetadata = headerResult.Item1;
                result.Key = new byte[] { headerResult.Item2 };
                result.KeyLength = 1;
                result.DecryptedEntropy = CalculateEntropy(result.DecryptedMetadata, 0, Math.Min(result.DecryptedMetadata.Length, 0x10000));
                result.Details = $"First 0x{headerResult.Item3:X} bytes XOR'd with 0x{headerResult.Item2:X2}";
                return result;
            }

            result.Details = "Could not determine encryption method";
            return result;
        }

        public static double CalculateEntropy(byte[] data, int offset, int length)
        {
            if (data == null || length <= 0) return 0;
            int end = Math.Min(offset + length, data.Length);
            int count = end - offset;
            if (count <= 0) return 0;

            int[] freq = new int[256];
            for (int i = offset; i < end; i++)
                freq[data[i]]++;

            double entropy = 0;
            for (int i = 0; i < 256; i++)
            {
                if (freq[i] == 0) continue;
                double p = (double)freq[i] / count;
                entropy -= p * Math.Log(p, 2);
            }
            return entropy;
        }

        public static bool IsStringTableEncrypted(byte[] metadata)
        {
            if (metadata == null || metadata.Length < 280) return false;

            uint magic = BitConverter.ToUInt32(metadata, 0);
            if (magic != 0xFAB11BAF) return true; // entire metadata encrypted

            int version = BitConverter.ToInt32(metadata, 4);
            if (version < 16 || version > 40) return false;

            // Parse string table offset/size from header
            int stringOffset = BitConverter.ToInt32(metadata, 8 + 4 * 4); // StringOffset
            int stringSize = BitConverter.ToInt32(metadata, 8 + 4 * 4 + 4); // StringSize

            if (stringOffset <= 0 || stringSize <= 0 || stringOffset + stringSize > metadata.Length)
                return false;

            // Check if string table has high entropy (encrypted) vs normal (lots of null bytes and ASCII)
            double entropy = CalculateEntropy(metadata, stringOffset, Math.Min(stringSize, 0x10000));

            // Normal string tables have low entropy (lots of null terminators and ASCII text)
            // Encrypted ones approach 8.0 (random bytes)
            return entropy > 6.5;
        }

        public static byte[] TryDecryptStringTable(byte[] metadata, Action<string> log = null)
        {
            if (metadata == null || metadata.Length < 280) return null;

            int stringOffset = BitConverter.ToInt32(metadata, 8 + 4 * 4);
            int stringSize = BitConverter.ToInt32(metadata, 8 + 4 * 4 + 4);

            if (stringOffset <= 0 || stringSize <= 0 || stringOffset + stringSize > metadata.Length)
                return null;

            double entropy = CalculateEntropy(metadata, stringOffset, Math.Min(stringSize, 0x10000));
            if (entropy < 6.5)
            {
                log?.Invoke($"String table entropy {entropy:F4} is normal — not encrypted");
                return null;
            }

            log?.Invoke($"String table entropy {entropy:F4} suggests encryption");

            byte[] decrypted = (byte[])metadata.Clone();

            // Try single-byte XOR on string table only
            // The string table should start with a null byte (index 0 = empty string)
            // and contain mostly ASCII text with null terminators
            for (byte key = 1; key != 0; key++)
            {
                byte first = (byte)(metadata[stringOffset] ^ key);
                if (first != 0) continue;

                // Check if decrypted data looks like strings
                int nullCount = 0;
                int asciiCount = 0;
                int checkLen = Math.Min(stringSize, 4096);

                for (int i = 0; i < checkLen; i++)
                {
                    byte b = (byte)(metadata[stringOffset + i] ^ key);
                    if (b == 0) nullCount++;
                    else if (b >= 0x20 && b <= 0x7E) asciiCount++;
                }

                double nullRatio = (double)nullCount / checkLen;
                double asciiRatio = (double)asciiCount / checkLen;

                if (nullRatio > 0.05 && asciiRatio > 0.5)
                {
                    log?.Invoke($"String table XOR key: 0x{key:X2} (null ratio: {nullRatio:F3}, ascii ratio: {asciiRatio:F3})");
                    for (int i = 0; i < stringSize && stringOffset + i < decrypted.Length; i++)
                        decrypted[stringOffset + i] ^= key;
                    return decrypted;
                }
            }

            log?.Invoke("Could not determine string table encryption key");
            return null;
        }

        // ===== Internal decryption methods =====

        private static Tuple<byte[], byte> TrySingleByteXor(byte[] data, Action<string> log)
        {
            byte[] expectedMagic = { 0xAF, 0x1B, 0xB1, 0xFA };

            for (byte key = 1; key != 0; key++)
            {
                bool match = true;
                for (int i = 0; i < 4; i++)
                {
                    if ((byte)(data[i] ^ key) != expectedMagic[i])
                    { match = false; break; }
                }
                if (!match) continue;

                int version = (data[4] ^ key) | ((data[5] ^ key) << 8);
                if (version < 16 || version > 40) continue;

                log?.Invoke($"Single-byte XOR hit: key=0x{key:X2}, version={version}");
                byte[] decrypted = new byte[data.Length];
                for (int i = 0; i < data.Length; i++)
                    decrypted[i] = (byte)(data[i] ^ key);
                return Tuple.Create(decrypted, key);
            }
            return null;
        }

        private static Tuple<byte[], byte[]> TryMultiByteXor(byte[] data, Action<string> log)
        {
            byte[] expectedMagic = { 0xAF, 0x1B, 0xB1, 0xFA };
            int[] keyLengths = { 2, 4, 8, 16, 32 };

            foreach (int keyLen in keyLengths)
            {
                byte[] key = new byte[keyLen];
                for (int i = 0; i < Math.Min(keyLen, 4); i++)
                    key[i] = (byte)(data[i] ^ expectedMagic[i]);

                // For keys longer than 4, derive remaining bytes from known version fields
                if (keyLen > 4)
                {
                    // version bytes (4,5) should decode to 16-40 range
                    // bytes 6,7 should be 0 for version high bytes
                    for (int trial = 16; trial <= 40; trial++)
                    {
                        key[4] = (byte)(data[4] ^ (byte)(trial & 0xFF));
                        if (keyLen > 5) key[5] = (byte)(data[5] ^ (byte)((trial >> 8) & 0xFF));
                        if (keyLen > 6) key[6] = (byte)(data[6] ^ 0);
                        if (keyLen > 7) key[7] = (byte)(data[7] ^ 0);

                        // Fill rest with pattern repeat
                        for (int k = 8; k < keyLen; k++)
                            key[k] = key[k % 8];

                        byte[] test = new byte[Math.Min(data.Length, 280)];
                        for (int i = 0; i < test.Length; i++)
                            test[i] = (byte)(data[i] ^ key[i % keyLen]);

                        if (Il2CppDumper.ValidateMetadataStructure(test))
                        {
                            log?.Invoke($"Multi-byte XOR hit: {keyLen}-byte key, version={trial}");
                            byte[] decrypted = new byte[data.Length];
                            for (int i = 0; i < data.Length; i++)
                                decrypted[i] = (byte)(data[i] ^ key[i % keyLen]);
                            return Tuple.Create(decrypted, key);
                        }
                    }
                }
                else
                {
                    byte[] test = new byte[Math.Min(data.Length, 280)];
                    for (int i = 0; i < test.Length; i++)
                        test[i] = (byte)(data[i] ^ key[i % keyLen]);

                    if (Il2CppDumper.ValidateMetadataStructure(test))
                    {
                        log?.Invoke($"Multi-byte XOR hit: {keyLen}-byte key");
                        byte[] decrypted = new byte[data.Length];
                        for (int i = 0; i < data.Length; i++)
                            decrypted[i] = (byte)(data[i] ^ key[i % keyLen]);
                        return Tuple.Create(decrypted, key);
                    }
                }
            }
            return null;
        }

        private static byte[] TryRollingXor(byte[] data, Action<string> log)
        {
            byte[] expectedMagic = { 0xAF, 0x1B, 0xB1, 0xFA };

            // Try: key starts at data[0] ^ expected[0], then increments
            byte startKey = (byte)(data[0] ^ expectedMagic[0]);
            byte[] test = new byte[Math.Min(data.Length, 280)];
            for (int i = 0; i < test.Length; i++)
                test[i] = (byte)(data[i] ^ (byte)(startKey + i));

            if (Il2CppDumper.ValidateMetadataStructure(test))
            {
                log?.Invoke($"Rolling XOR hit: start=0x{startKey:X2}, increment=1");
                byte[] decrypted = new byte[data.Length];
                for (int i = 0; i < data.Length; i++)
                    decrypted[i] = (byte)(data[i] ^ (byte)(startKey + i));
                return decrypted;
            }

            // Try with multiply pattern
            for (byte mult = 2; mult < 8; mult++)
            {
                for (int i = 0; i < test.Length; i++)
                    test[i] = (byte)(data[i] ^ (byte)(startKey + i * mult));

                if (Il2CppDumper.ValidateMetadataStructure(test))
                {
                    log?.Invoke($"Rolling XOR hit: start=0x{startKey:X2}, step={mult}");
                    byte[] decrypted = new byte[data.Length];
                    for (int i = 0; i < data.Length; i++)
                        decrypted[i] = (byte)(data[i] ^ (byte)(startKey + i * mult));
                    return decrypted;
                }
            }

            return null;
        }

        private static byte[] TryByteSwap(byte[] data, Action<string> log)
        {
            byte[] expectedMagic = { 0xAF, 0x1B, 0xB1, 0xFA };

            // Nibble swap: swap high and low nibbles
            byte[] test = new byte[Math.Min(data.Length, 280)];
            for (int i = 0; i < test.Length; i++)
                test[i] = (byte)((data[i] >> 4) | (data[i] << 4));

            if (Il2CppDumper.ValidateMetadataStructure(test))
            {
                log?.Invoke("Nibble swap detected");
                byte[] decrypted = new byte[data.Length];
                for (int i = 0; i < data.Length; i++)
                    decrypted[i] = (byte)((data[i] >> 4) | (data[i] << 4));
                return decrypted;
            }

            // Bit reverse
            for (int i = 0; i < test.Length; i++)
            {
                byte b = data[i];
                b = (byte)((b & 0xF0) >> 4 | (b & 0x0F) << 4);
                b = (byte)((b & 0xCC) >> 2 | (b & 0x33) << 2);
                b = (byte)((b & 0xAA) >> 1 | (b & 0x55) << 1);
                test[i] = b;
            }

            if (Il2CppDumper.ValidateMetadataStructure(test))
            {
                log?.Invoke("Bit reversal detected");
                byte[] decrypted = new byte[data.Length];
                for (int i = 0; i < data.Length; i++)
                {
                    byte b = data[i];
                    b = (byte)((b & 0xF0) >> 4 | (b & 0x0F) << 4);
                    b = (byte)((b & 0xCC) >> 2 | (b & 0x33) << 2);
                    b = (byte)((b & 0xAA) >> 1 | (b & 0x55) << 1);
                    decrypted[i] = b;
                }
                return decrypted;
            }

            return null;
        }

        private static Tuple<byte[], byte, int> TryHeaderOnlyDecrypt(byte[] data, Action<string> log)
        {
            byte[] expectedMagic = { 0xAF, 0x1B, 0xB1, 0xFA };
            int[] headerSizes = { 0x100, 0x200, 0x400, 0x800, 0x1000 };

            for (byte key = 1; key != 0; key++)
            {
                bool magicMatch = true;
                for (int i = 0; i < 4; i++)
                {
                    if ((byte)(data[i] ^ key) != expectedMagic[i])
                    { magicMatch = false; break; }
                }
                if (!magicMatch) continue;

                foreach (int headerSize in headerSizes)
                {
                    if (headerSize > data.Length) continue;

                    byte[] test = (byte[])data.Clone();
                    for (int i = 0; i < headerSize; i++)
                        test[i] ^= key;

                    if (Il2CppDumper.ValidateMetadataStructure(test))
                    {
                        log?.Invoke($"Header-only XOR: key=0x{key:X2}, size=0x{headerSize:X}");
                        return Tuple.Create(test, key, headerSize);
                    }
                }
            }

            return null;
        }
    }
}
