using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using KsDumperClient.Driver;

namespace KsDumperClient.Utility
{
    public static class ProtobufDetector
    {
        public enum SerializationFormat
        {
            Unknown,
            Protobuf,
            FlatBuffers,
            MessagePack,
            Json,
            Xml
        }

        public class FormatDetection
        {
            public SerializationFormat Format;
            public ulong Address;
            public int Size;
            public float Confidence;
            public string Details;
        }

        public class ProtobufField
        {
            public int FieldNumber;
            public int WireType; // 0=varint, 1=64bit, 2=length-delimited, 5=32bit
            public string WireTypeName;
            public int Offset;
            public int DataLength;
            public string InferredType;
            public string SampleValue;
        }

        public class InferredMessage
        {
            public ulong Address;
            public int Size;
            public List<ProtobufField> Fields = new List<ProtobufField>();
            public float Confidence;
        }

        public class DetectionResult
        {
            public List<FormatDetection> Detections = new List<FormatDetection>();
            public List<InferredMessage> InferredMessages = new List<InferredMessage>();
            public Dictionary<SerializationFormat, int> CountByFormat = new Dictionary<SerializationFormat, int>();
            public int RegionsScanned;
        }

        // FlatBuffers magic
        private static readonly byte[] FlatBuffersMagic = Encoding.ASCII.GetBytes("BFBS");
        private static readonly byte[] FlatBuffersFileMagic = Encoding.ASCII.GetBytes("FLTB");

        // MessagePack markers
        private const byte MsgPack_FixMap = 0x80;
        private const byte MsgPack_FixArray = 0x90;
        private const byte MsgPack_Map16 = 0xDE;
        private const byte MsgPack_Array16 = 0xDC;

        public static DetectionResult Detect(
            IMemoryReader driver, int pid,
            ulong scanBase = 0, ulong scanEnd = 0,
            int maxDetections = 500)
        {
            var result = new DetectionResult();

            var regions = driver.EnumRegions(pid);
            if (regions == null) return result;

            foreach (var (baseAddr, regionSize, protect, state, type) in regions)
            {
                if (result.Detections.Count >= maxDetections) break;
                if (state != 0x1000) continue;
                if ((protect & 0x02) == 0 && (protect & 0x04) == 0 &&
                    (protect & 0x08) == 0 && (protect & 0x40) == 0) continue;
                if (regionSize < 16 || regionSize > 0x4000000) continue;

                if (scanBase != 0 && baseAddr + regionSize <= scanBase) continue;
                if (scanEnd != 0 && baseAddr >= scanEnd) continue;

                int readSize = (int)Math.Min(regionSize, 0x1000000);
                byte[] data = ReadMemory(driver, pid, baseAddr, readSize);
                if (data == null) continue;

                result.RegionsScanned++;

                // Scan for format markers
                ScanForFlatBuffers(data, baseAddr, result);
                ScanForProtobufMessages(data, baseAddr, result, maxDetections);
                ScanForMessagePack(data, baseAddr, result);
                ScanForJsonXml(data, baseAddr, result);
            }

            // Count by format
            foreach (var det in result.Detections)
            {
                if (!result.CountByFormat.ContainsKey(det.Format))
                    result.CountByFormat[det.Format] = 0;
                result.CountByFormat[det.Format]++;
            }

            return result;
        }

        public static DetectionResult DetectInModule(
            IMemoryReader driver, int pid,
            ulong moduleBase, uint moduleSize)
        {
            return Detect(driver, pid, moduleBase, moduleBase + moduleSize);
        }

        private static void ScanForFlatBuffers(byte[] data, ulong baseAddr, DetectionResult result)
        {
            for (int i = 0; i <= data.Length - 8; i++)
            {
                // Check for "BFBS" magic (FlatBuffers binary schema)
                if (i + 4 <= data.Length &&
                    data[i] == FlatBuffersMagic[0] && data[i + 1] == FlatBuffersMagic[1] &&
                    data[i + 2] == FlatBuffersMagic[2] && data[i + 3] == FlatBuffersMagic[3])
                {
                    result.Detections.Add(new FormatDetection
                    {
                        Format = SerializationFormat.FlatBuffers,
                        Address = baseAddr + (ulong)i,
                        Confidence = 0.95f,
                        Details = "FlatBuffers binary schema (BFBS magic)"
                    });
                }

                // Check for FlatBuffers file identifier
                if (i + 8 <= data.Length)
                {
                    int rootOffset = BitConverter.ToInt32(data, i);
                    if (rootOffset > 0 && rootOffset < 0x10000 && i + rootOffset + 4 <= data.Length)
                    {
                        if (data[i + 4] == FlatBuffersFileMagic[0] && data[i + 5] == FlatBuffersFileMagic[1] &&
                            data[i + 6] == FlatBuffersFileMagic[2] && data[i + 7] == FlatBuffersFileMagic[3])
                        {
                            result.Detections.Add(new FormatDetection
                            {
                                Format = SerializationFormat.FlatBuffers,
                                Address = baseAddr + (ulong)i,
                                Confidence = 0.9f,
                                Details = "FlatBuffers file (FLTB identifier)"
                            });
                        }
                    }
                }
            }
        }

        private static void ScanForProtobufMessages(byte[] data, ulong baseAddr, DetectionResult result, int maxDetections)
        {
            // Look for sequences of valid protobuf field tags
            for (int i = 0; i <= data.Length - 8; i += 4)
            {
                if (result.Detections.Count >= maxDetections) return;

                var msg = TryParseProtobuf(data, i);
                if (msg != null && msg.Fields.Count >= 3 && msg.Confidence > 0.6f)
                {
                    msg.Address = baseAddr + (ulong)i;
                    result.InferredMessages.Add(msg);
                    result.Detections.Add(new FormatDetection
                    {
                        Format = SerializationFormat.Protobuf,
                        Address = baseAddr + (ulong)i,
                        Size = msg.Size,
                        Confidence = msg.Confidence,
                        Details = $"Protobuf message ({msg.Fields.Count} fields)"
                    });
                }
            }
        }

        private static InferredMessage TryParseProtobuf(byte[] data, int offset)
        {
            var msg = new InferredMessage();
            int pos = offset;
            int maxPos = Math.Min(offset + 4096, data.Length);
            int consecutiveValid = 0;
            var seenFields = new HashSet<int>();

            while (pos < maxPos - 1)
            {
                // Read varint tag
                long tagLong = ReadVarint(data, ref pos, maxPos);
                if (tagLong < 0 || tagLong > 0x1FFFFFFF) break;
                int tag = (int)tagLong;
                if (tag <= 0) break;

                int fieldNumber = tag >> 3;
                int wireType = tag & 0x07;

                if (fieldNumber <= 0 || fieldNumber > 536870911) break;
                if (wireType > 5 || wireType == 3 || wireType == 4) break;

                string wireTypeName;
                string inferredType;
                int dataLen = 0;
                string sampleValue = "";

                switch (wireType)
                {
                    case 0: // Varint
                        wireTypeName = "varint";
                        long val = ReadVarint(data, ref pos, maxPos);
                        inferredType = val < 0 ? "sint32/sint64" : (val > int.MaxValue ? "int64/uint64" : "int32/uint32/bool/enum");
                        sampleValue = val.ToString();
                        break;

                    case 1: // 64-bit
                        wireTypeName = "64-bit";
                        if (pos + 8 > maxPos) goto done;
                        double dv = BitConverter.ToDouble(data, pos);
                        long lv = BitConverter.ToInt64(data, pos);
                        inferredType = (Math.Abs(dv) > 0.0001 && Math.Abs(dv) < 1e15 && !double.IsNaN(dv)) ? "double" : "fixed64/sfixed64";
                        sampleValue = inferredType == "double" ? dv.ToString("G6") : $"0x{lv:X}";
                        pos += 8;
                        break;

                    case 2: // Length-delimited
                        wireTypeName = "length-delimited";
                        dataLen = (int)ReadVarint(data, ref pos, maxPos);
                        if (dataLen <= 0 || dataLen > 0x100000 || pos + dataLen > maxPos) goto done;
                        inferredType = IsUtf8String(data, pos, Math.Min(dataLen, 256)) ? "string" : "bytes/embedded message";
                        if (inferredType == "string" && dataLen < 200)
                            sampleValue = Encoding.UTF8.GetString(data, pos, Math.Min(dataLen, 64));
                        pos += dataLen;
                        break;

                    case 5: // 32-bit
                        wireTypeName = "32-bit";
                        if (pos + 4 > maxPos) goto done;
                        float fv = BitConverter.ToSingle(data, pos);
                        int iv = BitConverter.ToInt32(data, pos);
                        inferredType = (Math.Abs(fv) > 0.0001f && Math.Abs(fv) < 1e10f && !float.IsNaN(fv)) ? "float" : "fixed32/sfixed32";
                        sampleValue = inferredType == "float" ? fv.ToString("G4") : $"0x{iv:X}";
                        pos += 4;
                        break;

                    default:
                        goto done;
                }

                if (seenFields.Contains(fieldNumber)) break; // Duplicate field = probably not protobuf
                seenFields.Add(fieldNumber);

                msg.Fields.Add(new ProtobufField
                {
                    FieldNumber = fieldNumber,
                    WireType = wireType,
                    WireTypeName = wireTypeName,
                    Offset = pos - offset,
                    DataLength = dataLen,
                    InferredType = inferredType,
                    SampleValue = sampleValue
                });

                consecutiveValid++;
            }

            done:
            msg.Size = pos - offset;
            msg.Confidence = consecutiveValid >= 5 ? 0.9f :
                             consecutiveValid >= 3 ? 0.7f :
                             consecutiveValid >= 2 ? 0.5f : 0.2f;

            // Additional confidence: field numbers should be mostly sequential
            if (msg.Fields.Count >= 3)
            {
                var sorted = msg.Fields.Select(f => f.FieldNumber).OrderBy(n => n).ToList();
                bool sequential = true;
                for (int i = 1; i < sorted.Count; i++)
                {
                    if (sorted[i] - sorted[i - 1] > 10) { sequential = false; break; }
                }
                if (sequential) msg.Confidence += 0.1f;
            }

            if (msg.Confidence > 1f) msg.Confidence = 1f;
            return msg;
        }

        private static long ReadVarint(byte[] data, ref int pos, int max)
        {
            long result = 0;
            int shift = 0;
            while (pos < max && shift < 64)
            {
                byte b = data[pos++];
                result |= (long)(b & 0x7F) << shift;
                if ((b & 0x80) == 0) return result;
                shift += 7;
            }
            return -1;
        }

        private static bool IsUtf8String(byte[] data, int offset, int length)
        {
            int printable = 0;
            for (int i = offset; i < offset + length && i < data.Length; i++)
            {
                byte b = data[i];
                if (b >= 0x20 && b < 0x7F) printable++;
                else if (b == 0x0A || b == 0x0D || b == 0x09) printable++;
            }
            return length > 0 && (float)printable / length > 0.8f;
        }

        private static void ScanForMessagePack(byte[] data, ulong baseAddr, DetectionResult result)
        {
            for (int i = 0; i < data.Length - 4; i++)
            {
                // Look for MessagePack map/array markers followed by valid data
                byte b = data[i];
                bool isMsgPack = false;
                string details = "";

                if ((b & 0xF0) == MsgPack_FixMap && (b & 0x0F) >= 2)
                {
                    isMsgPack = true;
                    details = $"MessagePack fixmap ({b & 0x0F} entries)";
                }
                else if (b == MsgPack_Map16 && i + 3 < data.Length)
                {
                    int count = (data[i + 1] << 8) | data[i + 2];
                    if (count >= 2 && count < 1000)
                    {
                        isMsgPack = true;
                        details = $"MessagePack map16 ({count} entries)";
                    }
                }

                if (isMsgPack)
                {
                    result.Detections.Add(new FormatDetection
                    {
                        Format = SerializationFormat.MessagePack,
                        Address = baseAddr + (ulong)i,
                        Confidence = 0.5f,
                        Details = details
                    });
                }
            }
        }

        private static void ScanForJsonXml(byte[] data, ulong baseAddr, DetectionResult result)
        {
            // Look for JSON objects or XML declarations in writable memory
            for (int i = 0; i < data.Length - 16; i++)
            {
                if (data[i] == '{' && data[i + 1] == '"')
                {
                    int end = FindJsonEnd(data, i);
                    if (end > i + 10)
                    {
                        int len = end - i;
                        result.Detections.Add(new FormatDetection
                        {
                            Format = SerializationFormat.Json,
                            Address = baseAddr + (ulong)i,
                            Size = len,
                            Confidence = 0.8f,
                            Details = $"JSON object ({len} bytes)"
                        });
                        i = end;
                    }
                }
                else if (data[i] == '<' && data[i + 1] == '?' && data[i + 2] == 'x' && data[i + 3] == 'm' && data[i + 4] == 'l')
                {
                    result.Detections.Add(new FormatDetection
                    {
                        Format = SerializationFormat.Xml,
                        Address = baseAddr + (ulong)i,
                        Confidence = 0.9f,
                        Details = "XML declaration"
                    });
                }
            }
        }

        private static int FindJsonEnd(byte[] data, int start)
        {
            int depth = 0;
            for (int i = start; i < data.Length && i < start + 0x10000; i++)
            {
                if (data[i] == '{') depth++;
                else if (data[i] == '}') { depth--; if (depth == 0) return i + 1; }
                else if (data[i] < 0x09) return -1; // invalid character
            }
            return -1;
        }

        public static string GenerateReport(DetectionResult result)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - Serialization Format Detector");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"// Regions scanned: {result.RegionsScanned}");
            sb.AppendLine($"// Total detections: {result.Detections.Count}");
            sb.AppendLine();

            if (result.CountByFormat.Count > 0)
            {
                sb.AppendLine("// Format breakdown:");
                foreach (var kvp in result.CountByFormat.OrderByDescending(k => k.Value))
                    sb.AppendLine($"//   {kvp.Key}: {kvp.Value}");
                sb.AppendLine();
            }

            foreach (var det in result.Detections.OrderByDescending(d => d.Confidence).Take(200))
            {
                sb.AppendLine($"  [{det.Format}] 0x{det.Address:X16} confidence:{det.Confidence:F2} {det.Details}");
            }

            if (result.InferredMessages.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("// Inferred Protobuf schemas:");
                foreach (var msg in result.InferredMessages.OrderByDescending(m => m.Confidence).Take(20))
                {
                    sb.AppendLine($"  message @ 0x{msg.Address:X16} ({msg.Size} bytes, confidence: {msg.Confidence:F2}):");
                    foreach (var field in msg.Fields)
                    {
                        string sample = !string.IsNullOrEmpty(field.SampleValue) ? $" = {field.SampleValue}" : "";
                        sb.AppendLine($"    field {field.FieldNumber}: {field.InferredType} ({field.WireTypeName}){sample}");
                    }
                }
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
