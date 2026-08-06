using System;
using System.IO;
using System.Text;

namespace KsDumperClient
{
    public class ModuleSummary
    {
        public int ProcessId { get; private set; }
        public ulong BaseAddress { get; private set; }
        public ulong EntryPoint { get; private set; }
        public uint ImageSize { get; private set; }
        public string FileName { get; private set; }
        public string ModuleName { get; private set; }
        public bool IsHidden { get; private set; }

        private ModuleSummary(int processId, ulong baseAddress, ulong entryPoint, uint imageSize, string fileName, bool isHidden)
        {
            ProcessId = processId;
            BaseAddress = baseAddress;
            EntryPoint = entryPoint;
            ImageSize = imageSize;
            FileName = fileName;
            ModuleName = string.IsNullOrEmpty(fileName) ? $"Hidden Module @ 0x{baseAddress:x}" : Path.GetFileName(fileName);
            IsHidden = isHidden;
        }

        public static ModuleSummary FromStream(BinaryReader reader, string[] knownPEBModules)
        {
            int processId = reader.ReadInt32();
            ulong baseAddress = reader.ReadUInt64();
            ulong entryPoint = reader.ReadUInt64();
            uint imageSize = reader.ReadUInt32();
            string fileName = Encoding.Unicode.GetString(reader.ReadBytes(512)).Split('\0')[0];
            bool isHidden = reader.ReadBoolean();

            return new ModuleSummary(processId, baseAddress, entryPoint, imageSize, fileName, isHidden);
        }

        public static ModuleSummary Create(int processId, ulong baseAddress, ulong entryPoint, uint imageSize, string fileName, bool isHidden)
        {
            return new ModuleSummary(processId, baseAddress, entryPoint, imageSize, fileName, isHidden);
        }
    }
}
