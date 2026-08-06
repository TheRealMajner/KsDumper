using System;
using System.IO;
using System.Text;

namespace KsDumperClient.Utility
{
    public static class MemoryMapDumper
    {
        // Protection flags for display
        private static string ProtectToString(uint protect)
        {
            string result = "";
            if ((protect & 0x01) != 0) result += "NC ";  // PAGE_NOACCESS
            if ((protect & 0x02) != 0) result += "R ";   // PAGE_READONLY
            if ((protect & 0x04) != 0) result += "RW ";  // PAGE_READWRITE
            if ((protect & 0x08) != 0) result += "WC ";  // PAGE_WRITECOPY
            if ((protect & 0x10) != 0) result += "X ";   // PAGE_EXECUTE
            if ((protect & 0x20) != 0) result += "RX ";  // PAGE_EXECUTE_READ
            if ((protect & 0x40) != 0) result += "RWX "; // PAGE_EXECUTE_READWRITE
            if ((protect & 0x80) != 0) result += "XWC "; // PAGE_EXECUTE_WRITECOPY
            if ((protect & 0x100) != 0) result += "G ";  // PAGE_GUARD
            if ((protect & 0x200) != 0) result += "NC "; // PAGE_NOCACHE
            if ((protect & 0x400) != 0) result += "WC "; // PAGE_WRITECOMBINE
            return result.Trim();
        }

        private static string TypeToString(uint type)
        {
            if (type == 0x20000) return "PRIVATE";
            if (type == 0x40000) return "MAPPED";
            if (type == 0x1000000) return "IMAGE";
            return $"0x{type:x}";
        }

        private static string FormatSize(ulong size)
        {
            if (size >= 0x100000) return $"{size / 0x100000}MB";
            if (size >= 0x1000) return $"{size / 0x1000}KB";
            return $"{size}B";
        }

        public static void Save(string outputPath,
            System.Collections.Generic.List<(ulong baseAddress, ulong regionSize, uint protect, uint state, uint type)> regions,
            string processName, int processId)
        {
            using (var writer = new StreamWriter(outputPath, false, Encoding.UTF8))
            {
                writer.WriteLine($"// KsDumper - Process Memory Map");
                writer.WriteLine($"// Process: {processName} (PID: {processId})");
                writer.WriteLine($"// Regions: {regions.Count}");
                writer.WriteLine($"// Generated: {DateTime.Now}");
                writer.WriteLine();
                writer.WriteLine($"{"Base Address",-20} {"Size",-12} {"Protect",-12} {"Type",-10}");
                writer.WriteLine(new string('-', 60));

                ulong totalSize = 0;
                int imageCount = 0, mappedCount = 0, privateCount = 0;

                foreach (var (baseAddr, size, protect, state, type) in regions)
                {
                    string typeStr = TypeToString(type);
                    string protStr = ProtectToString(protect);
                    string sizeStr = FormatSize(size);

                    writer.WriteLine($"0x{baseAddr:X16} {sizeStr,-12} {protStr,-12} {typeStr,-10}");

                    totalSize += size;
                    if (type == 0x1000000) imageCount++;
                    else if (type == 0x40000) mappedCount++;
                    else if (type == 0x20000) privateCount++;
                }

                writer.WriteLine();
                writer.WriteLine($"// Summary:");
                writer.WriteLine($"// Total committed: {FormatSize(totalSize)}");
                writer.WriteLine($"// IMAGE regions: {imageCount}");
                writer.WriteLine($"// MAPPED regions: {mappedCount}");
                writer.WriteLine($"// PRIVATE regions: {privateCount}");
            }
        }
    }
}
