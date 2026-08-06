using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;

namespace KsDumperClient.Utility
{
    public static class ProcessAnalyzer
    {
        [Flags]
        public enum ProcessFlags
        {
            None = 0,
            Elevated = 1 << 0,
            Protected = 1 << 1,
            DotNet = 1 << 2,
            Service = 1 << 3,
            Console = 1 << 4,
            GUI = 1 << 5,
            AntiDebug = 1 << 6,
            StrippedHandles = 1 << 7,
            HighEntropy = 1 << 8,
            SystemProcess = 1 << 9,
            Immersive = 1 << 10,
            Secure = 1 << 11,
            Debugged = 1 << 12,
            Suspended = 1 << 13,
            // PE-level protections
            ASLR = 1 << 14,
            HighEntropyASLR = 1 << 15,
            DEP = 1 << 16,
            SEH = 1 << 17,
            CFG = 1 << 18,
            ForceIntegrity = 1 << 19,
            Packed = 1 << 20,
            Hollowed = 1 << 21
        }

        public struct ProcessAnalysis
        {
            public ProcessFlags Flags;
            public string IntegrityLevel;
            public string UserName;
            public int ThreadCount;
            public int HandleCount;
            public long WorkingSetMB;
            public double CpuTimeMs;
            public string StatusText;
        }

        public static ProcessAnalysis Analyze(int processId, string processName, string mainModulePath)
        {
            var analysis = new ProcessAnalysis();

            try
            {
                var proc = Process.GetProcessById(processId);
                analysis.ThreadCount = proc.Threads.Count;
                analysis.HandleCount = proc.HandleCount;
                analysis.WorkingSetMB = proc.WorkingSet64 / (1024 * 1024);
                analysis.CpuTimeMs = proc.TotalProcessorTime.TotalMilliseconds;

                // Detect if suspended (all threads suspended)
                if (analysis.ThreadCount > 0)
                {
                    bool allSuspended = true;
                    foreach (ProcessThread t in proc.Threads)
                    {
                        if (t.ThreadState != ThreadState.Wait || t.WaitReason != ThreadWaitReason.Suspended)
                        {
                            allSuspended = false;
                            break;
                        }
                    }
                    if (allSuspended) analysis.Flags |= ProcessFlags.Suspended;
                }

                // Detect elevation via token
                DetectElevation(processId, ref analysis);

                // Detect .NET
                if (IsDotNetProcess(proc))
                    analysis.Flags |= ProcessFlags.DotNet;

                // Detect GUI
                if (proc.MainWindowHandle != IntPtr.Zero)
                    analysis.Flags |= ProcessFlags.GUI;
                else
                    analysis.Flags |= ProcessFlags.Console;

                // Detect system process
                string sysRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLower();
                if (!string.IsNullOrEmpty(mainModulePath) &&
                    (mainModulePath.ToLower().StartsWith(sysRoot) || mainModulePath.StartsWith(@"\")))
                    analysis.Flags |= ProcessFlags.SystemProcess;

                // Detect service
                if (IsServiceProcess(processName))
                    analysis.Flags |= ProcessFlags.Service;

                // Detect anti-debug
                if (HasAntiDebug(processId))
                    analysis.Flags |= ProcessFlags.AntiDebug;

                // Detect PE-level protections from file on disk
                if (!string.IsNullOrEmpty(mainModulePath))
                    DetectPEProtections(mainModulePath, ref analysis);

                // Detect process hollowing (on-disk vs in-memory mismatch)
                if (!string.IsNullOrEmpty(mainModulePath))
                    DetectHollowing(processId, mainModulePath, ref analysis);

                // Detect stripped handles (try to open with full access)
                IntPtr hFull = OpenProcess(0x1FFFFF, false, processId);
                if (hFull == IntPtr.Zero)
                {
                    analysis.Flags |= ProcessFlags.StrippedHandles;
                }
                else
                {
                    CloseHandle(hFull);
                }

                // Detect if being debugged
                bool isDebugged;
                CheckRemoteDebuggerPresent(new IntPtr(-1), out isDebugged);
                if (isDebugged) analysis.Flags |= ProcessFlags.Debugged;
            }
            catch { }

            analysis.StatusText = BuildStatusText(analysis);
            return analysis;
        }

        private static string BuildStatusText(ProcessAnalysis a)
        {
            var parts = new List<string>();

            if ((a.Flags & ProcessFlags.Protected) != 0) parts.Add("PPL");
            if ((a.Flags & ProcessFlags.Secure) != 0) parts.Add("SECURE");
            if ((a.Flags & ProcessFlags.Elevated) != 0) parts.Add("ELEVATED");
            if ((a.Flags & ProcessFlags.StrippedHandles) != 0) parts.Add("PROTECTED");
            if ((a.Flags & ProcessFlags.AntiDebug) != 0) parts.Add("ANTI-DBG");
            if ((a.Flags & ProcessFlags.Debugged) != 0) parts.Add("DEBUGGED");
            if ((a.Flags & ProcessFlags.Suspended) != 0) parts.Add("SUSPENDED");
            if ((a.Flags & ProcessFlags.DotNet) != 0) parts.Add(".NET");
            if ((a.Flags & ProcessFlags.Packed) != 0) parts.Add("PACKED");
            if ((a.Flags & ProcessFlags.Hollowed) != 0) parts.Add("HOLLOWED");
            if ((a.Flags & ProcessFlags.ASLR) != 0) parts.Add("ASLR");
            if ((a.Flags & ProcessFlags.HighEntropyASLR) != 0) parts.Add("HE-ASLR");
            if ((a.Flags & ProcessFlags.DEP) != 0) parts.Add("DEP");
            if ((a.Flags & ProcessFlags.CFG) != 0) parts.Add("CFG");
            if ((a.Flags & ProcessFlags.ForceIntegrity) != 0) parts.Add("FORCE-INTEGRITY");

            if (parts.Count == 0)
                return (a.Flags & ProcessFlags.Service) != 0 ? "Service" :
                       (a.Flags & ProcessFlags.GUI) != 0 ? "GUI" : "Normal";

            return string.Join(", ", parts);
        }

        private static void DetectElevation(int processId, ref ProcessAnalysis analysis)
        {
            IntPtr hProc = OpenProcess(PROCESS_QUERY_INFORMATION, false, processId);
            if (hProc == IntPtr.Zero)
            {
                hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, processId);
                if (hProc == IntPtr.Zero) return;
            }

            try
            {
                IntPtr hToken;
                if (!OpenProcessToken(hProc, TOKEN_QUERY, out hToken))
                    return;

                try
                {
                    // Get elevation type
                    uint elevationType = 0;
                    uint retLen = 0;
                    GetTokenInformation(hToken, 18 /* TokenElevationType */, ref elevationType, 4, out retLen);

                    // TokenElevationTypeDefault = 1, TokenElevationTypeFull = 2, TokenElevationTypeLimited = 3
                    if (elevationType == 2)
                        analysis.Flags |= ProcessFlags.Elevated;

                    // Get integrity level
                    byte[] infoBuffer = new byte[256];
                    if (GetTokenInformation(hToken, 25 /* TokenIntegrityLevel */, infoBuffer, 256, out retLen))
                    {
                        // TOKEN_MANDATORY_LABEL structure: SID_AND_ATTRIBUTES Sid + DWORD
                        // The SID is at the start, the RID (last sub-authority) determines integrity
                        IntPtr pSid = Marshal.ReadIntPtr(infoBuffer, 0);
                        if (pSid != IntPtr.Zero)
                        {
                            int subAuthCount = Marshal.ReadByte(pSid, 1);
                            if (subAuthCount > 0)
                            {
                                uint rid = (uint)Marshal.ReadInt32(pSid, 8 + (subAuthCount - 1) * 4);
                                if (rid >= 0x4000) analysis.IntegrityLevel = "System";
                                else if (rid >= 0x3000) analysis.IntegrityLevel = "High";
                                else if (rid >= 0x2000) analysis.IntegrityLevel = "Medium";
                                else if (rid >= 0x1000) analysis.IntegrityLevel = "Low";
                                else analysis.IntegrityLevel = "Untrusted";
                            }
                        }
                    }

                    // Get token user name
                    byte[] userBuffer = new byte[512];
                    if (GetTokenInformation(hToken, 1 /* TokenUser */, userBuffer, 512, out retLen))
                    {
                        IntPtr pUserSid = Marshal.ReadIntPtr(userBuffer, 0);
                        if (pUserSid != IntPtr.Zero)
                        {
                            IntPtr pName = IntPtr.Zero;
                            IntPtr pDomain = IntPtr.Zero;
                            uint nameLen = 0, domainLen = 0;
                            int sidUse = 0;

                            LookupAccountSid(null, pUserSid, pName, ref nameLen, pDomain, ref domainLen, ref sidUse);
                            if (nameLen > 0)
                            {
                                pName = Marshal.AllocHGlobal((int)nameLen * 2);
                                pDomain = Marshal.AllocHGlobal((int)domainLen * 2);
                                try
                                {
                                    if (LookupAccountSid(null, pUserSid, pName, ref nameLen, pDomain, ref domainLen, ref sidUse))
                                    {
                                        analysis.UserName = Marshal.PtrToStringUni(pName);
                                    }
                                }
                                finally
                                {
                                    Marshal.FreeHGlobal(pName);
                                    Marshal.FreeHGlobal(pDomain);
                                }
                            }
                        }
                    }
                }
                finally
                {
                    CloseHandle(hToken);
                }
            }
            finally
            {
                CloseHandle(hProc);
            }
        }

        private static bool IsDotNetProcess(Process proc)
        {
            try
            {
                foreach (ProcessModule mod in proc.Modules)
                {
                    string name = mod.ModuleName.ToLower();
                    if (name == "mscoree.dll" || name == "clr.dll" || name == "coreclr.dll" ||
                        name == "mscorlib.dll" || name == "mscorlib.ni.dll" ||
                        name == "clrjit.dll" || name == "mscorwks.dll")
                        return true;
                }
            }
            catch { }
            return false;
        }

        private static bool IsServiceProcess(string processName)
        {
            string lower = processName.ToLower();
            // Common service processes
            return lower == "svchost.exe" || lower == "services.exe" ||
                   lower == "lsass.exe" || lower == "wininit.exe" ||
                   lower == "csrss.exe" || lower == "smss.exe" ||
                   lower == "spoolsv.exe" || lower == "dllhost.exe";
        }

        private static bool HasAntiDebug(int processId)
        {
            IntPtr hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, processId);
            if (hProc == IntPtr.Zero) return false;

            try
            {
                // Check NtGlobalFlag (anti-debug indicator)
                // For x64: PEB+0xBC contains NtGlobalFlag
                // If FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
                // are set (0x70), process is likely being debugged
                // This is a heuristic, not 100% reliable
                return false; // Simplified - full check would need PEB reading
            }
            finally
            {
                CloseHandle(hProc);
            }
        }

        /// <summary>
        /// Reads the PE file from disk and checks DllCharacteristics for security features.
        /// Also detects common packers (UPX, Themida, VMProtect) via section name analysis.
        /// </summary>
        private static void DetectPEProtections(string filePath, ref ProcessAnalysis analysis)
        {
            try
            {
                if (!System.IO.File.Exists(filePath)) return;

                using (var fs = new System.IO.FileStream(filePath, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.ReadWrite))
                {
                    // Read first 4KB (enough for DOS + PE headers + section table)
                    byte[] header = new byte[4096];
                    int bytesRead = fs.Read(header, 0, 4096);
                    if (bytesRead < 64) return;

                    // Validate DOS header
                    if (BitConverter.ToUInt16(header, 0) != 0x5A4D) return;
                    int e_lfanew = BitConverter.ToInt32(header, 60);
                    if (e_lfanew <= 0 || e_lfanew + 24 > bytesRead) return;

                    // Validate PE signature
                    if (BitConverter.ToUInt32(header, e_lfanew) != 0x00004550) return;

                    // File Header
                    ushort numSections = BitConverter.ToUInt16(header, e_lfanew + 6);
                    ushort sizeOfOptHdr = BitConverter.ToUInt16(header, e_lfanew + 20);

                    // Optional Header
                    int optHdrOffset = e_lfanew + 24;
                    if (optHdrOffset + 2 > bytesRead) return;
                    ushort magic = BitConverter.ToUInt16(header, optHdrOffset);
                    bool is64 = magic == 0x20b;

                    // DllCharacteristics offset: PE32 = optHdr+70, PE32+ = optHdr+70
                    int dllCharsOffset = optHdrOffset + 70;
                    if (dllCharsOffset + 2 > bytesRead) return;
                    ushort dllChars = BitConverter.ToUInt16(header, dllCharsOffset);

                    // Check security flags
                    if ((dllChars & 0x0040) != 0) analysis.Flags |= ProcessFlags.ASLR;           // IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
                    if ((dllChars & 0x0020) != 0) analysis.Flags |= ProcessFlags.HighEntropyASLR;  // IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
                    if ((dllChars & 0x0100) != 0) analysis.Flags |= ProcessFlags.DEP;              // IMAGE_DLLCHARACTERISTICS_NX_COMPAT
                    if ((dllChars & 0x0400) != 0) analysis.Flags |= ProcessFlags.SEH;              // IMAGE_DLLCHARACTERISTICS_NO_SEH (inverted: present means NO SEH)
                    if ((dllChars & 0x4000) != 0) analysis.Flags |= ProcessFlags.CFG;              // IMAGE_DLLCHARACTERISTICS_GUARD_CF
                    if ((dllChars & 0x0080) != 0) analysis.Flags |= ProcessFlags.ForceIntegrity;   // IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY

                    // Packer detection via section names
                    int sectionTableOffset = optHdrOffset + sizeOfOptHdr;
                    var sectionNames = new List<string>();

                    for (int i = 0; i < numSections && sectionTableOffset + (i + 1) * 40 <= bytesRead; i++)
                    {
                        int secOff = sectionTableOffset + i * 40;
                        string name = System.Text.Encoding.ASCII.GetString(header, secOff, 8).TrimEnd('\0');
                        sectionNames.Add(name);
                    }

                    // UPX detection: sections named UPX0, UPX1, UPX2
                    if (sectionNames.Any(n => n.StartsWith("UPX", StringComparison.OrdinalIgnoreCase)))
                        analysis.Flags |= ProcessFlags.Packed;

                    // Themida/WinLicense: section named .themida or .winlic
                    if (sectionNames.Any(n => n.Contains(".themida") || n.Contains(".winlic")))
                        analysis.Flags |= ProcessFlags.Packed;

                    // VMProtect: section named .vmp
                    if (sectionNames.Any(n => n.Contains(".vmp")))
                        analysis.Flags |= ProcessFlags.Packed;

                    // PECompact: section named PEC2
                    if (sectionNames.Any(n => n.Contains("PEC2")))
                        analysis.Flags |= ProcessFlags.Packed;

                    // Generic packer heuristic: only 1-2 sections with high raw size but small virtual size
                    // or sections with entropy > 7.0 (not computed here, but unusual section counts are a signal)
                    if (numSections <= 2 && sectionNames.Any(n => !n.StartsWith(".")))
                        analysis.Flags |= ProcessFlags.Packed;
                }
            }
            catch { }
        }

        /// <summary>
        /// Detects process hollowing by comparing the on-disk PE entry point and section
        /// hashes with the in-memory PE. Hollowed processes have different entry points
        /// and/or modified code sections compared to the file on disk.
        /// </summary>
        private static void DetectHollowing(int processId, string mainModulePath, ref ProcessAnalysis analysis)
        {
            try
            {
                if (!System.IO.File.Exists(mainModulePath)) return;

                IntPtr hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, processId);
                if (hProc == IntPtr.Zero) return;

                try
                {
                    // Get the base address of the main module in memory
                    IntPtr hModule = IntPtr.Zero;
                    try
                    {
                        var mainModule = Process.GetProcessById(processId).MainModule;
                        if (mainModule != null) hModule = mainModule.BaseAddress;
                    }
                    catch { return; }

                    if (hModule == IntPtr.Zero) return;

                    // Read on-disk PE headers
                    byte[] diskHeaders = new byte[4096];
                    using (var fs = new System.IO.FileStream(mainModulePath, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.ReadWrite))
                    {
                        fs.Read(diskHeaders, 0, 4096);
                    }

                    // Read in-memory PE headers
                    byte[] memHeaders = new byte[4096];
                    if (!ReadProcessMemory(hProc, hModule, memHeaders, 4096, out _))
                        return;

                    // Validate both are valid PEs
                    if (BitConverter.ToUInt16(diskHeaders, 0) != 0x5A4D) return;
                    if (BitConverter.ToUInt16(memHeaders, 0) != 0x5A4D) return;

                    int diskLfane = BitConverter.ToInt32(diskHeaders, 60);
                    int memLfane = BitConverter.ToInt32(memHeaders, 60);

                    if (diskLfane <= 0 || memLfane <= 0) return;
                    if (BitConverter.ToUInt32(diskHeaders, diskLfane) != 0x00004550) return;
                    if (BitConverter.ToUInt32(memHeaders, memLfane) != 0x00004550) return;

                    // Compare entry points (AddressOfEntryPoint at optional header + 16)
                    int diskEntryOff = diskLfane + 24 + 16;
                    int memEntryOff = memLfane + 24 + 16;
                    if (diskEntryOff + 4 > 4096 || memEntryOff + 4 > 4096) return;

                    uint diskEntry = BitConverter.ToUInt32(diskHeaders, diskEntryOff);
                    uint memEntry = BitConverter.ToUInt32(memHeaders, memEntryOff);

                    // If entry points differ significantly, likely hollowed
                    if (diskEntry != memEntry)
                    {
                        analysis.Flags |= ProcessFlags.Hollowed;
                        return;
                    }

                    // Compare section headers (name, virtual size, characteristics)
                    ushort diskNumSections = BitConverter.ToUInt16(diskHeaders, diskLfane + 6);
                    ushort memNumSections = BitConverter.ToUInt16(memHeaders, memLfane + 6);

                    if (diskNumSections != memNumSections)
                    {
                        analysis.Flags |= ProcessFlags.Hollowed;
                        return;
                    }

                    ushort diskOptHdrSize = BitConverter.ToUInt16(diskHeaders, diskLfane + 20);
                    int diskSecTableOff = diskLfane + 24 + diskOptHdrSize;
                    ushort memOptHdrSize = BitConverter.ToUInt16(memHeaders, memLfane + 20);
                    int memSecTableOff = memLfane + 24 + memOptHdrSize;

                    for (int i = 0; i < diskNumSections; i++)
                    {
                        int diskSecOff = diskSecTableOff + i * 40;
                        int memSecOff = memSecTableOff + i * 40;
                        if (diskSecOff + 40 > 4096 || memSecOff + 40 > 4096) break;

                        // Compare section names
                        string diskName = System.Text.Encoding.ASCII.GetString(diskHeaders, diskSecOff, 8);
                        string memName = System.Text.Encoding.ASCII.GetString(memHeaders, memSecOff, 8);

                        if (diskName != memName)
                        {
                            analysis.Flags |= ProcessFlags.Hollowed;
                            return;
                        }

                        // Compare section characteristics (executable sections should match)
                        uint diskChars = BitConverter.ToUInt32(diskHeaders, diskSecOff + 36);
                        uint memChars = BitConverter.ToUInt32(memHeaders, memSecOff + 36);

                        // If a non-executable section became executable, suspicious
                        if ((diskChars & 0x20000000) == 0 && (memChars & 0x20000000) != 0)
                        {
                            analysis.Flags |= ProcessFlags.Hollowed;
                            return;
                        }
                    }

                    // Compare first 256 bytes of .text section (code hash)
                    // Find .text section offset in both
                    for (int i = 0; i < diskNumSections; i++)
                    {
                        int diskSecOff = diskSecTableOff + i * 40;
                        int memSecOff = memSecTableOff + i * 40;
                        if (diskSecOff + 40 > 4096) break;

                        string name = System.Text.Encoding.ASCII.GetString(diskHeaders, diskSecOff, 8).TrimEnd('\0');
                        if (name == ".text" || (BitConverter.ToUInt32(diskHeaders, diskSecOff + 36) & 0x20000000) != 0)
                        {
                            uint diskRawPtr = BitConverter.ToUInt32(diskHeaders, diskSecOff + 20);
                            uint memRawPtr = BitConverter.ToUInt32(memHeaders, memSecOff + 20);
                            int compareSize = 256;

                            if (diskRawPtr + compareSize > diskHeaders.Length) break;

                            // Read in-memory .text section start
                            byte[] memCode = new byte[compareSize];
                            if (ReadProcessMemory(hProc, (IntPtr)((long)hModule + memRawPtr), memCode, compareSize, out _))
                            {
                                // Compare with on-disk
                                int mismatches = 0;
                                for (int j = 0; j < compareSize; j++)
                                {
                                    if (diskRawPtr + j < diskHeaders.Length && diskHeaders[diskRawPtr + j] != memCode[j])
                                        mismatches++;
                                }

                                // If more than 10% of bytes differ, likely hollowed
                                if (mismatches > compareSize / 10)
                                {
                                    analysis.Flags |= ProcessFlags.Hollowed;
                                    return;
                                }
                            }
                            break;
                        }
                    }
                }
                finally
                {
                    CloseHandle(hProc);
                }
            }
            catch { }
        }

        // ---- P/Invoke ----

        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        private const uint PROCESS_VM_READ = 0x0010;
        private const uint TOKEN_QUERY = 0x0008;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass,
            byte[] TokenInformation, uint TokenInformationLength, out uint ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass,
            ref uint TokenInformation, uint TokenInformationLength, out uint ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LookupAccountSid(string lpSystemName, IntPtr Sid,
            IntPtr Name, ref uint cchName, IntPtr ReferencedDomainName, ref uint cchReferencedDomainName, ref int peUse);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbDebuggerPresent);
    }
}
