using System;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security;
using KsDumperClient.Driver;
using KsDumperClient.PE;
using KsDumperClient.Utility;

using static KsDumperClient.PE.NativePEStructs;

namespace KsDumperClient
{
    public class ProcessDumper
    {
        private IMemoryReader kernelDriver;

        public ProcessDumper(IMemoryReader kernelDriver)
        {
            this.kernelDriver = kernelDriver;
        }

        [HandleProcessCorruptedStateExceptions]
        [SecurityCritical]
        public bool DumpProcess(ProcessSummary processSummary, out PEFile outputFile, bool rebuildImports = false, bool suspendBeforeDump = false)
        {
            IntPtr basePointer = (IntPtr)processSummary.MainModuleBase;
            outputFile = default(PEFile);
            bool suspended = false;

            Logger.SkipLine();
            Logger.Log("Targeting Process: {0} ({1})", processSummary.ProcessName, processSummary.ProcessId);

            if (suspendBeforeDump)
            {
                int suspendedCount = kernelDriver.SuspendProcess(processSummary.ProcessId);
                if (suspendedCount >= 0)
                {
                    suspended = true;
                    Logger.Log("Suspended {0} threads before dump", suspendedCount);
                }
                else
                {
                    Logger.Log("Warning: failed to suspend process, continuing anyway");
                }
            }

            try
            {

            IMAGE_DOS_HEADER dosHeader = ReadProcessStruct<IMAGE_DOS_HEADER>(processSummary.ProcessId, basePointer);

            if (dosHeader.IsValid)
            {
                IntPtr peHeaderPointer = basePointer + dosHeader.e_lfanew;
                Logger.Log("PE Header Found: 0x{0:x8}", peHeaderPointer.ToInt64());

                IntPtr dosStubPointer = basePointer + Marshal.SizeOf<IMAGE_DOS_HEADER>();
                int dosStubSize = dosHeader.e_lfanew - Marshal.SizeOf<IMAGE_DOS_HEADER>();
                byte[] dosStub = dosStubSize > 0 ? ReadProcessBytes(processSummary.ProcessId, dosStubPointer, dosStubSize) : new byte[0];

                PEFile peFile;

                if (!processSummary.IsWOW64)
                {
                    peFile = Dump64BitPE(processSummary.ProcessId, dosHeader, dosStub, peHeaderPointer);
                }
                else
                {
                    peFile = Dump32BitPE(processSummary.ProcessId, dosHeader, dosStub, peHeaderPointer);
                }

                if (peFile != default(PEFile))
                {
                    IntPtr sectionHeaderPointer = peHeaderPointer + peFile.GetFirstSectionHeaderOffset();
                    
                    Logger.Log("Header is valid ({0}) !", peFile.Type);
                    Logger.Log("Parsing {0} Sections...", peFile.Sections.Length);

                    for (int i = 0; i < peFile.Sections.Length; i++)
                    {
                        IMAGE_SECTION_HEADER sectionHeader = ReadProcessStruct<IMAGE_SECTION_HEADER>(processSummary.ProcessId, sectionHeaderPointer);
                        peFile.Sections[i] = new PESection
                        {
                            Header = PESection.PESectionHeader.FromNativeStruct(sectionHeader),
                            InitialSize = (int)sectionHeader.VirtualSize
                        };

                        ReadSectionContent(processSummary.ProcessId, new IntPtr(basePointer.ToInt64() + sectionHeader.VirtualAddress), peFile.Sections[i]);
                        sectionHeaderPointer += Marshal.SizeOf<IMAGE_SECTION_HEADER>();
                    }

                    Logger.Log("Aligning Sections...");
                    peFile.AlignSectionHeaders();

                    Logger.Log("Fixing PE Header...");
                    peFile.FixPEHeader();

                    if (rebuildImports)
                    {
                        Logger.Log("Rebuilding Import Table...");
                        try
                        {
                            var exportMap = kernelDriver.GetExportMap(processSummary.ProcessId);
                            if (exportMap.Count > 0)
                            {
                                var rebuilder = new ImportRebuilder();
                                var report = rebuilder.DoRebuild(peFile, exportMap, processSummary.MainModuleBase);
                                Logger.Log("Import rebuild: {0} total, {1} by name, {2} by ordinal, {3} from INT, {4} delay-load, {5} unresolved, {6} DLLs, {7} forwarders, {8} API sets",
                                    report.TotalImports, report.ResolvedByName, report.ResolvedByOrdinal,
                                    report.ResolvedFromINT, report.ResolvedFromDelayLoad,
                                    report.Unresolved, report.DllsReferenced, report.Forwarders, report.ApiSetsResolved);
                                foreach (var warning in report.Warnings)
                                    Logger.Log("  Warning: {0}", warning);
                            }
                            else
                            {
                                Logger.Log("Import rebuild: no exports found in target process");
                            }
                        }
                        catch (Exception ex)
                        {
                            Logger.Log("Import rebuild error: {0}", ex.Message);
                        }
                    }

                    // IDA Pro optimization: clean up headers and normalize ImageBase
                    Logger.Log("Optimizing PE for IDA Pro...");
                    try
                    {
                        PEAnalyzer.CleanupForIDA(peFile);
                        PEAnalyzer.NormalizeImageBase(peFile);
                    }
                    catch (Exception ex)
                    {
                        Logger.Log("PE optimization error (non-fatal): {0}", ex.Message);
                    }

                    try
                    {
                        var importStats = PEAnalyzer.GetImportStats(peFile);
                        double resolvePct = importStats.total > 0 ? (100.0 * importStats.resolved / importStats.total) : 0;
                        Logger.Log("Imports: {0} total, {1} resolved ({2:F0}%) across {3} DLLs",
                            importStats.total, importStats.resolved, resolvePct, importStats.dllCount);
                    }
                    catch (Exception ex)
                    {
                        Logger.Log("Import stats error (non-fatal): {0}", ex.Message);
                    }

                    try
                    {
                        var rttiClasses = PEAnalyzer.ScanRTTI(peFile);
                        if (rttiClasses.Count > 0)
                            Logger.Log("RTTI: found {0} C++ classes", rttiClasses.Count);

                        var vtables = PEAnalyzer.FindVTables(peFile, processSummary.MainModuleBase);
                        if (vtables.Count > 0)
                            Logger.Log("VTables: found {0} virtual method tables", vtables.Count);
                    }
                    catch (Exception ex)
                    {
                        Logger.Log("RTTI/VTable scan error (non-fatal): {0}", ex.Message);
                    }

                    Logger.Log("Dump Completed !");
                    outputFile = peFile;
                    return true;
                }
                else
                {
                    Logger.Log("Bad PE Header !");
                }
            }
            return false;

            } // end try
            finally
            {
                if (suspended)
                {
                    int resumedCount = kernelDriver.ResumeProcess(processSummary.ProcessId);
                    if (resumedCount >= 0)
                        Logger.Log("Resumed {0} threads after dump", resumedCount);
                }
            }
        }

        private PEFile Dump64BitPE(int processId, IMAGE_DOS_HEADER dosHeader, byte[] dosStub, IntPtr peHeaderPointer)
        {
            IMAGE_NT_HEADERS64 peHeader = ReadProcessStruct<IMAGE_NT_HEADERS64>(processId, peHeaderPointer);

            if (peHeader.IsValid)
            {
                return new PE64File(dosHeader, peHeader, dosStub);
            }
            return default(PEFile);
        }

        private PEFile Dump32BitPE(int processId, IMAGE_DOS_HEADER dosHeader, byte[] dosStub, IntPtr peHeaderPointer)
        {
            IMAGE_NT_HEADERS32 peHeader = ReadProcessStruct<IMAGE_NT_HEADERS32>(processId, peHeaderPointer);

            if (peHeader.IsValid)
            {
                return new PE32File(dosHeader, peHeader, dosStub);
            }
            return default(PEFile);
        }

        private T ReadProcessStruct<T>(int processId, IntPtr address) where T : struct
        {
            int size = Marshal.SizeOf<T>();
            IntPtr buffer = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)size,
                WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
            if (buffer == IntPtr.Zero) return default(T);
            try
            {
                if (kernelDriver.CopyVirtualMemory(processId, address, buffer, size))
                {
                    return Marshal.PtrToStructure<T>(buffer);
                }
                return default(T);
            }
            finally
            {
                WinApi.VirtualFree(buffer, UIntPtr.Zero, WinApi.MEM_RELEASE);
            }
        }

        private bool ReadSectionContent(int processId, IntPtr sectionPointer, PESection section)
        {
            const int maxReadSize = 100;
            int readSize = section.InitialSize;

            if (sectionPointer == IntPtr.Zero || readSize == 0)
            {
                return true;
            }

            if (readSize <= maxReadSize)
            {
                section.DataSize = readSize;
                section.Content = ReadProcessBytes(processId, sectionPointer, readSize);

                return true;
            }
            else
            {
                CalculateRealSectionSize(processId, sectionPointer, section);

                if (section.DataSize != 0)
                {
                    section.Content = ReadProcessBytes(processId, sectionPointer, section.DataSize);
                    return true;
                }
            }
            return false;
        }

        private byte[] ReadProcessBytes(int processId, IntPtr address, int size)
        {
            IntPtr unmanagedBytePointer = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)size,
                WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
            if (unmanagedBytePointer == IntPtr.Zero)
                return new byte[size];

            kernelDriver.CopyVirtualMemory(processId, address, unmanagedBytePointer, size);

            byte[] buffer = new byte[size];
            Marshal.Copy(unmanagedBytePointer, buffer, 0, size);
            WinApi.VirtualFree(unmanagedBytePointer, UIntPtr.Zero, WinApi.MEM_RELEASE);

            return buffer;
        }

        private void CalculateRealSectionSize(int processId, IntPtr sectionPointer, PESection section)
        {
            const int maxReadSize = 100;
            int readSize = section.InitialSize;
            int currentReadSize = readSize % maxReadSize;

            if (currentReadSize == 0)
            {
                currentReadSize = maxReadSize;
            }
            IntPtr currentOffset = sectionPointer + readSize - currentReadSize;

            while (currentOffset.ToInt64() >= sectionPointer.ToInt64())
            {
                byte[] buffer = ReadProcessBytes(processId, currentOffset, currentReadSize);
                int codeByteCount = GetInstructionByteCount(buffer);

                if (codeByteCount != 0)
                {
                    currentOffset += codeByteCount;

                    if (sectionPointer.ToInt64() < currentOffset.ToInt64())
                    {
                        section.DataSize = (int)(currentOffset.ToInt64() - sectionPointer.ToInt64());
                        section.DataSize += 4;

                        if (section.InitialSize < section.DataSize)
                        {
                            section.DataSize = section.InitialSize;
                        }
                    }
                    break;
                }

                currentReadSize = maxReadSize;
                currentOffset -= currentReadSize;
            }
        }
        
        private int GetInstructionByteCount(byte[] dataBlock)
        {
            for (int i = (dataBlock.Length - 1); i >= 0; i--)
            {
                if (dataBlock[i] != 0)
                {
                    return i + 1;
                }
            }
            return 0;
        }
    }
}
