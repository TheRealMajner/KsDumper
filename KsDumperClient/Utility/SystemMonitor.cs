using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace KsDumperClient.Utility
{
    public class SystemMonitor : IDisposable
    {
        public struct ProcessStats
        {
            public double CpuPercent;
            public long WorkingSetMB;
            public long PrivateBytesMB;
            public int HandleCount;
            public int ThreadCount;
            public long IoReadMB;
            public long IoWriteMB;
        }

        private ulong lastKernelTime;
        private ulong lastUserTime;
        private DateTime lastSampleTime;
        private int lastProcessId;

        public ProcessStats Sample(int processId)
        {
            var stats = new ProcessStats();

            try
            {
                // Use Process class for memory, handles, threads (reliable)
                var proc = Process.GetProcessById(processId);
                proc.Refresh();

                stats.WorkingSetMB = proc.WorkingSet64 / (1024 * 1024);
                stats.PrivateBytesMB = proc.PrivateMemorySize64 / (1024 * 1024);
                stats.HandleCount = proc.HandleCount;

                try { stats.ThreadCount = proc.Threads.Count; } catch { }

                // CPU % via direct P/Invoke GetProcessTimes
                IntPtr hProcess = IntPtr.Zero;
                try
                {
                    // Try multiple access levels
                    hProcess = OpenProcess(0x0400, false, processId); // PROCESS_QUERY_INFORMATION
                    if (hProcess == IntPtr.Zero)
                        hProcess = OpenProcess(0x1000, false, processId); // PROCESS_QUERY_LIMITED_INFORMATION
                    if (hProcess == IntPtr.Zero)
                        hProcess = proc.Handle; // Fallback to Process class handle

                    if (hProcess != IntPtr.Zero)
                    {
                        FILETIME createTime, exitTime, kernelTime, userTime;
                        if (GetProcessTimes(hProcess, out createTime, out exitTime, out kernelTime, out userTime))
                        {
                            ulong currentKernel = ((ulong)kernelTime.dwHighDateTime << 32) | kernelTime.dwLowDateTime;
                            ulong currentUser = ((ulong)userTime.dwHighDateTime << 32) | userTime.dwLowDateTime;
                            var now = DateTime.UtcNow;

                            if (lastSampleTime != default && lastProcessId == processId)
                            {
                                ulong kernelDelta = currentKernel - lastKernelTime;
                                ulong userDelta = currentUser - lastUserTime;
                                ulong totalDelta = kernelDelta + userDelta;

                                double elapsedMs = (now - lastSampleTime).TotalMilliseconds;
                                if (elapsedMs > 10) // Need at least 10ms between samples
                                {
                                    // FILETIME units are 100-nanosecond intervals
                                    // Convert delta to milliseconds: totalDelta / 10000
                                    double cpuMs = (double)totalDelta / 10000.0;
                                    stats.CpuPercent = cpuMs / elapsedMs * 100.0;
                                    // Cap at 100% per core * number of cores
                                    if (stats.CpuPercent > 100.0 * Environment.ProcessorCount)
                                        stats.CpuPercent = 100.0 * Environment.ProcessorCount;
                                }
                            }

                            lastKernelTime = currentKernel;
                            lastUserTime = currentUser;
                            lastSampleTime = now;
                            lastProcessId = processId;
                        }

                        // I/O counters
                        IO_COUNTERS ioCounters;
                        if (GetProcessIoCounters(hProcess, out ioCounters))
                        {
                            stats.IoReadMB = (long)(ioCounters.ReadTransferCount / (1024 * 1024));
                            stats.IoWriteMB = (long)(ioCounters.WriteTransferCount / (1024 * 1024));
                        }
                    }
                }
                finally
                {
                    // Only close if we opened it ourselves (not proc.Handle)
                    if (hProcess != IntPtr.Zero && hProcess != proc.Handle)
                        CloseHandle(hProcess);
                }
            }
            catch
            {
                // Process may have exited
            }

            return stats;
        }

        public void Dispose() { }

        // ==================== P/Invoke ====================

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetProcessTimes(IntPtr hProcess,
            out FILETIME lpCreationTime, out FILETIME lpExitTime,
            out FILETIME lpKernelTime, out FILETIME lpUserTime);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetProcessIoCounters(IntPtr hProcess, out IO_COUNTERS lpIoCounters);

        [StructLayout(LayoutKind.Sequential)]
        private struct FILETIME
        {
            public uint dwLowDateTime;
            public uint dwHighDateTime;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IO_COUNTERS
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }
    }
}
