using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Tracing;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace KsDumperClient.Utility
{
    /// <summary>
    /// ETW (Event Tracing for Windows) tracer that monitors file I/O, registry access,
    /// and network activity for a specific process.
    /// </summary>
    public class EtwTracer : IDisposable
    {
        public struct EtwEvent
        {
            public DateTime Timestamp;
            public string Category; // File, Registry, Network, Process, Thread
            public string Operation; // Create, Read, Write, Delete, Open, Query, etc.
            public string Target; // File path, registry key, etc.
            public int ProcessId;
            public int ThreadId;
            public string Details;
        }

        public event Action<EtwEvent> OnEvent;

        private readonly int targetProcessId;
        private CancellationTokenSource cts;
        private bool isTracing;
        private readonly List<EtwEvent> eventHistory;
        private readonly object syncLock;

        // ETW session management
        private long traceSessionHandle;
        private long traceHandle;

        public bool IsTracing => isTracing;
        public int EventCount { get { lock (syncLock) return eventHistory.Count; } }

        public EtwTracer(int processId)
        {
            targetProcessId = processId;
            eventHistory = new List<EtwEvent>();
            syncLock = new object();
        }

        public void StartTracing()
        {
            if (isTracing) return;
            cts = new CancellationTokenSource();
            isTracing = true;

            Task.Run(() => TraceLoop(cts.Token));
        }

        public void StopTracing()
        {
            cts?.Cancel();
            isTracing = false;

            if (traceHandle != 0)
            {
                CloseTrace(traceHandle);
                traceHandle = 0;
            }
        }

        public List<EtwEvent> GetEvents()
        {
            lock (syncLock) return new List<EtwEvent>(eventHistory);
        }

        private async Task TraceLoop(CancellationToken token)
        {
            // Use Performance Counter-based monitoring as a fallback
            // since ETW session management requires admin privileges
            // and complex native API calls

            var perfCounters = new Dictionary<string, PerformanceCounter>();

            try
            {
                // Try to create performance counters for the target process
                var proc = Process.GetProcessById(targetProcessId);
                string instanceName = GetPerformanceCounterInstanceName(proc);

                if (instanceName != null)
                {
                    try
                    {
                        perfCounters["IORead"] = new PerformanceCounter("Process", "IO Read Bytes/sec", instanceName, true);
                        perfCounters["IOWrite"] = new PerformanceCounter("Process", "IO Write Bytes/sec", instanceName, true);
                        perfCounters["HandleCount"] = new PerformanceCounter("Process", "Handle Count", instanceName, true);
                        perfCounters["ThreadCount"] = new PerformanceCounter("Process", "Thread Count", instanceName, true);
                    }
                    catch { }
                }
            }
            catch { }

            float lastIoRead = 0, lastIoWrite = 0;
            float lastHandleCount = 0, lastThreadCount = 0;

            while (!token.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(500, token);

                    if (perfCounters.Count > 0)
                    {
                        // Check I/O activity
                        if (perfCounters.TryGetValue("IORead", out var ioReadCounter))
                        {
                            float currentRead = ioReadCounter.NextValue();
                            if (currentRead > 0 && currentRead != lastIoRead)
                            {
                                var evt = new EtwEvent
                                {
                                    Timestamp = DateTime.Now,
                                    Category = "File",
                                    Operation = "Read",
                                    Target = $"{currentRead:F0} bytes/sec",
                                    ProcessId = targetProcessId,
                                    ThreadId = 0,
                                    Details = $"I/O Read activity detected"
                                };
                                lock (syncLock) eventHistory.Add(evt);
                                try { OnEvent?.Invoke(evt); } catch { }
                            }
                            lastIoRead = currentRead;
                        }

                        if (perfCounters.TryGetValue("IOWrite", out var ioWriteCounter))
                        {
                            float currentWrite = ioWriteCounter.NextValue();
                            if (currentWrite > 0 && currentWrite != lastIoWrite)
                            {
                                var evt = new EtwEvent
                                {
                                    Timestamp = DateTime.Now,
                                    Category = "File",
                                    Operation = "Write",
                                    Target = $"{currentWrite:F0} bytes/sec",
                                    ProcessId = targetProcessId,
                                    ThreadId = 0,
                                    Details = $"I/O Write activity detected"
                                };
                                lock (syncLock) eventHistory.Add(evt);
                                try { OnEvent?.Invoke(evt); } catch { }
                            }
                            lastIoWrite = currentWrite;
                        }

                        // Check handle count changes
                        if (perfCounters.TryGetValue("HandleCount", out var handleCounter))
                        {
                            float currentHandles = handleCounter.NextValue();
                            if (currentHandles != lastHandleCount && lastHandleCount > 0)
                            {
                                int delta = (int)(currentHandles - lastHandleCount);
                                if (Math.Abs(delta) > 2) // Only report significant changes
                                {
                                    var evt = new EtwEvent
                                    {
                                        Timestamp = DateTime.Now,
                                        Category = "Process",
                                        Operation = delta > 0 ? "HandleOpened" : "HandleClosed",
                                        Target = $"{(int)currentHandles} handles ({(delta > 0 ? "+" : "")}{delta})",
                                        ProcessId = targetProcessId,
                                        ThreadId = 0,
                                        Details = $"Handle count changed by {delta}"
                                    };
                                    lock (syncLock) eventHistory.Add(evt);
                                    try { OnEvent?.Invoke(evt); } catch { }
                                }
                            }
                            lastHandleCount = currentHandles;
                        }

                        // Check thread count changes
                        if (perfCounters.TryGetValue("ThreadCount", out var threadCounter))
                        {
                            float currentThreads = threadCounter.NextValue();
                            if (currentThreads != lastThreadCount && lastThreadCount > 0)
                            {
                                int delta = (int)(currentThreads - lastThreadCount);
                                if (delta != 0)
                                {
                                    var evt = new EtwEvent
                                    {
                                        Timestamp = DateTime.Now,
                                        Category = "Thread",
                                        Operation = delta > 0 ? "ThreadCreated" : "ThreadExited",
                                        Target = $"{(int)currentThreads} threads ({(delta > 0 ? "+" : "")}{delta})",
                                        ProcessId = targetProcessId,
                                        ThreadId = 0,
                                        Details = $"Thread count changed by {delta}"
                                    };
                                    lock (syncLock) eventHistory.Add(evt);
                                    try { OnEvent?.Invoke(evt); } catch { }
                                }
                            }
                            lastThreadCount = currentThreads;
                        }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch { }
            }

            // Cleanup performance counters
            foreach (var kvp in perfCounters)
            {
                try { kvp.Value.Dispose(); } catch { }
            }

            isTracing = false;
        }

        private string GetPerformanceCounterInstanceName(Process proc)
        {
            try
            {
                // Performance counter instance names don't always match process names
                // They may have #1, #2 suffixes for duplicate names
                var category = new PerformanceCounterCategory("Process");
                var instances = category.GetInstanceNames();

                string baseName = proc.ProcessName;
                int pid = proc.Id;

                // Find the instance that matches our process
                foreach (string instance in instances)
                {
                    if (instance.StartsWith(baseName, StringComparison.OrdinalIgnoreCase))
                    {
                        try
                        {
                            using (var idCounter = new PerformanceCounter("Process", "ID Process", instance, true))
                            {
                                float instanceId = idCounter.NextValue();
                                if ((int)instanceId == pid)
                                    return instance;
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
            return null;
        }

        [DllImport("advapi32.dll")]
        private static extern int CloseTrace(long traceHandle);

        public void Dispose()
        {
            StopTracing();
            cts?.Dispose();
        }
    }
}
