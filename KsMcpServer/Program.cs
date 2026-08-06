using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Server;
using KsMcpServer.Tools;
using KsDumperClient.Driver;

namespace KsMcpServer
{
    class Program
    {
        private static volatile bool _shouldExit = false;

        static async Task<int> Main(string[] args)
        {
            bool autoRestart = Array.Exists(args, a => a == "--auto-restart" || a == "-r");

            Console.Error.WriteLine("[KsDumper] MCP Server v1.0");
            Console.Error.WriteLine("[KsDumper] Transport: stdio");
            Console.Error.WriteLine("[KsDumper] Auto-restart: {0}", autoRestart ? "enabled" : "disabled");

            do
            {
                try
                {
                    await RunServerAsync(args);

                    Console.Error.WriteLine("[KsDumper] Server exited cleanly.");
                    return 0;
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine("[KsDumper] Server crashed: {0}", ex.Message);

                    if (!autoRestart || _shouldExit)
                    {
                        Console.Error.WriteLine("[KsDumper] Exiting.");
                        return 1;
                    }

                    Console.Error.WriteLine("[KsDumper] Restarting in 2 seconds...");
                    await Task.Delay(2000);
                    Console.Error.WriteLine("[KsDumper] Restarting...");
                }
            } while (autoRestart && !_shouldExit);

            return 0;
        }

        static async Task RunServerAsync(string[] args)
        {
            // Handle Ctrl+C gracefully
            var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (s, e) =>
            {
                e.Cancel = true;
                _shouldExit = true;
                cts.Cancel();
                Console.Error.WriteLine("[KsDumper] Shutdown requested...");
            };

            var builder = Host.CreateDefaultBuilder(args)
                .ConfigureLogging(logging =>
                {
                    logging.ClearProviders();
                })
                .ConfigureServices((context, services) =>
                {
                    services
                        .AddMcpServer()
                        .WithStdioServerTransport()
                        .WithTools<ProcessTools>()
                        .WithTools<MemoryTools>()
                        .WithTools<ModuleTools>()
                        .WithTools<DumpTools>()
                        .WithTools<PatternTools>()
                        .WithTools<ThreadTools>()
                        .WithTools<Il2CppTools>()
                        .WithTools<KernelTools>()
                        .WithTools<DebugTools>()
                        .WithTools<DeobfuscationTools>();

                    // Register the driver as a singleton — connects to the KsDumper kernel driver
                    services.AddSingleton<IMemoryReader>(sp =>
                    {
                        try
                        {
                            var kernel = new DriverInterface("\\\\.\\KsDumper");
                            if (kernel.HasValidHandle())
                            {
                                Console.Error.WriteLine("[KsDumper] Connected to kernel driver.");
                                return kernel;
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.Error.WriteLine("[KsDumper] Kernel driver unavailable: {0}", ex.Message);
                        }

                        Console.Error.WriteLine("[KsDumper] Using user-mode fallback.");
                        return new UserModeInterface();
                    });
                });

            var app = builder.Build();
            await app.RunAsync(cts.Token);
        }
    }
}
