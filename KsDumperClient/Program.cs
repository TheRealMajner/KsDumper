using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace KsDumperClient
{
    static class Program
    {
        private static readonly string LogPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "KsDumper", "crash.log");

        [STAThread]
        static void Main()
        {
            // Ensure log directory exists
            try { Directory.CreateDirectory(Path.GetDirectoryName(LogPath)); } catch { }

            // Catch all unhandled exceptions from any source
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);

            // WinForms UI thread exceptions — log and show, do NOT terminate
            Application.ThreadException += (s, e) =>
            {
                LogException("UI Thread", e.Exception);
                try
                {
                    MessageBox.Show(
                        $"UI Thread Error:\n\n{e.Exception.Message}\n\nStack:\n{TruncateStack(e.Exception)}",
                        "KsDumper - Error",
                        MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                catch { }
            };

            // Non-UI thread exceptions — log and suppress termination
            AppDomain.CurrentDomain.UnhandledException += (s, e) =>
            {
                var ex = e.ExceptionObject as Exception;
                LogException("AppDomain", ex ?? new Exception(e.ExceptionObject?.ToString() ?? "Unknown"));

                try
                {
                    string msg = ex != null
                        ? $"{ex.Message}\n\nStack:\n{TruncateStack(ex)}"
                        : e.ExceptionObject?.ToString() ?? "Unknown error";

                    MessageBox.Show(
                        $"Error:\n\n{msg}",
                        "KsDumper - Error",
                        MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                catch { }
            };

            // TaskScheduler unobserved exceptions — log and suppress
            TaskScheduler.UnobservedTaskException += (s, e) =>
            {
                e.SetObserved(); // Prevent process termination
                var ex = e.Exception?.InnerException ?? e.Exception;
                LogException("Task", ex);

                // Only show dialog for serious errors, not transient ones
                if (ex != null && !(ex is OperationCanceledException) && !(ex is TaskCanceledException))
                {
                    try
                    {
                        MessageBox.Show(
                            $"Background Error:\n\n{ex.Message}",
                            "KsDumper - Background Error",
                            MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    }
                    catch { }
                }
            };

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            try
            {
                Application.Run(new Dumper());
            }
            catch (Exception ex)
            {
                LogException("Main Loop", ex);
                MessageBox.Show(
                    $"Fatal error in main loop:\n\n{ex.Message}",
                    "KsDumper - Fatal",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private static void LogException(string source, Exception ex)
        {
            try
            {
                string entry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{source}] {ex?.GetType().Name}: {ex?.Message}\n" +
                               $"  Stack: {ex?.StackTrace}\n" +
                               (ex?.InnerException != null ? $"  Inner: {ex.InnerException.GetType().Name}: {ex.InnerException.Message}\n" : "") +
                               "\n";
                File.AppendAllText(LogPath, entry);
            }
            catch { }
        }

        private static string TruncateStack(Exception ex)
        {
            if (ex?.StackTrace == null) return "(no stack trace)";
            int len = Math.Min(500, ex.StackTrace.Length);
            return ex.StackTrace.Substring(0, len);
        }
    }
}
