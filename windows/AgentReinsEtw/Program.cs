using System.Diagnostics;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

namespace AgentReinsEtw;

internal static class Program
{
    private static readonly object WriterLock = new();
    private static StreamWriter? Writer;
    private static string OutputPath = "";
    private static long MaxLogBytes = 50L * 1024 * 1024;
    private static string[] Roots = [];
    private static long Records;

    private static int Main(string[] args)
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("AgentReins ETW helper runs on Windows only.");
            return 2;
        }

        string output = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "AgentReins", "etw-events.jsonl");
        var rootArgs = new List<string>();
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--root" when i + 1 < args.Length:
                    rootArgs.Add(args[++i]);
                    break;
                case "--output" when i + 1 < args.Length:
                    output = args[++i];
                    break;
                case "--max-log-mb" when i + 1 < args.Length && long.TryParse(args[++i], out long logMb) && logMb is >= 1 and <= 1024:
                    MaxLogBytes = logMb * 1024 * 1024;
                    break;
                case "--help":
                case "-h":
                    Usage();
                    return 0;
                default:
                    Console.Error.WriteLine($"Unknown or incomplete argument: {args[i]}");
                    Usage();
                    return 2;
            }
        }

        if (rootArgs.Count == 0)
        {
            Console.Error.WriteLine("Specify at least one --root path; tracing the entire filesystem is intentionally not the default.");
            Usage();
            return 2;
        }
        if (!IsAdministrator())
        {
            Console.Error.WriteLine("ETW kernel file tracing needs an elevated Administrator process. Run this helper from an elevated terminal.");
            return 5;
        }

        Roots = rootArgs.Select(NormalizePath).Where(x => x.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (Roots.Length == 0 || Roots.Any(root => !Directory.Exists(root) && !File.Exists(root)))
        {
            Console.Error.WriteLine("Every --root must be an existing file or directory.");
            return 2;
        }

        try
        {
            string fullOutput = Path.GetFullPath(output);
            OutputPath = fullOutput;
            Directory.CreateDirectory(Path.GetDirectoryName(fullOutput)!);
            Writer = OpenWriter(fullOutput);
            WriteStatus("started", $"Watching {Roots.Length} path root(s); ETW event metadata only.");
            using var heartbeat = new Timer(
                _ => WriteStatus("heartbeat", "Kernel ETW capture active."),
                null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));

            Console.Error.WriteLine($"AgentReins ETW helper active. Output: {fullOutput}");
            Console.Error.WriteLine("Press Ctrl+C to stop. Only paths under the configured roots are recorded.");
            using var session = new TraceEventSession("AgentReinsFileEvents") { StopOnDispose = true };
            session.EnableKernelProvider(KernelTraceEventParser.Keywords.FileIO | KernelTraceEventParser.Keywords.FileIOInit);
            var kernel = session.Source.Kernel;
            ConsoleCancelEventHandler cancel = (_, eventArgs) =>
            {
                eventArgs.Cancel = true;
                session.Source.StopProcessing();
            };
            Console.CancelKeyPress += cancel;

            // These events are emitted by the kernel file I/O provider. FileIOWrite is
            // operation-oriented and can also represent writes into mapped files only
            // when the provider reports them; content is never captured.
            kernel.FileIOFileCreate += data => Emit(data.FileName, "create", "file-create", data.ProcessID, null);
            kernel.FileIOFileDelete += data => Emit(data.FileName, "delete", "file-delete", data.ProcessID, null);
            kernel.FileIOWrite += data => Emit(data.FileName, "modify", "write", data.ProcessID, data.IoSize);
            kernel.FileIODelete += data => Emit(data.FileName, "delete", "delete", data.ProcessID, null);
            kernel.FileIORename += data => Emit(data.FileName, "rename", "rename", data.ProcessID, null);
            kernel.FileIOSetInfo += data => Emit(data.FileName, "modify", "set-info", data.ProcessID, null);

            try
            {
                session.Source.Process();
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"ETW session stopped: {ex.Message}");
                WriteStatus("stopped", ex.Message);
                return 1;
            }
            finally
            {
                Console.CancelKeyPress -= cancel;
            }
            WriteStatus("stopped", "ETW trace processing ended.");
            return 0;
        }
        catch (UnauthorizedAccessException ex)
        {
            Console.Error.WriteLine($"ETW access denied. Confirm this terminal is elevated and system policy permits kernel tracing. {ex.Message}");
            WriteStatus("error", "access-denied");
            return 5;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Could not start ETW capture: {ex.Message}");
            WriteStatus("error", ex.Message);
            return 1;
        }
        finally
        {
            lock (WriterLock)
            {
                Writer?.Dispose();
                Writer = null;
            }
        }
    }

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static string NormalizePath(string path)
    {
        try
        {
            string full = Path.GetFullPath(Environment.ExpandEnvironmentVariables(path));
            string volumeRoot = Path.GetPathRoot(full) ?? "";
            return full.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).Length < volumeRoot.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).Length
                ? volumeRoot : full.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }
        catch { return ""; }
    }

    private static bool IsUnderRoots(string path)
    {
        string normalized = NormalizePath(path);
        if (normalized.Length == 0) return false;
        return Roots.Any(root => normalized.Equals(root, StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith(root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase));
    }

    private static void Emit(string? path, string action, string operation, int processId, int? size = null)
    {
        if (string.IsNullOrWhiteSpace(path) || !IsUnderRoots(path)) return;
        Write(new
        {
            recordType = "file_event",
            timestamp = DateTimeOffset.UtcNow.ToString("O"),
            path = NormalizePath(path),
            action,
            source = "windows-etw",
            operation,
            processId,
            isDirectory = Directory.Exists(NormalizePath(path)),
            sizeBytes = size,
            captureScope = "metadata-only",
            outcomeKnown = false
        });
    }

    private static void WriteStatus(string status, string detail) => Write(new
    {
        recordType = "status",
        timestamp = DateTimeOffset.UtcNow.ToString("O"),
        source = "windows-etw",
        processId = Environment.ProcessId,
        roots = Roots,
        status,
        detail
    });

    private static void Write(object record)
    {
        string line = JsonSerializer.Serialize(record);
        lock (WriterLock)
        {
            RotateIfNeeded();
            Writer?.WriteLine(line);
            if (++Records % 1000 == 0) Writer?.Flush();
        }
    }

    private static StreamWriter OpenWriter(string path) => new(
        new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete),
        new System.Text.UTF8Encoding(false)) { AutoFlush = true };

    private static void RotateIfNeeded()
    {
        if (Writer == null || Writer.BaseStream.Length < MaxLogBytes) return;
        Writer.Dispose();
        Writer = null;
        string archive = OutputPath + ".1";
        bool rotated = false;
        try
        {
            if (File.Exists(archive)) File.Delete(archive);
            File.Move(OutputPath, archive);
            rotated = true;
        }
        catch (IOException)
        {
            // A reader or endpoint scanner may hold the old path open. Retain
            // the active file and retry on the next event instead of dropping data.
        }
        Writer = OpenWriter(OutputPath);
        if (rotated) WriteStatus("started", "ETW event log rotated; capture remains active.");
    }

    private static void Usage()
    {
        Console.Error.WriteLine("Usage: AgentReinsEtwHelper.exe --root <existing-path> [--root <existing-path> ...] [--output <jsonl-path>] [--max-log-mb 50]");
        Console.Error.WriteLine("Requires Administrator. Records file event metadata only; ETW is not started unless this executable is explicitly run.");
    }
}
