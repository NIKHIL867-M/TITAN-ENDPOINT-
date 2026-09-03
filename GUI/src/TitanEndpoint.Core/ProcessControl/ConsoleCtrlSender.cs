using System.Runtime.InteropServices;

namespace TitanEndpoint.Core.ProcessControl;

/// <summary>
/// Sends a real Ctrl+C to a target console process so it can flush queues and
/// finalize evidence on shutdown, matching Test Group E's expectation
/// ("Ctrl+C every endpoint while busy; verify queues flush") instead of a hard
/// Kill(). Best effort: only works for processes that own their own console.
/// </summary>
internal static class ConsoleCtrlSender
{
    private const int CTRL_C_EVENT = 0;
    private const int ATTACH_PARENT_PROCESS = -1;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AttachConsole(int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FreeConsole();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GenerateConsoleCtrlEvent(uint dwCtrlEvent, uint dwProcessGroupId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetConsoleProcessList([Out] uint[] processList, uint processCount);

    private delegate bool ConsoleCtrlDelegate(uint dwCtrlType);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetConsoleCtrlHandler(ConsoleCtrlDelegate? handlerRoutine, bool add);

    /// <summary>Attempts a graceful Ctrl+C. Returns false if the target isn't a console we can attach to.</summary>
    public static bool TrySendCtrlC(int targetProcessId)
    {
        var originalConsole = GetAttachedConsoleProcessIds();
        FreeConsole();
        try
        {
            if (!AttachConsole(targetProcessId))
                return false;

            // CTRL_C_EVENT with process-group 0 reaches every process attached to
            // the target console. In console-hosted tests, Python inherits the
            // same console as PowerShell/testhost; signaling it would interrupt
            // the caller too. Only send when the target console is isolated from
            // every process that shared our original console (other than self).
            var currentPid = (uint)Environment.ProcessId;
            var targetConsole = GetAttachedConsoleProcessIds();
            if (targetConsole.Any(pid => pid != currentPid && originalConsole.Contains(pid)))
                return false;

            try
            {
                // Ignore the signal in our own process so GenerateConsoleCtrlEvent doesn't tear us down too.
                SetConsoleCtrlHandler(null, true);
                return GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0);
            }
            finally
            {
                FreeConsole();
                SetConsoleCtrlHandler(null, false);
            }
        }
        finally
        {
            AttachConsole(ATTACH_PARENT_PROCESS);
        }
    }

    private static HashSet<uint> GetAttachedConsoleProcessIds()
    {
        var buffer = new uint[64];
        var count = GetConsoleProcessList(buffer, (uint)buffer.Length);
        if (count == 0) return new HashSet<uint>();
        if (count > buffer.Length)
        {
            buffer = new uint[count];
            count = GetConsoleProcessList(buffer, (uint)buffer.Length);
        }
        return buffer.Take((int)Math.Min(count, (uint)buffer.Length)).ToHashSet();
    }
}
