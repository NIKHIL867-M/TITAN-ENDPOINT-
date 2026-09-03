using System.Runtime.InteropServices;

namespace TitanEndpoint.Core.ProcessControl;

/// <summary>
/// Enumerates direct child process IDs of a given parent via CreateToolhelp32Snapshot. Found live:
/// python.exe launched from a venv's Scripts\ directory re-execs into a separate child process (the
/// real interpreter actually running uvicorn/watcher.main) rather than running in-process, so
/// Process.Kill(entireProcessTree: true) on the launcher alone misses that child once the launcher
/// itself has already exited on its own -- exactly what happens on CustomRuleServiceController's
/// graceful-Ctrl+C shutdown path, which left the real API/watcher process running as an orphan after
/// its launcher stub exited and WaitForExit reported success.
/// </summary>
internal static class ProcessTree
{
    private const uint TH32CS_SNAPPROCESS = 0x00000002;

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESSENTRY32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll")]
    private static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("kernel32.dll")]
    private static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    /// <summary>Direct children only (one level) -- sufficient for the venv-launcher-plus-one-real-
    /// interpreter shape this exists for. Never throws; returns an empty list on any failure.</summary>
    public static List<int> GetChildProcessIds(int parentPid)
    {
        var children = new List<int>();
        var snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == IntPtr.Zero || snapshot == new IntPtr(-1)) return children;
        try
        {
            var entry = new PROCESSENTRY32 { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32>() };
            if (!Process32First(snapshot, ref entry)) return children;
            do
            {
                if (entry.th32ParentProcessID == (uint)parentPid)
                    children.Add((int)entry.th32ProcessID);
            } while (Process32Next(snapshot, ref entry));
        }
        finally
        {
            CloseHandle(snapshot);
        }
        return children;
    }
}
