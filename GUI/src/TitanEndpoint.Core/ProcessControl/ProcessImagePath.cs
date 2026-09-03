using System.Runtime.InteropServices;
using System.Text;

namespace TitanEndpoint.Core.ProcessControl;

/// <summary>
/// Resolves a process's executable path via QueryFullProcessImageName instead of
/// System.Diagnostics.Process.MainModule. This exists specifically because MainModule
/// requires PROCESS_QUERY_INFORMATION | PROCESS_VM_READ and throws Win32Exception (Access
/// Denied) when the target process runs at a higher integrity level than the caller — exactly
/// the normal case here: every TITAN native collector requires elevation, and the GUI itself is
/// not necessarily elevated. QueryFullProcessImageName only needs
/// PROCESS_QUERY_LIMITED_INFORMATION, which Windows grants across integrity levels for the same
/// user session, so this lets an unelevated GUI verify an elevated collector's exact executable
/// path — the identity check FORU.TXT section 2 requires ("a matching process name alone is not
/// sufficient") would otherwise silently degrade to unverifiable for every real deployment.
/// </summary>
public static class ProcessImagePath
{
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageNameW(IntPtr hProcess, uint dwFlags, StringBuilder lpExeName, ref int lpdwSize);

    /// <summary>Returns null if the process has exited, cannot be opened at all (rare —
    /// typically only fully protected system processes), or any other failure occurs. Never
    /// throws.</summary>
    public static string? TryGetImagePath(int pid)
    {
        var handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (handle == IntPtr.Zero) return null;
        try
        {
            var size = 1024;
            var sb = new StringBuilder(size);
            if (!QueryFullProcessImageNameW(handle, 0, sb, ref size)) return null;
            return sb.ToString(0, size);
        }
        finally
        {
            CloseHandle(handle);
        }
    }
}
