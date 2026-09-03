using System.Runtime.InteropServices;

namespace TitanEndpoint.Core.ProcessControl;

/// <summary>Raw P/Invoke elevation check, shared by PreflightService and EndpointProcessController
/// so there is exactly one implementation. Deliberately not System.Security.Principal.
/// WindowsPrincipal -- that BCL type is annotated [SupportedOSPlatform("windows")], which trips
/// CA1416 under Core's plain (not -windows) net8.0 target; P/Invoke declarations aren't annotated
/// the same way, matching this project's existing P/Invoke-over-BCL-helper convention (see
/// ProcessImagePath.cs/DpapiUnprotect.cs).</summary>
public static class ElevationHelper
{
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr tokenHandle, int tokenInformationClass,
        ref int tokenInformation, int tokenInformationLength, out int returnLength);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    private const uint TOKEN_QUERY = 0x0008;
    private const int TokenElevation = 20;

    public static bool IsCurrentProcessElevated()
    {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, out var token)) return false;
        try
        {
            var elevated = 0;
            return GetTokenInformation(token, TokenElevation, ref elevated, sizeof(int), out _) && elevated != 0;
        }
        finally
        {
            CloseHandle(token);
        }
    }
}
