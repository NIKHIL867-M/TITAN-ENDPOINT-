using System.Runtime.InteropServices;
using System.Text;

namespace TitanEndpoint.Core.CustomRule;

/// <summary>
/// P/Invoke CryptUnprotectData — reads the exact same DPAPI blob format that
/// CUSTOM RULE\shared\secret_store.py writes via pywin32's win32crypt.CryptProtectData
/// (both are thin wrappers over the identical Win32 API, CurrentUser scope). Implemented
/// as a direct P/Invoke rather than the System.Security.Cryptography.ProtectedData NuGet
/// package to keep this project's "zero NuGet deps, pure BCL" convention (see
/// TITAN_MASTER_CONTEXT.md / gui_build memory) — no functional difference either way.
/// </summary>
internal static class DpapiUnprotect
{
    [StructLayout(LayoutKind.Sequential)]
    private struct DATA_BLOB
    {
        public int cbData;
        public IntPtr pbData;
    }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptUnprotectData(
        ref DATA_BLOB pDataIn, StringBuilder? ppszDataDescr, IntPtr pOptionalEntropy,
        IntPtr pvReserved, IntPtr pPromptStruct, int dwFlags, out DATA_BLOB pDataOut);

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptProtectData(
        ref DATA_BLOB pDataIn, string? szDataDescr, IntPtr pOptionalEntropy,
        IntPtr pvReserved, IntPtr pPromptStruct, int dwFlags, out DATA_BLOB pDataOut);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr hMem);

    /// <summary>Returns null (never throws) if the blob is missing, corrupt, or was
    /// encrypted under a different Windows user account — DPAPI keys are not portable
    /// by design, same behavior as secret_store.py's load_encrypted_secret.</summary>
    public static string? TryUnprotect(byte[] encrypted)
    {
        var bytes = TryUnprotectBytes(encrypted);
        return bytes is null ? null : Encoding.UTF8.GetString(bytes);
    }

    public static byte[]? TryUnprotectBytes(byte[] encrypted)
    {
        if (encrypted.Length == 0) return null;

        var inBlob = new DATA_BLOB { cbData = encrypted.Length, pbData = Marshal.AllocHGlobal(encrypted.Length) };
        try
        {
            Marshal.Copy(encrypted, 0, inBlob.pbData, encrypted.Length);
            if (!CryptUnprotectData(ref inBlob, null, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0, out var outBlob))
                return null;
            try
            {
                if (outBlob.pbData == IntPtr.Zero || outBlob.cbData <= 0) return null;
                var bytes = new byte[outBlob.cbData];
                Marshal.Copy(outBlob.pbData, bytes, 0, outBlob.cbData);
                return bytes;
            }
            finally
            {
                if (outBlob.pbData != IntPtr.Zero) LocalFree(outBlob.pbData);
            }
        }
        catch
        {
            return null;
        }
        finally
        {
            Marshal.FreeHGlobal(inBlob.pbData);
        }
    }

    public static byte[]? TryProtect(byte[] plaintext)
    {
        if (plaintext.Length == 0) return null;
        var inBlob = new DATA_BLOB { cbData = plaintext.Length, pbData = Marshal.AllocHGlobal(plaintext.Length) };
        try
        {
            Marshal.Copy(plaintext, 0, inBlob.pbData, plaintext.Length);
            if (!CryptProtectData(ref inBlob, "Titan Endpoint local integrity key", IntPtr.Zero,
                    IntPtr.Zero, IntPtr.Zero, 0, out var outBlob))
                return null;
            try
            {
                if (outBlob.pbData == IntPtr.Zero || outBlob.cbData <= 0) return null;
                var bytes = new byte[outBlob.cbData];
                Marshal.Copy(outBlob.pbData, bytes, 0, outBlob.cbData);
                return bytes;
            }
            finally
            {
                if (outBlob.pbData != IntPtr.Zero) LocalFree(outBlob.pbData);
            }
        }
        catch { return null; }
        finally { Marshal.FreeHGlobal(inBlob.pbData); }
    }
}
