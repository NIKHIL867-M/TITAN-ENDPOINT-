using System.Diagnostics;
using System.IO;
using System.Windows.Automation;

namespace TitanEndpoint.App.UiTests.Fixtures;

/// <summary>FORU.TXT 0.8: "Tests must launch an isolated test profile and never reuse or mutate
/// production logs, approved rules, settings, baselines, endpoint sessions, or retention state."
///
/// Redirects settings.json to a per-run temp file via TITAN_ENDPOINT_TEST_SETTINGS_PATH (see
/// TitanSettings.SettingsPath) so any test that triggers a Settings.Save() never touches the real
/// operator's %LocalAppData%\TitanEndpoint\settings.json. Native binaries, runtime-manifest.json,
/// and endpoint log directories are intentionally NOT redirected here -- they are read (and, for
/// EndpointControlTests, the real Correlator process is started/stopped) exactly as a real launch
/// would, which is what "live" tests in this suite are for (FORU.TXT 0.8: "Keep separate elevated
/// live tests for real named-pipe acknowledgements"). Faking the entire native binary tree so even
/// Start/Stop can run against a synthetic endpoint is a larger undertaking intentionally deferred
/// -- see FakeEndpointControlServer.cs's doc comment.
/// </summary>
public sealed class IsolatedTestProfile : IDisposable
{
    public string TestSettingsPath { get; }
    private readonly string _tempDir;

    public IsolatedTestProfile()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "titan_uitest_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        TestSettingsPath = Path.Combine(_tempDir, "settings.json");
    }

    public static string FindAppExecutable()
    {
        // Walk up from this test assembly's output directory to the TITAN root, then down to the
        // Release build -- matches TitanSettings.GuessTitanRoot's own marker-file-walk convention
        // so this fixture keeps working if the build output layout ever changes.
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "TITAN_MASTER_CONTEXT.md")))
            dir = dir.Parent;
        if (dir is null)
            throw new InvalidOperationException("Could not locate the TITAN root (TITAN_MASTER_CONTEXT.md) above " + AppContext.BaseDirectory);

        var exePath = Path.Combine(dir.FullName, "GUI", "src", "TitanEndpoint.App", "bin", "Release",
            "net8.0-windows", "TitanEndpoint.App.exe");
        if (!File.Exists(exePath))
            throw new FileNotFoundException("TitanEndpoint.App.exe was not found. Build the solution in Release before running UI tests.", exePath);
        return exePath;
    }

    /// <summary>Launches the app with the isolated settings path and waits for its main window.
    /// Throws with a clear message on timeout rather than returning a null/zero handle for the
    /// caller to mishandle.</summary>
    public Process LaunchAndWaitForMainWindow(TimeSpan? timeout = null)
    {
        var psi = new ProcessStartInfo
        {
            FileName = FindAppExecutable(),
            UseShellExecute = false
        };
        psi.EnvironmentVariables["TITAN_ENDPOINT_TEST_SETTINGS_PATH"] = TestSettingsPath;

        var process = Process.Start(psi) ?? throw new InvalidOperationException("Process.Start returned null for TitanEndpoint.App.exe.");
        var deadline = DateTime.UtcNow + (timeout ?? TimeSpan.FromSeconds(20));
        while (process.MainWindowHandle == IntPtr.Zero && DateTime.UtcNow < deadline)
        {
            Thread.Sleep(200);
            process.Refresh();
        }
        if (process.MainWindowHandle == IntPtr.Zero)
        {
            try { process.Kill(entireProcessTree: true); } catch { /* best effort */ }
            throw new TimeoutException("TitanEndpoint.App.exe did not present a main window within the timeout.");
        }
        // Give WPF a moment to finish its initial layout pass -- MainWindowHandle can be non-zero
        // slightly before the first page's content is actually laid out and stable.
        Thread.Sleep(2500);
        return process;
    }

    public static void CloseAndWait(Process process, TimeSpan? timeout = null)
    {
        process.CloseMainWindow();
        if (!process.WaitForExit((int)(timeout ?? TimeSpan.FromSeconds(8)).TotalMilliseconds))
        {
            try { process.Kill(entireProcessTree: true); } catch { /* best effort */ }
        }
    }

    public static AutomationElement GetRootElement(Process process) =>
        AutomationElement.FromHandle(process.MainWindowHandle)
        ?? throw new InvalidOperationException("Could not obtain an AutomationElement for the main window.");

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { /* best effort */ }
    }
}
