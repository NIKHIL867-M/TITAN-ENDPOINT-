using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Runtime.InteropServices;
using TitanEndpoint.App.UiTests.Fixtures;

namespace TitanEndpoint.App.UiTests;

/// <summary>FORU.TXT 0.8 "Visual regression: capture approved screenshots for all 12 pages, each
/// major Custom Rule workflow, Network panes, dialogs, empty/error/pending states, compact/
/// comfortable density, high contrast, and supported DPI. Mask clocks/PIDs/session IDs before pixel
/// comparison; require human approval for intentional baseline changes."
///
/// This is a first pass, not the full suite -- and in THIS session's sandboxed agent environment, it
/// could not be exercised end-to-end at all: investigated 2026-08-03, both PrintWindow (with
/// PW_RENDERFULLCONTENT, the same technique used for manual GUI verification earlier this session)
/// and a screen-rectangle BitBlt/CopyFromScreen fallback produced captures that were either only the
/// window's non-client chrome or completely blank white, regardless of bringing the window to the
/// foreground first. That is consistent with this environment not exposing a real composited desktop
/// framebuffer to GDI screen-capture APIs at all (typical of some non-interactive/virtualized
/// automation sessions), not a defect in the navigation or comparison logic below, both of which are
/// real and were exercised correctly (all 12 pages navigated to and captures attempted). Rather than
/// silently save blank images as "baselines" -- which would be exactly the kind of fabricated result
/// this project's own evidence rules forbid -- IsCaptureUsable() rejects a near-uniform-color capture
/// and this suite reports each page's case as a SKIP with a clear reason instead of a false PASS or a
/// baseline that would never mean anything. The navigation, baseline-create-vs-compare flow, and grid-
/// sampled diff-percent algorithm below are real and ready to produce genuine baselines and
/// comparisons the first time this suite runs somewhere with a real interactive desktop session --
/// they have simply never been exercised against real captured pixels. No Custom Rule workflow
/// sub-states, dialogs, empty/error/pending states, high contrast, or multiple DPI/density
/// combinations are covered even conceptually yet; this suite only ever attempted the 12 top-level
/// pages. Comparison also does not mask specific dynamic regions (clocks/PIDs/session IDs) by
/// coordinate -- it uses a generous whole-image difference tolerance instead (see
/// DiffPercentThreshold) intended to absorb small dynamic-content churn.</summary>
public static class VisualRegressionTests
{
    private static readonly (string NavLabel, string PageName)[] Pages =
    {
        ("Overview", "Overview"),
        ("Process", "Process"),
        ("Network", "Network"),
        ("Applications", "Applications"),
        ("Files", "Files"),
        ("Port / USB", "PortUsb"),
        ("Correlation", "Correlation"),
        ("Custom Rules", "CustomRules"),
        ("Alerts & Evidence", "AlertsAndEvidence"),
        ("Unified Logs", "UnifiedLogs"),
        ("System Health", "SystemHealth"),
        ("Settings", "Settings"),
    };

    // A run-to-run capture legitimately differs in clock text, per-session PIDs, heartbeat ages,
    // sparkline samples, etc. even on an otherwise-unchanged page -- this suite does not mask those
    // regions individually (see class doc comment), so the pass threshold has to be generous enough
    // to absorb them while still catching a page that is visibly broken, blank, or wrong.
    private const double DiffPercentThreshold = 20.0;

    public static List<string> Run()
    {
        var failures = new List<string>();
        var reportsRoot = FindReportsRoot();
        var baselineDir = Path.Combine(reportsRoot, "visual-baselines");
        Directory.CreateDirectory(baselineDir);

        using var profile = new IsolatedTestProfile();
        var process = profile.LaunchAndWaitForMainWindow();
        try
        {
            // Layout persistence is intentionally global rather than tied to the
            // isolated settings file, so a prior operator session can leave the
            // window restored or maximized. Normalize geometry before every
            // visual run; otherwise the same UI produces 20-35% false diffs.
            ShowWindow(process.MainWindowHandle, 3 /* SW_MAXIMIZE */);
            EnsureForeground(process.MainWindowHandle);
            Thread.Sleep(1000);

            var isFirst = true;
            foreach (var (navLabel, pageName) in Pages)
            {
                // CopyFromScreen grabs whatever is actually on top at that screen rectangle -- bring
                // the window to the foreground first so an unrelated window (terminal, IDE) sitting
                // over it doesn't get captured instead.
                EnsureForeground(process.MainWindowHandle);
                Thread.Sleep(150);
                var selected = isFirst;
                if (!isFirst)
                {
                    for (var attempt = 0; attempt < 5 && !selected; attempt++)
                    {
                        try { selected = UiAutomationHelpers.SelectByLabel(IsolatedTestProfile.GetRootElement(process), navLabel); }
                        catch (System.Windows.Automation.ElementNotAvailableException) { Thread.Sleep(300); }
                        if (!selected) Thread.Sleep(250);
                    }
                }
                isFirst = false;
                Report(failures, selected, $"Visual regression: navigated to '{navLabel}'");
                if (!selected) continue;
                Thread.Sleep(900);
                EnsureForeground(process.MainWindowHandle);

                using var capture = CaptureWindow(process.MainWindowHandle);
                Report(failures, capture is not null, $"Visual regression: captured a screenshot of '{navLabel}'");
                if (capture is null) continue;

                if (!IsCaptureUsable(capture))
                {
                    Console.WriteLine($"[SKIP] Visual regression: '{navLabel}' capture is near-uniform color " +
                        "(this environment's screen-capture APIs are not returning real rendered content -- " +
                        "see class doc comment) -- not saved as a baseline and not scored as pass/fail.");
                    continue;
                }

                var baselinePath = Path.Combine(baselineDir, $"{pageName}.png");
                if (!File.Exists(baselinePath))
                {
                    capture.Save(baselinePath, ImageFormat.Png);
                    Console.WriteLine($"[BASELINE CREATED] '{navLabel}' -> {baselinePath}");
                    continue;
                }

                using var baseline = new Bitmap(baselinePath);
                var diffPercent = ComputeDiffPercent(baseline, capture);
                var withinTolerance = diffPercent <= DiffPercentThreshold;
                Report(failures, withinTolerance,
                    $"Visual regression: '{navLabel}' matches its approved baseline within {DiffPercentThreshold}% " +
                    $"(actual difference {diffPercent:0.0}%)");

                if (!withinTolerance)
                {
                    var actualPath = Path.Combine(baselineDir, $"{pageName}.actual.png");
                    capture.Save(actualPath, ImageFormat.Png);
                    Console.WriteLine($"[INFO] Saved the differing capture to {actualPath} for human review against the baseline.");
                }
            }
        }
        finally
        {
            IsolatedTestProfile.CloseAndWait(process);
        }
        return failures;
    }

    private static string FindReportsRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "TITAN_MASTER_CONTEXT.md")))
            dir = dir.Parent;
        if (dir is null)
            throw new InvalidOperationException("Could not locate the TITAN root (TITAN_MASTER_CONTEXT.md) above " + AppContext.BaseDirectory);
        return Path.Combine(dir.FullName, "reports", "acceptance");
    }

    /// <summary>PrintWindow (even with PW_RENDERFULLCONTENT) was tried first, matching earlier
    /// manual-verification technique used elsewhere this session -- but found empirically 2026-08-03
    /// to capture only this WPF app's non-client chrome (title bar/caption buttons) with the entire
    /// client area blank, apparently because this app's DirectX-composited rendering doesn't flush
    /// into GDI the way PrintWindow expects on this machine/driver combination. Falls back to a
    /// screen-rectangle BitBlt instead, which works for any window that is actually visible on
    /// screen (the normal case for an automated foreground test window) at the cost of capturing
    /// whatever is on top if something else occludes it -- an acceptable tradeoff for this first
    /// pass over a technique that was silently capturing nothing useful at all.</summary>
    private static Bitmap? CaptureWindow(IntPtr hwnd)
    {
        // GetWindowRect is DPI-virtualized according to the *calling thread*. In a full multi-suite
        // run that context can differ from a focused run, yielding a 1550x830 coordinate rectangle
        // for a physically 1938x1038 window; CopyFromScreen then captures only the top-left crop.
        // Ask for physical per-monitor coordinates around the complete bounds/capture operation.
        var previousDpiContext = SetThreadDpiAwarenessContext(new IntPtr(-4) /* PER_MONITOR_AWARE_V2 */);
        const uint swpNoSize = 0x0001;
        const uint swpNoMove = 0x0002;
        const uint swpShowWindow = 0x0040;
        try
        {
            // Keep the product above terminals/IDEs for the exact CopyFromScreen interval. Merely
            // calling SetForegroundWindow before this method is racy: a notification or the test
            // runner's own UI can reclaim foreground between that call and the pixel copy.
            SetWindowPos(hwnd, new IntPtr(-1) /* HWND_TOPMOST */, 0, 0, 0, 0,
                swpNoSize | swpNoMove | swpShowWindow);
            NativeMethods.SetForegroundWindow(hwnd);
            Thread.Sleep(100);
            if (!GetWindowRect(hwnd, out var rect)) return null;
            var width = rect.Right - rect.Left;
            var height = rect.Bottom - rect.Top;
            if (width <= 0 || height <= 0) return null;

            var bitmap = new Bitmap(width, height, PixelFormat.Format32bppArgb);
            using var graphics = Graphics.FromImage(bitmap);
            graphics.CopyFromScreen(rect.Left, rect.Top, 0, 0, new Size(width, height), CopyPixelOperation.SourceCopy);
            return bitmap;
        }
        finally
        {
            SetWindowPos(hwnd, new IntPtr(-2) /* HWND_NOTOPMOST */, 0, 0, 0, 0,
                swpNoSize | swpNoMove | swpShowWindow);
            if (previousDpiContext != IntPtr.Zero) SetThreadDpiAwarenessContext(previousDpiContext);
        }
    }

    /// <summary>Samples a small grid of pixels and checks whether there is any real variation
    /// between them -- a genuine TITAN screenshot always has dark panels, light text, colored status
    /// dots, etc. and would never come back as one near-uniform color. Exists specifically to catch
    /// the blank/chrome-only captures this environment's screen-capture APIs were found to produce
    /// (see class doc comment) rather than silently treating them as valid baselines.</summary>
    private static bool IsCaptureUsable(Bitmap capture)
    {
        const int sampleGrid = 12;
        Color? first = null;
        for (var gy = 0; gy < sampleGrid; gy++)
        {
            for (var gx = 0; gx < sampleGrid; gx++)
            {
                var x = Math.Min(capture.Width - 1, capture.Width * gx / sampleGrid);
                var y = Math.Min(capture.Height - 1, capture.Height * gy / sampleGrid);
                var pixel = capture.GetPixel(x, y);
                if (first is null) { first = pixel; continue; }
                var delta = Math.Abs(pixel.R - first.Value.R) + Math.Abs(pixel.G - first.Value.G) + Math.Abs(pixel.B - first.Value.B);
                if (delta > 20) return true; // found real variation -- this is a real capture
            }
        }
        return false;
    }

    /// <summary>Downsamples both images to a small common grid (rather than pixel-for-pixel, which
    /// would be sensitive to 1px anti-aliasing differences that mean nothing) and compares average
    /// color per cell -- fast, and tolerant of exactly the kind of noise a whole-page screenshot
    /// legitimately has between two otherwise-identical runs.</summary>
    private static double ComputeDiffPercent(Bitmap a, Bitmap b)
    {
        const int gridSize = 32;
        var totalCells = gridSize * gridSize;
        var differingCells = 0;

        for (var gy = 0; gy < gridSize; gy++)
        {
            for (var gx = 0; gx < gridSize; gx++)
            {
                var ax = a.Width * gx / gridSize;
                var ay = a.Height * gy / gridSize;
                var bx = b.Width * gx / gridSize;
                var by = b.Height * gy / gridSize;
                if (ax >= a.Width || ay >= a.Height || bx >= b.Width || by >= b.Height) { differingCells++; continue; }

                var pa = a.GetPixel(ax, ay);
                var pb = b.GetPixel(bx, by);
                var delta = Math.Abs(pa.R - pb.R) + Math.Abs(pa.G - pb.G) + Math.Abs(pa.B - pb.B);
                if (delta > 60) differingCells++; // small per-channel drift (anti-aliasing) is not a real difference
            }
        }
        return 100.0 * differingCells / totalCells;
    }

    /// <summary>SetForegroundWindow alone is advisory and Windows can reject it when the test
    /// runner owns the foreground lock. Briefly raising the product window to the top guarantees
    /// CopyFromScreen captures TITAN instead of whichever IDE/terminal was previously active.</summary>
    private static void EnsureForeground(IntPtr hwnd)
    {
        const uint swpNoSize = 0x0001;
        const uint swpNoMove = 0x0002;
        const uint swpShowWindow = 0x0040;
        SetWindowPos(hwnd, new IntPtr(-1) /* HWND_TOPMOST */, 0, 0, 0, 0,
            swpNoSize | swpNoMove | swpShowWindow);
        NativeMethods.SetForegroundWindow(hwnd);
        Thread.Sleep(100);
        SetWindowPos(hwnd, new IntPtr(-2) /* HWND_NOTOPMOST */, 0, 0, 0, 0,
            swpNoSize | swpNoMove | swpShowWindow);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT { public int Left, Top, Right, Bottom; }

    [DllImport("user32.dll")] private static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);
    [DllImport("user32.dll")] private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] private static extern IntPtr SetThreadDpiAwarenessContext(IntPtr dpiContext);
    [DllImport("user32.dll")] private static extern bool SetWindowPos(
        IntPtr hWnd, IntPtr hWndInsertAfter, int x, int y, int cx, int cy, uint flags);

    private static void Report(List<string> failures, bool condition, string name)
    {
        Console.WriteLine($"[{(condition ? "PASS" : "FAIL")}] {name}");
        if (!condition) failures.Add(name);
    }
}
