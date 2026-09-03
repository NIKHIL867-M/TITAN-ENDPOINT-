using System.IO;
using System.Text.Json;
using System.Windows;

namespace TitanEndpoint.App.Common;

/// <summary>FORU.TXT 0.4: "Persist only safe presentation preferences -- window bounds, navigation
/// width, table density, column order/width/visibility, splitter positions, selected Network
/// workspace tab, and theme/accessibility preferences. Restore them with bounds checking; corrupt
/// layout state must fall back to defaults without breaking startup."
///
/// A flat, forward-compatible key/value store (not one hard-coded settings class) so any page can
/// persist an arbitrary named layout value -- a DataGrid's column widths, a splitter's position, a
/// selected tab index -- via SetValue/TryGetValue without this file needing to know about every
/// page in advance. Window bounds get dedicated helpers because they need OS work-area bounds
/// checking, which a generic value store cannot do on the caller's behalf.
/// </summary>
public sealed class LayoutPreferenceStore
{
    private readonly string _path;
    private Dictionary<string, JsonElement> _values = new();
    private bool _loaded;

    public LayoutPreferenceStore(string titanRootDirectory)
    {
        _path = Path.Combine(titanRootDirectory, ".titan-runtime", "gui_layout.json");
    }

    private void EnsureLoaded()
    {
        if (_loaded) return;
        _loaded = true;
        try
        {
            if (File.Exists(_path))
            {
                var json = File.ReadAllText(_path);
                var parsed = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json);
                if (parsed is not null) _values = parsed;
            }
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            // Corrupt or unreadable layout state must never break startup (FORU.TXT 0.4) -- fall
            // back to an empty store, which every caller already treats as "no saved preference."
            _values = new Dictionary<string, JsonElement>();
        }
    }

    private void Save()
    {
        try
        {
            var dir = Path.GetDirectoryName(_path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            var tmp = _path + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(_values, new JsonSerializerOptions { WriteIndented = true }));
            File.Copy(tmp, _path, overwrite: true);
            File.Delete(tmp);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Best effort -- a failed layout save must never surface as a user-facing error or
            // block window close.
        }
    }

    public void SetValue<T>(string key, T value)
    {
        EnsureLoaded();
        _values[key] = JsonSerializer.SerializeToElement(value);
        Save();
    }

    public bool TryGetValue<T>(string key, out T? value)
    {
        EnsureLoaded();
        value = default;
        if (!_values.TryGetValue(key, out var element)) return false;
        try
        {
            value = element.Deserialize<T>();
            return value is not null;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private const string WindowBoundsKey = "MainWindow.Bounds";

    public void SaveWindowBounds(Window window)
    {
        // RestoreBounds reflects the pre-maximize/minimize size on a maximized/minimized window --
        // saving raw Left/Top/Width/Height while maximized would persist the maximized geometry
        // (usually {0,0,ScreenWidth,ScreenHeight}), which is not a useful "restored" size next launch.
        var bounds = window.WindowState == WindowState.Normal ? new Rect(window.Left, window.Top, window.Width, window.Height) : window.RestoreBounds;
        SetValue(WindowBoundsKey, new SavedWindowBounds(bounds.Left, bounds.Top, bounds.Width, bounds.Height, window.WindowState == WindowState.Maximized));
    }

    /// <summary>Bounds-checked restore (FORU.TXT 0.4): a saved position from a monitor
    /// configuration that no longer exists must not strand the window off-screen. Returns whether
    /// saved bounds were actually applied -- callers must decide their own fallback WindowState
    /// (e.g. Maximized) in code rather than relying on a XAML default, since WPF's internal
    /// show-window sequence for a XAML-declared WindowState="Maximized" wins over a WindowState
    /// change made later from any lifecycle event (constructor, SourceInitialized, or Loaded),
    /// silently discarding a restored Normal size -- found empirically 2026-08-02.</summary>
    public bool RestoreWindowBounds(Window window)
    {
        if (!TryGetValue<SavedWindowBounds>(WindowBoundsKey, out var saved) || saved is null) return false;

        var virtualScreen = new Rect(SystemParameters.VirtualScreenLeft, SystemParameters.VirtualScreenTop,
            SystemParameters.VirtualScreenWidth, SystemParameters.VirtualScreenHeight);
        var candidate = new Rect(saved.Left, saved.Top, Math.Max(saved.Width, window.MinWidth), Math.Max(saved.Height, window.MinHeight));

        // Require at least a corner of the saved rectangle to actually land inside a currently
        // connected monitor's virtual-screen bounds; otherwise a removed/reconfigured monitor
        // would otherwise place the window somewhere the user can never reach it.
        var visibleCorner = new Rect(candidate.Left, candidate.Top, Math.Min(40, candidate.Width), Math.Min(40, candidate.Height));
        if (!virtualScreen.IntersectsWith(visibleCorner)) return false;

        // WindowStartupLocation="CenterScreen" (MainWindow.xaml's default) recomputes and overwrites
        // Left/Top when the window is shown, discarding whatever was set here beforehand -- Manual
        // is required for an explicit restored position to actually stick.
        window.WindowStartupLocation = WindowStartupLocation.Manual;
        window.Left = candidate.Left;
        window.Top = candidate.Top;
        window.Width = candidate.Width;
        window.Height = candidate.Height;
        window.WindowState = saved.Maximized ? WindowState.Maximized : WindowState.Normal;
        return true;
    }

    private sealed record SavedWindowBounds(double Left, double Top, double Width, double Height, bool Maximized);
}
