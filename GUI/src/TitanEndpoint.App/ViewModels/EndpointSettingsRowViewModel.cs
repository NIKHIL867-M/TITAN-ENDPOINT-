using System.IO;
using System.Linq;
using TitanEndpoint.App.Common;
using TitanEndpoint.Core.Config;

namespace TitanEndpoint.App.ViewModels;

public sealed class EndpointSettingsRowViewModel : ViewModelBase
{
    private static readonly char[] InvalidLogPatternChars =
        Path.GetInvalidFileNameChars().Where(c => c != '*' && c != '?').ToArray();

    private readonly EndpointDefinition _def;
    public string DisplayName => _def.DisplayName;
    public bool RequiresElevation => _def.RequiresElevation;
    public bool IsExecutableEditable => string.IsNullOrWhiteSpace(_def.ManifestExePath);
    public bool IsExecutableReadOnly => !IsExecutableEditable;
    public string ExecutableSource => IsExecutableEditable ? "User setting" : "Runtime manifest (authoritative)";

    private string _exePath;
    private string _logDirectory;
    private string _logFilePattern;

    public string ExePath
    {
        get => _exePath;
        set => SetField(ref _exePath, value);
    }

    public string LogDirectory
    {
        get => _logDirectory;
        set => SetField(ref _logDirectory, value);
    }

    public string LogFilePattern
    {
        get => _logFilePattern;
        set => SetField(ref _logFilePattern, value);
    }

    public EndpointSettingsRowViewModel(EndpointDefinition def)
    {
        _def = def;
        _exePath = def.ManifestExePath ?? def.ExeCandidatePaths.FirstOrDefault() ?? "";
        _logDirectory = def.LogDirectory;
        _logFilePattern = def.LogFilePattern;
    }

    public IEnumerable<string> Validate()
    {
        if (string.IsNullOrWhiteSpace(ExePath)) yield return $"{DisplayName}: executable path is required.";
        else if (!IsValidPath(ExePath)) yield return $"{DisplayName}: executable path is invalid.";
        if (string.IsNullOrWhiteSpace(LogDirectory)) yield return $"{DisplayName}: log directory is required.";
        else if (!IsValidPath(LogDirectory)) yield return $"{DisplayName}: log directory is invalid.";
        // Santosh, 2026-08-31: "make sure that everything works properly" -- found while wiring the
        // new light/dark theme setting: Save Settings has been completely broken from a fresh
        // default state for every endpoint, always, unrelated to theme. Path.GetInvalidFileNameChars()
        // includes '*' and '?' (correctly, for a literal filename) -- but LogFilePattern is a glob
        // SEARCH PATTERN (TitanSettings.cs's own defaults are "titan_*.jsonl", "*.json*", etc.), not
        // a filename, so every single default value tripped this check and Save Settings silently
        // failed with "log file pattern is invalid" on all six endpoints, every time, for anyone who
        // had never customized this field. '*'/'?' are the only two characters .NET's own directory-
        // search glob syntax uses, so they are excluded here; everything else GetInvalidFileNameChars
        // flags (path separators, quotes, control characters, etc.) still correctly fails.
        var invalidPatternChars = InvalidLogPatternChars;
        if (string.IsNullOrWhiteSpace(LogFilePattern) || LogFilePattern.IndexOfAny(invalidPatternChars) >= 0)
            yield return $"{DisplayName}: log file pattern is invalid.";
    }

    public void Apply()
    {
        if (IsExecutableEditable)
        {
            if (_def.ExeCandidatePaths.Count == 0) _def.ExeCandidatePaths.Add(ExePath.Trim());
            else _def.ExeCandidatePaths[0] = ExePath.Trim();
        }
        _def.LogDirectory = LogDirectory.Trim();
        _def.LogFilePattern = LogFilePattern.Trim();
    }

    public EndpointSettingsSnapshot Capture() => new(
        _def.ExeCandidatePaths.ToList(), _def.LogDirectory, _def.LogFilePattern);

    public void Restore(EndpointSettingsSnapshot snapshot)
    {
        _def.ExeCandidatePaths = snapshot.ExeCandidatePaths.ToList();
        _def.LogDirectory = snapshot.LogDirectory;
        _def.LogFilePattern = snapshot.LogFilePattern;
    }

    private static bool IsValidPath(string path)
    {
        try { _ = Path.GetFullPath(Environment.ExpandEnvironmentVariables(path)); return true; }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { return false; }
    }
}

public sealed record EndpointSettingsSnapshot(
    IReadOnlyList<string> ExeCandidatePaths, string LogDirectory, string LogFilePattern);
