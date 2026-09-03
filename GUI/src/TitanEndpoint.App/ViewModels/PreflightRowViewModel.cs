using System.Windows.Media;
using TitanEndpoint.App.Common;
using TitanEndpoint.Core.Preflight;

namespace TitanEndpoint.App.ViewModels;

/// <summary>Presentation wrapper over Core's PreflightCheck -- keeps brush/glyph formatting out
/// of Core, matching this app's existing Row-ViewModel convention (e.g. StartAllRowViewModel).</summary>
public sealed class PreflightRowViewModel
{
    private readonly PreflightCheck _check;

    public PreflightRowViewModel(PreflightCheck check) => _check = check;

    public string Name => _check.Name;
    public string Detail => _check.Detail;
    public bool Passed => _check.Passed;

    public string StatusGlyph => Passed ? "OK"
        : _check.Severity == PreflightSeverity.Blocking ? "BLOCK"
        : "WARN";

    public Brush StatusBrush => Passed ? ThemeBrushes.Healthy
        : _check.Severity == PreflightSeverity.Blocking ? ThemeBrushes.Critical
        : ThemeBrushes.Warning;
}
