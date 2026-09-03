using System.Windows.Media;
using TitanEndpoint.App.Common;
using TitanEndpoint.Core.Config;
using TitanEndpoint.Core.Health;

namespace TitanEndpoint.App.ViewModels;

public sealed class NavItemViewModel : ViewModelBase
{
    public AppPage Page { get; }
    public string Label { get; }
    public string IconGlyph { get; }
    public bool ShowDot { get; }
    private readonly EndpointId? _endpointId;

    private Brush _dotBrush = ThemeBrushes.Disabled;
    public Brush DotBrush { get => _dotBrush; private set => SetField(ref _dotBrush, value); }

    private bool _isSelected;
    public bool IsSelected { get => _isSelected; set => SetField(ref _isSelected, value); }

    public NavItemViewModel(AppPage page, string label, string iconGlyph, EndpointId? endpointId = null)
    {
        Page = page;
        Label = label;
        IconGlyph = iconGlyph;
        _endpointId = endpointId;
        ShowDot = endpointId.HasValue;
    }

    public void RefreshStatus()
    {
        if (_endpointId is null) return;
        var state = App.Fleet.Get(_endpointId.Value);
        var health = state.Tailer.LastHealth is null
            ? HealthStatus.Unknown
            : HealthSnapshot.FromRecord(state.Tailer.LastHealth).Status;
        DotBrush = ThemeBrushes.ForEndpointDot(state.IsRunning, health);
    }
}
