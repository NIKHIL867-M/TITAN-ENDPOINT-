using TitanEndpoint.App.Common;

namespace TitanEndpoint.App.ViewModels;

/// <summary>One AI-suggested response action (RuleIR.suggested_action) the human can accept
/// or reject before it becomes part of the real response_actions sent to /api/rules/approve.
/// Nothing here is ever auto-enabled — see spec section 13: "Never show model output as
/// automatically trusted."</summary>
public sealed class SuggestedActionRowViewModel : ViewModelBase
{
    public string ActionType { get; init; } = "";
    public bool RequiresExtraConfirmation => ActionType is "kill_process" or "isolate_host";

    private bool _isSelected;
    public bool IsSelected { get => _isSelected; set => SetField(ref _isSelected, value); }

    private bool _extraConfirmed;
    public bool ExtraConfirmed { get => _extraConfirmed; set => SetField(ref _extraConfirmed, value); }
}
