using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Windows.Threading;
using TitanEndpoint.App.Common;
using TitanEndpoint.Core.CustomRule;

namespace TitanEndpoint.App.ViewModels;

/// <summary>
/// The guided Describe -&gt; Review Structure -&gt; Test -&gt; Approve rule-authoring workflow
/// (FORU.TXT section 13), replacing the previous read-only-only Custom Rule page. Calls CUSTOM
/// RULE's existing FastAPI service (/api/parse-rule, /api/rules/from-yaml, /api/rules/draft-check,
/// /api/rules/approve) via CustomRuleApiClient — see that class for the auth/token story.
/// Supports a limited but real structured edit of the reviewed IR (severity/priority/
/// sustain_for/tags/investigation steps) — conditions/aggregation/correlation are preserved
/// as-is rather than edited, a deliberate scope limit rather than a half-built full editor.
/// Every edit invalidates the current simulation until the user explicitly re-validates
/// (13.6) — Approve is blocked while a revalidation is pending.
/// </summary>
public sealed class CustomRuleWizardViewModel : ViewModelBase
{
    private readonly CustomRuleApiClient _client;

    public CustomRuleWizardViewModel(CustomRuleApiClient client)
    {
        _client = client;
        ParseCommand = new RelayCommand(RunParse, () => !IsBusy);
        ParseYamlCommand = new RelayCommand(RunParseYaml, () => !IsBusy);
        SelectEnglishModeCommand = new RelayCommand(() => IsYamlMode = false);
        SelectYamlModeCommand = new RelayCommand(() => IsYamlMode = true);
        RevalidateCommand = new RelayCommand(RunRevalidate, () => !IsBusy && NeedsRevalidation);
        AddConditionCommand = new RelayCommand(() => AddCondition(new RuleConditionEditorViewModel()));
        RemoveConditionCommand = new RelayCommand(parameter =>
        {
            if (parameter is RuleConditionEditorViewModel row) { Conditions.Remove(row); MarkDirtyIfParsed(); }
        });
        ApproveCommand = new RelayCommand(RunApprove, () => CanApprove);
        BackCommand = new RelayCommand(() => Stage = Math.Max(1, Stage - 1), () => CanGoBack);
        NextCommand = new RelayCommand(() => Stage = Math.Min(4, Stage + 1), () => CanGoNext);
        _ = RefreshHealthAsync();

        // Santosh, 2026-08-07: health was only ever checked once at page-open, so an API restart
        // (e.g. picking up a freshly-added GROQ_API_KEY) left a stale "unreachable" banner showing
        // forever even after the API came back — the rule wizard itself kept working fine underneath
        // since Approve/parse-rule don't consult this cached flag, only the banner text was wrong.
        // Periodic re-check keeps it honest without needing a manual retry button.
        _healthTimer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromSeconds(5) };
        _healthTimer.Tick += async (_, _) => await RefreshHealthAsync();
        _healthTimer.Start();
    }

    private readonly DispatcherTimer _healthTimer;

    // ── Stage / navigation ──────────────────────────────────────────────
    private int _stage = 1;
    public int Stage { get => _stage; private set { if (SetField(ref _stage, value)) OnPropertyChanged(nameof(StageName)); } }
    public string StageName => Stage switch
    {
        1 => "1. Describe",
        2 => "2. Review Structure",
        3 => "3. Test",
        4 => "4. Approve",
        _ => ""
    };

    public bool CanGoBack => Stage > 1 && !IsBusy;
    public bool CanGoNext => Stage switch
    {
        1 => HasParsedSuccessfully && !IsBusy,
        2 => HasParsedSuccessfully && !IsBusy && !NeedsRevalidation,
        3 => HasParsedSuccessfully && !IsBusy && !NeedsRevalidation,
        _ => false
    };

    public RelayCommand BackCommand { get; private set; } = null!;
    public RelayCommand NextCommand { get; private set; } = null!;

    // ── API health ───────────────────────────────────────────────────────
    private string _healthText = "Checking Custom Rule API...";
    public string HealthText { get => _healthText; private set => SetField(ref _healthText, value); }

    private bool _apiReachable;
    public bool ApiReachable { get => _apiReachable; private set => SetField(ref _apiReachable, value); }

    public async Task RefreshHealthAsync()
    {
        var health = await _client.CheckHealthAsync();
        ApiReachable = health.Reachable && health.Success;
        HealthText = !health.Reachable
            ? $"Custom Rule API is unreachable ({health.TransportError}). Start TITAN's Custom Rule desktop app first — this is a LOCAL SERVICE failure, unrelated to Groq quota (see the YAML fallback note below, which only helps when Groq itself is the problem)."
            : health.Success
                ? "Custom Rule API is reachable."
                : _client.TryGetToken(out _)
                    ? $"Custom Rule API responded with an error (HTTP {health.StatusCode})."
                    : "Custom Rule API is running but no valid access token was found — restart the Custom Rule desktop app so it can publish a fresh token.";
    }

    // ── Stage 1: Describe ────────────────────────────────────────────────
    private string _ruleText = "";
    public string RuleText { get => _ruleText; set => SetField(ref _ruleText, value); }

    /// <summary>FORU.TXT 0.5.A: "Put two large first-class modes at the top: WRITE IN ENGLISH and
    /// WRITE/IMPORT YAML... Do not hide YAML behind a small checkbox." Selected via
    /// SelectEnglishModeCommand/SelectYamlModeCommand from two equally prominent buttons rather than
    /// a checkbox — switching preserves whatever text is already in either box (FORU.TXT: "Switching
    /// modes must preserve unsaved text").</summary>
    private bool _isYamlMode;
    public bool IsYamlMode { get => _isYamlMode; set => SetField(ref _isYamlMode, value); }

    public RelayCommand SelectEnglishModeCommand { get; }
    public RelayCommand SelectYamlModeCommand { get; }

    private string _yamlText = "";
    public string YamlText { get => _yamlText; set => SetField(ref _yamlText, value); }

    public RelayCommand ParseYamlCommand { get; }

    private bool _isBusy;
    public bool IsBusy
    {
        get => _isBusy;
        private set { if (SetField(ref _isBusy, value)) RaiseAllCanExecuteChanged(); }
    }

    private string _parseErrorText = "";
    public string ParseErrorText { get => _parseErrorText; private set => SetField(ref _parseErrorText, value); }

    private bool _isBlocked;
    public bool IsBlocked { get => _isBlocked; private set => SetField(ref _isBlocked, value); }

    private string _blockedMessage = "";
    public string BlockedMessage { get => _blockedMessage; private set => SetField(ref _blockedMessage, value); }

    public RelayCommand ParseCommand { get; }

    // ── Parsed result (Stages 2-4) ───────────────────────────────────────
    private bool _hasParsedSuccessfully;
    public bool HasParsedSuccessfully
    {
        get => _hasParsedSuccessfully;
        private set { if (SetField(ref _hasParsedSuccessfully, value)) RaiseAllCanExecuteChanged(); }
    }

    /// <summary>FORU.TXT 13.6: set whenever an editable field changes after a successful parse;
    /// cleared only by a fresh RevalidateCommand round-trip. Approve and Next (past Review/Test)
    /// are blocked while this is true — never approve or test stale pre-edit output.</summary>
    private bool _needsRevalidation;
    public bool NeedsRevalidation
    {
        get => _needsRevalidation;
        private set { if (SetField(ref _needsRevalidation, value)) RaiseAllCanExecuteChanged(); }
    }

    private JsonElement _ir;
    private string _triggerEvent = "";
    public string TriggerEvent { get => _triggerEvent; set { if (SetField(ref _triggerEvent, value)) MarkDirtyIfParsed(); } }

    private string _severity = "";
    public string Severity
    {
        get => _severity;
        set { if (SetField(ref _severity, value)) MarkDirtyIfParsed(); }
    }

    private int _priority;
    public int Priority
    {
        get => _priority;
        set { if (SetField(ref _priority, value)) MarkDirtyIfParsed(); }
    }

    private string _sustainFor = "";
    public string SustainFor
    {
        get => _sustainFor;
        set { if (SetField(ref _sustainFor, value)) MarkDirtyIfParsed(); }
    }

    private string _tagsText = "";
    public string TagsText
    {
        get => _tagsText;
        set { if (SetField(ref _tagsText, value)) MarkDirtyIfParsed(); }
    }

    private string _investigationStepsText = "";
    public string InvestigationStepsText
    {
        get => _investigationStepsText;
        set { if (SetField(ref _investigationStepsText, value)) MarkDirtyIfParsed(); }
    }

    public ObservableCollection<RuleConditionEditorViewModel> Conditions { get; } = new();
    public RelayCommand AddConditionCommand { get; }
    public RelayCommand RemoveConditionCommand { get; }

    private bool _aggregationEnabled;
    public bool AggregationEnabled { get => _aggregationEnabled; set { if (SetField(ref _aggregationEnabled, value)) MarkDirtyIfParsed(); } }
    private string _aggregationKeys = "";
    public string AggregationKeys { get => _aggregationKeys; set { if (SetField(ref _aggregationKeys, value)) MarkDirtyIfParsed(); } }
    private string _aggregationWindow = "";
    public string AggregationWindow { get => _aggregationWindow; set { if (SetField(ref _aggregationWindow, value)) MarkDirtyIfParsed(); } }
    private int _aggregationThreshold = 1;
    public int AggregationThreshold { get => _aggregationThreshold; set { if (SetField(ref _aggregationThreshold, value)) MarkDirtyIfParsed(); } }

    private bool _correlationEnabled;
    public bool CorrelationEnabled { get => _correlationEnabled; set { if (SetField(ref _correlationEnabled, value)) MarkDirtyIfParsed(); } }
    private string _correlationWithin = "";
    public string CorrelationWithin { get => _correlationWithin; set { if (SetField(ref _correlationWithin, value)) MarkDirtyIfParsed(); } }
    private string _correlationJoinOn = "";
    public string CorrelationJoinOn { get => _correlationJoinOn; set { if (SetField(ref _correlationJoinOn, value)) MarkDirtyIfParsed(); } }
    private bool _correlationOrdered = true;
    public bool CorrelationOrdered { get => _correlationOrdered; set { if (SetField(ref _correlationOrdered, value)) MarkDirtyIfParsed(); } }
    private string _correlationStagesJson = "[]";
    public string CorrelationStagesJson { get => _correlationStagesJson; set { if (SetField(ref _correlationStagesJson, value)) MarkDirtyIfParsed(); } }
    public string SuggestedActionReason { get; private set; } = "";
    public string RawIrJson { get; private set; } = "";

    public bool IsValid { get; private set; }
    public ObservableCollection<string> ValidationErrors { get; } = new();
    public bool IsCapable { get; private set; }
    public ObservableCollection<string> CapabilityGaps { get; } = new();
    public ObservableCollection<string> InjectionFlagsList { get; } = new();

    public string SimulationSummary { get; private set; } = "";
    public string RawSimulationJson { get; private set; } = "";

    public string ModelMetaText { get; private set; } = "";

    public ObservableCollection<SuggestedActionRowViewModel> SuggestedActions { get; } = new();

    public RelayCommand RevalidateCommand { get; }

    private List<string> _injectionFlagsRaw = new();
    private List<string> _capabilityGapsRaw = new();
    private JsonElement? _retrievalTrace;
    private bool _suppressDirtyTracking;

    private void MarkDirtyIfParsed()
    {
        if (_suppressDirtyTracking || !HasParsedSuccessfully) return;
        NeedsRevalidation = true;
    }

    private async void RunParse()
    {
        ParseErrorText = "";
        IsBlocked = false;
        HasParsedSuccessfully = false;
        ResetEvaluationState();
        if (string.IsNullOrWhiteSpace(RuleText))
        {
            ParseErrorText = "Describe the rule in plain language before continuing.";
            return;
        }

        IsBusy = true;
        try
        {
            var result = await _client.ParseRuleAsync(RuleText);
            if (!result.Reachable)
            {
                ParseErrorText = $"Custom Rule API unreachable: {result.TransportError}";
                return;
            }
            if (result.Body is not { } body)
            {
                ParseErrorText = $"Unexpected response (HTTP {result.StatusCode}): {Truncate(result.RawBody, 300)}";
                return;
            }

            if (body.TryGetProperty("blocked", out var blockedEl) && blockedEl.ValueKind == JsonValueKind.True)
            {
                IsBlocked = true;
                BlockedMessage = body.TryGetProperty("message", out var m) ? m.GetString() ?? "Blocked." : "Blocked.";
                return;
            }

            if (!result.Success)
            {
                var error = body.TryGetProperty("error", out var e) ? e.GetString() : null;
                ParseErrorText = error switch
                {
                    "service_unavailable" => "The rule-parsing model (Groq) is temporarily unavailable (quota or outage). Switch to \"Use YAML Instead\" above — that path never calls Groq.",
                    _ => $"Rule parsing failed (HTTP {result.StatusCode}): {error ?? Truncate(result.RawBody, 300)}"
                };
                return;
            }

            var irWrapper = body.TryGetProperty("ir", out var irw) ? irw : default;

            // FOUND LIVE (real bug): the endpoint can return HTTP 200 with a body-level
            // "success": false when the model asks for clarification instead of producing a rule
            // (irWrapper.ir is then literally null) -- result.Success only reflects the HTTP status,
            // so this fell straight through into ApplyIr(null) and silently advanced to "Review
            // Structure" with every field blank, looking like a successful-but-empty parse.
            if (body.TryGetProperty("success", out var succEl) && succEl.ValueKind == JsonValueKind.False)
            {
                var status = irWrapper.ValueKind == JsonValueKind.Object && irWrapper.TryGetProperty("status", out var st) ? st.GetString() : null;
                var clarification = irWrapper.ValueKind == JsonValueKind.Object && irWrapper.TryGetProperty("clarification", out var c) ? c.GetString() : null;
                var bodyError = body.TryGetProperty("error", out var e2) ? e2.GetString() : null;
                ParseErrorText = status == "needs_clarification"
                    ? $"The AI needs more detail before it can build this rule: {clarification ?? "Please add more specifics and try again."}"
                    : $"Rule parsing did not produce a usable rule: {bodyError ?? clarification ?? "Try rephrasing the rule with more specific detail."}";
                return;
            }

            var innerIr = irWrapper.ValueKind == JsonValueKind.Object && irWrapper.TryGetProperty("ir", out var inner)
                ? inner : default;

            ApplyIr(innerIr);
            ApplyValidationCapabilitySimulation(
                validation: body.TryGetProperty("validation", out var val) ? val : default,
                capability: body.TryGetProperty("capability", out var cap) ? cap : default,
                simulation: body.TryGetProperty("simulation", out var sim) ? sim : default);

            InjectionFlagsList.Clear();
            _injectionFlagsRaw.Clear();
            foreach (var flag in EnumerateStrings(body, "injection_flags"))
            {
                InjectionFlagsList.Add(flag);
                _injectionFlagsRaw.Add(flag);
            }

            if (body.TryGetProperty("retrieval", out var retr)) _retrievalTrace = retr.Clone();

            if (body.TryGetProperty("meta", out var meta) && meta.ValueKind == JsonValueKind.Object)
            {
                var model = GetString(meta, "model_used");
                var ms = meta.TryGetProperty("response_time_ms", out var rt) ? rt.ToString() : "?";
                var budget = meta.TryGetProperty("budget_used", out var bu) ? bu.ToString() : "?";
                ModelMetaText = $"Model: {model} — {ms} ms — budget used: {budget}";
                OnPropertyChanged(nameof(ModelMetaText));
            }

            NeedsRevalidation = false;
            HasParsedSuccessfully = true;
            IsYamlMode = false;
            Stage = 2;
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async void RunParseYaml()
    {
        ParseErrorText = "";
        IsBlocked = false;
        HasParsedSuccessfully = false;
        ResetEvaluationState();
        if (string.IsNullOrWhiteSpace(YamlText))
        {
            ParseErrorText = "Enter or paste YAML before continuing.";
            return;
        }

        IsBusy = true;
        try
        {
            var result = await _client.FromYamlAsync(YamlText);
            ApplyDraftCheckShapeResponse(result, onSuccess: () =>
            {
                _injectionFlagsRaw.Clear();
                InjectionFlagsList.Clear();
                _retrievalTrace = null;
                ModelMetaText = "Parsed from YAML — Groq was not called.";
                OnPropertyChanged(nameof(ModelMetaText));
                NeedsRevalidation = false;
                HasParsedSuccessfully = true;
                IsYamlMode = true;
                Stage = 2;
            });
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async void RunRevalidate()
    {
        if (_ir.ValueKind != JsonValueKind.Object)
        {
            ParseErrorText = "No IR to revalidate — describe or import a rule first.";
            return;
        }

        IsBusy = true;
        try
        {
            var dict = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(_ir.GetRawText())
                       ?? new Dictionary<string, JsonElement>();

            dict["severity"] = JsonSerializer.SerializeToElement(Severity);
            dict["priority"] = JsonSerializer.SerializeToElement(Priority);
            dict["sustain_for"] = string.IsNullOrWhiteSpace(SustainFor)
                ? JsonSerializer.SerializeToElement<string?>(null)
                : JsonSerializer.SerializeToElement(SustainFor);
            dict["tags"] = JsonSerializer.SerializeToElement(SplitLines(TagsText, ','));
            dict["investigation_steps"] = JsonSerializer.SerializeToElement(SplitLines(InvestigationStepsText, '\n'));
            dict["trigger_event"] = JsonSerializer.SerializeToElement(TriggerEvent.Trim());
            dict["conditions"] = JsonSerializer.SerializeToElement(Conditions.Select(condition =>
                new Dictionary<string, object?> { ["field"] = condition.Field.Trim(), ["operator"] = condition.Operator.Trim(), ["value"] = condition.TypedValue() }).ToArray());
            dict["aggregation"] = AggregationEnabled
                ? JsonSerializer.SerializeToElement<object>(new { key = SplitLines(AggregationKeys, ','), window = AggregationWindow.Trim(), threshold = AggregationThreshold })
                : JsonSerializer.SerializeToElement<object?>(null);
            if (CorrelationEnabled)
            {
                using var stages = JsonDocument.Parse(CorrelationStagesJson);
                if (stages.RootElement.ValueKind != JsonValueKind.Array) throw new JsonException("Correlation stages must be a JSON array.");
                dict["correlation"] = JsonSerializer.SerializeToElement<object>(new
                {
                    stages = stages.RootElement.Clone(), within = CorrelationWithin.Trim(),
                    join_on = SplitLines(CorrelationJoinOn, ','), ordered = CorrelationOrdered
                });
            }
            else dict["correlation"] = JsonSerializer.SerializeToElement<object?>(null);

            var result = await _client.DraftCheckAsync(dict);
            ApplyDraftCheckShapeResponse(result, onSuccess: () =>
            {
                NeedsRevalidation = false;
                ParseErrorText = "";
            });
        }
        catch (JsonException ex)
        {
            ParseErrorText = $"Structured correlation JSON is invalid: {ex.Message}";
            NeedsRevalidation = true;
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>Shared handler for /api/rules/from-yaml and /api/rules/draft-check — both return
    /// the identical {"valid","errors","simulation","capability","normalized_draft"} shape.</summary>
    private void ApplyDraftCheckShapeResponse(CustomRuleApiResult result, Action onSuccess)
    {
        if (!result.Reachable)
        {
            ParseErrorText = $"Custom Rule API unreachable: {result.TransportError}";
            return;
        }
        if (result.Body is not { } body)
        {
            ParseErrorText = $"Unexpected response (HTTP {result.StatusCode}): {Truncate(result.RawBody, 300)}";
            return;
        }

        var valid = body.TryGetProperty("valid", out var v) && v.ValueKind == JsonValueKind.True;
        if (!valid)
        {
            var errors = EnumerateStrings(body, "errors").ToList();
            ParseErrorText = errors.Count > 0
                ? "Validation failed: " + string.Join("; ", errors)
                : $"Validation failed (HTTP {result.StatusCode}).";
            ValidationErrors.Clear();
            foreach (var err in errors) ValidationErrors.Add(err);
            IsValid = false;
            IsCapable = false;
            OnPropertyChanged(nameof(IsValid));
            OnPropertyChanged(nameof(IsCapable));
            RaiseAllCanExecuteChanged();
            return;
        }

        if (body.TryGetProperty("normalized_draft", out var draft) && draft.ValueKind == JsonValueKind.Object)
            ApplyIr(draft);

        ApplyValidationCapabilitySimulation(
            validation: body.TryGetProperty("validation", out var val) ? val : MakeValidTrue(),
            capability: body.TryGetProperty("capability", out var cap) ? cap : default,
            simulation: body.TryGetProperty("simulation", out var sim) ? sim : default);

        onSuccess();
    }

    private static JsonElement MakeValidTrue() =>
        JsonSerializer.SerializeToElement(new { valid = true, errors = Array.Empty<string>() });

    /// <summary>Populates the editable fields + read-only condition/suggested-action display
    /// from a RuleIR object, wherever it came from (parse-rule's nested ir.ir, or from-yaml/
    /// draft-check's normalized_draft — same schema either way).</summary>
    private void ApplyIr(JsonElement ir)
    {
        _ir = ir;
        RawIrJson = ir.ValueKind == JsonValueKind.Object
            ? JsonSerializer.Serialize(ir, new JsonSerializerOptions { WriteIndented = true })
            : "No IR returned.";
        OnPropertyChanged(nameof(RawIrJson));

        Conditions.Clear();
        SuggestedActions.Clear();

        if (ir.ValueKind != JsonValueKind.Object) return;

        _suppressDirtyTracking = true;
        TriggerEvent = GetString(ir, "trigger_event");
        Severity = GetString(ir, "severity");
        Priority = ir.TryGetProperty("priority", out var p) && p.ValueKind == JsonValueKind.Number ? p.GetInt32() : 0;
        SustainFor = GetString(ir, "sustain_for");
        SuggestedActionReason = GetString(ir, "suggested_action_reason");
        OnPropertyChanged(nameof(SuggestedActionReason));
        TagsText = string.Join(", ", EnumerateStrings(ir, "tags"));
        InvestigationStepsText = string.Join(Environment.NewLine, EnumerateStrings(ir, "investigation_steps"));
        if (ir.TryGetProperty("conditions", out var conditions) && conditions.ValueKind == JsonValueKind.Array)
            foreach (var condition in conditions.EnumerateArray())
                AddCondition(new RuleConditionEditorViewModel
                {
                    Field = GetString(condition, "field"), Operator = GetString(condition, "operator"),
                    Value = condition.TryGetProperty("value", out var value) ? (value.ValueKind == JsonValueKind.String ? value.GetString() ?? "" : value.GetRawText()) : ""
                });
        AggregationEnabled = ir.TryGetProperty("aggregation", out var aggregation) && aggregation.ValueKind == JsonValueKind.Object;
        if (AggregationEnabled)
        {
            AggregationKeys = string.Join(", ", EnumerateStrings(aggregation, "key"));
            AggregationWindow = GetString(aggregation, "window");
            AggregationThreshold = aggregation.TryGetProperty("threshold", out var threshold) && threshold.TryGetInt32(out var thresholdValue) ? thresholdValue : 1;
        }
        CorrelationEnabled = ir.TryGetProperty("correlation", out var correlation) && correlation.ValueKind == JsonValueKind.Object;
        if (CorrelationEnabled)
        {
            CorrelationWithin = GetString(correlation, "within");
            CorrelationJoinOn = string.Join(", ", EnumerateStrings(correlation, "join_on"));
            CorrelationOrdered = !correlation.TryGetProperty("ordered", out var ordered) || ordered.ValueKind == JsonValueKind.True;
            CorrelationStagesJson = correlation.TryGetProperty("stages", out var stages)
                ? JsonSerializer.Serialize(stages, new JsonSerializerOptions { WriteIndented = true }) : "[]";
        }
        _suppressDirtyTracking = false;
        foreach (var a in EnumerateStrings(ir, "suggested_action"))
            SuggestedActions.Add(new SuggestedActionRowViewModel { ActionType = a });
    }

    private void ApplyValidationCapabilitySimulation(JsonElement validation, JsonElement capability, JsonElement simulation)
    {
        ValidationErrors.Clear();
        CapabilityGaps.Clear();
        _capabilityGapsRaw.Clear();

        IsValid = validation.ValueKind == JsonValueKind.Object &&
                  validation.TryGetProperty("valid", out var v) && v.ValueKind == JsonValueKind.True;
        if (validation.ValueKind == JsonValueKind.Object)
            foreach (var err in EnumerateStrings(validation, "errors")) ValidationErrors.Add(err);
        OnPropertyChanged(nameof(IsValid));

        IsCapable = capability.ValueKind == JsonValueKind.Object &&
                    capability.TryGetProperty("capable", out var c) && c.ValueKind == JsonValueKind.True;
        if (capability.ValueKind == JsonValueKind.Object)
            foreach (var gap in EnumerateStrings(capability, "gaps"))
            {
                CapabilityGaps.Add(gap);
                _capabilityGapsRaw.Add(gap);
            }
        OnPropertyChanged(nameof(IsCapable));
        RaiseAllCanExecuteChanged();

        if (simulation.ValueKind == JsonValueKind.Object)
        {
            SimulationSummary = simulation.TryGetProperty("summary", out var s2) ? (s2.GetString() ?? "N/A") : "N/A";
            RawSimulationJson = JsonSerializer.Serialize(simulation, new JsonSerializerOptions { WriteIndented = true });
        }
        else
        {
            SimulationSummary = "N/A";
            RawSimulationJson = "";
        }
        OnPropertyChanged(nameof(SimulationSummary));
        OnPropertyChanged(nameof(RawSimulationJson));
    }

    // ── Stage 4: Approve ─────────────────────────────────────────────────
    private string _approveResultText = "";
    public string ApproveResultText { get => _approveResultText; private set => SetField(ref _approveResultText, value); }

    private bool _approveSucceeded;
    public bool ApproveSucceeded { get => _approveSucceeded; private set => SetField(ref _approveSucceeded, value); }

    public RelayCommand ApproveCommand { get; }

    public bool CanApprove =>
        !IsBusy && HasParsedSuccessfully && !NeedsRevalidation && IsValid && IsCapable &&
        SuggestedActions.Where(a => a.IsSelected).All(a => !a.RequiresExtraConfirmation || a.ExtraConfirmed);

    private async void RunApprove()
    {
        IsBusy = true;
        ApproveResultText = "";
        try
        {
            var beforeRuntime = await _client.GetWatcherRuntimeAsync();
            var previousRuleCount = ReadRuleCount(beforeRuntime);
            var selected = SuggestedActions.Where(a => a.IsSelected).Select(a => a.ActionType).ToList();
            if (selected.Count == 0) selected.Add("alert"); // matches server-side default (main.py: falls back to alert when empty)

            // FOUND LIVE (real, previously-unknown bug): _ir holds the FLAT RuleIR (trigger_event,
            // conditions, ... -- see ApplyIr), which is the correct shape for RunRevalidate's
            // draft-check call, but /api/rules/approve's ApproveRequest.ir specifically requires the
            // wrapped ParseResult shape ({"status","clarification","ir":<flat>,"explanation"}) -- the
            // same wrapping every stored rule in data/rules.jsonl already has. Confirmed empirically
            // against the real backend: sending _ir unwrapped gets a 400 "Expected a complete IR
            // object" on every Approve, from both the English and YAML paths, every time -- Approve
            // has never actually worked from this wizard until this fix.
            var wrappedIr = JsonSerializer.SerializeToElement(new
            {
                status = "ok",
                clarification = (string?)null,
                ir = _ir,
                explanation = (object?)null
            });

            var result = await _client.ApproveAsync(
                BuildApprovalSourceText(), wrappedIr, _injectionFlagsRaw, _capabilityGapsRaw, selected, _retrievalTrace);

            if (!result.Reachable)
            {
                ApproveResultText = $"Could not reach Custom Rule API: {result.TransportError}";
                ApproveSucceeded = false;
                return;
            }
            if (result.Success && result.Body is { } body)
            {
                var status = GetString(body, "status");
                var ruleId = GetString(body, "rule_id");
                ApproveResultText = $"Rule {status} — id {ruleId}. The running watcher reloads its rule set automatically the next time it polls rules.jsonl.";
                ApproveSucceeded = true;
                ApproveResultText = $"Rule {status} - id {ruleId}. Waiting for watcher reload acknowledgement...";
                var acknowledgement = await WaitForWatcherReloadAsync(previousRuleCount);
                ApproveResultText = $"Rule {status} - id {ruleId}. {acknowledgement}";
            }
            else
            {
                var messages = result.Body is { } errBody && errBody.TryGetProperty("messages", out var m) && m.ValueKind == JsonValueKind.Array
                    ? string.Join("; ", m.EnumerateArray().Select(e => e.GetString()))
                    : Truncate(result.RawBody, 300);
                ApproveResultText = $"Approval failed (HTTP {result.StatusCode}): {messages}";
                ApproveSucceeded = false;
            }
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task<string> WaitForWatcherReloadAsync(int? previousRuleCount)
    {
        for (var attempt = 0; attempt < 12; attempt++)
        {
            if (attempt > 0) await Task.Delay(500);
            var runtime = await _client.GetWatcherRuntimeAsync();
            if (!runtime.Success || runtime.Body is not { } body) continue;

            var running = body.TryGetProperty("running", out var runningElement) &&
                          runningElement.ValueKind == JsonValueKind.True;
            var currentRuleCount = ReadRuleCount(runtime);
            if (running && currentRuleCount is not null &&
                (previousRuleCount is null || currentRuleCount.Value > previousRuleCount.Value))
                return $"Watcher acknowledged the reload and now has {currentRuleCount.Value} rules loaded.";
        }

        return "The rule was saved, but the watcher did not acknowledge loading it within 6 seconds. Treat it as inactive until watcher status confirms the new rule count.";
    }

    private static int? ReadRuleCount(CustomRuleApiResult result)
    {
        if (!result.Success || result.Body is not { } body ||
            !body.TryGetProperty("rules_loaded", out var count) || count.ValueKind != JsonValueKind.Number)
            return null;
        return count.TryGetInt32(out var value) ? value : null;
    }

    private string BuildApprovalSourceText()
    {
        if (!IsYamlMode && !string.IsNullOrWhiteSpace(RuleText)) return RuleText.Trim();

        var sourceHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(YamlText))).ToLowerInvariant();
        return $"YAML rule: trigger={TriggerEvent}; severity={Severity}; priority={Priority}; source_sha256={sourceHash}";
    }

    private void ResetEvaluationState()
    {
        IsValid = false;
        IsCapable = false;
        ValidationErrors.Clear();
        CapabilityGaps.Clear();
        _capabilityGapsRaw.Clear();
        OnPropertyChanged(nameof(IsValid));
        OnPropertyChanged(nameof(IsCapable));
        RaiseAllCanExecuteChanged();
    }

    private void RaiseAllCanExecuteChanged()
    {
        BackCommand?.RaiseCanExecuteChanged();
        NextCommand?.RaiseCanExecuteChanged();
        ApproveCommand?.RaiseCanExecuteChanged();
        RevalidateCommand?.RaiseCanExecuteChanged();
        OnPropertyChanged(nameof(CanGoBack));
        OnPropertyChanged(nameof(CanGoNext));
        OnPropertyChanged(nameof(CanApprove));
    }

    private void AddCondition(RuleConditionEditorViewModel condition)
    {
        condition.PropertyChanged += (_, _) => MarkDirtyIfParsed();
        Conditions.Add(condition);
        MarkDirtyIfParsed();
    }

    private static string GetString(JsonElement e, string key) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString() ?? "" : "";

    private static IEnumerable<string> EnumerateStrings(JsonElement e, string key)
    {
        if (e.ValueKind != JsonValueKind.Object || !e.TryGetProperty(key, out var arr) || arr.ValueKind != JsonValueKind.Array)
            yield break;
        foreach (var item in arr.EnumerateArray())
            if (item.ValueKind == JsonValueKind.String) yield return item.GetString() ?? "";
    }

    private static List<string> SplitLines(string text, char separator) =>
        text.Split(separator, StringSplitOptions.RemoveEmptyEntries)
            .Select(s => s.Trim())
            .Where(s => s.Length > 0)
            .ToList();

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max] + "...";

    /// <summary>RuleIR.conditions items are {field, operator, value} objects (see
    /// app/semantic_validator.py's Condition model) — rendered as "field operator value"
    /// rather than raw JSON for readability; falls back to raw JSON for any shape mismatch.</summary>
    private static IEnumerable<string> EnumerateConditions(JsonElement ir)
    {
        if (ir.ValueKind != JsonValueKind.Object || !ir.TryGetProperty("conditions", out var arr) || arr.ValueKind != JsonValueKind.Array)
            yield break;
        foreach (var item in arr.EnumerateArray())
        {
            if (item.ValueKind == JsonValueKind.Object &&
                item.TryGetProperty("field", out var f) &&
                item.TryGetProperty("operator", out var op) &&
                item.TryGetProperty("value", out var v))
            {
                yield return $"{f.GetString()} {op.GetString()} {(v.ValueKind == JsonValueKind.String ? v.GetString() : v.GetRawText())}";
            }
            else
            {
                yield return item.GetRawText();
            }
        }
    }
}

public sealed class RuleConditionEditorViewModel : ViewModelBase
{
    private string _field = "";
    public string Field { get => _field; set => SetField(ref _field, value); }
    private string _operator = "equals";
    public string Operator { get => _operator; set => SetField(ref _operator, value); }
    private string _value = "";
    public string Value { get => _value; set => SetField(ref _value, value); }
    public object? TypedValue()
    {
        var trimmed = Value.Trim();
        if (bool.TryParse(trimmed, out var boolean)) return boolean;
        if (long.TryParse(trimmed, out var integer)) return integer;
        if (double.TryParse(trimmed, out var real)) return real;
        if ((trimmed.StartsWith('[') && trimmed.EndsWith(']')) || (trimmed.StartsWith('{') && trimmed.EndsWith('}')))
        { try { return JsonSerializer.Deserialize<JsonElement>(trimmed); } catch (JsonException) { } }
        return Value;
    }
}
