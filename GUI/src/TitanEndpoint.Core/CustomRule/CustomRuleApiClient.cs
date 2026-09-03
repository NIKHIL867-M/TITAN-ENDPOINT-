using System.Text;
using System.Text.Json;

namespace TitanEndpoint.Core.CustomRule;

public sealed class CustomRuleApiResult
{
    public bool Success { get; init; }
    public int StatusCode { get; init; }
    public JsonElement? Body { get; init; }
    public string RawBody { get; init; } = "";
    public string? TransportError { get; init; }

    public bool Reachable => TransportError is null;
}

/// <summary>
/// Talks to CUSTOM RULE's FastAPI service (CUSTOM RULE\app\main.py) for the Custom Rule
/// authoring wizard (spec section 13). Before this pass the GUI made no HTTP calls at all —
/// see gui_build memory / TITAN_MASTER_CONTEXT.md. The fail-closed auth added in Round 3
/// (X-GEKKO-Token, 503 if missing) means every call needs the per-launch token that
/// CUSTOM RULE\desktop.py now publishes to "&lt;CustomRuleDataDirectory&gt;\secrets\gekko_api_token.dpapi"
/// (see DpapiUnprotect) — if that file is missing or stale, TryGetToken simply fails and the
/// caller surfaces "Custom Rule API unavailable" rather than silently calling unauthenticated.
/// </summary>
public sealed class CustomRuleApiClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly string _tokenFilePath;

    // Santosh, 2026-08-31 (second finding, same day): the 25s -> 100s fix above solved the AI parse
    // path, but raising the SHARED HttpClient.Timeout to 100s had a real, unintended side effect on
    // every OTHER call through this one client -- health checks, alert-integrity polling
    // (AlertsViewModel.RefreshIntegrityAsync), watcher-runtime status, etc. all now silently waited
    // up to 100s to report "unreachable" whenever the Custom Rule API simply wasn't running, instead
    // of the old 25s -- exactly the "keeps on loading" feel reported on the Alerts & Evidence page.
    // HttpClient.Timeout is a hard ceiling that no per-call token can ever exceed, only shorten, so
    // it stays at the 100s ceiling the slow parse-rule path genuinely needs; every call now also
    // supplies its OWN per-call timeout via a linked token, and only ParseRuleAsync asks for the long
    // one. Every other call gets DefaultCallTimeout and fails fast again, as it did before that fix.
    private static readonly TimeSpan DefaultCallTimeout = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan ParseRuleCallTimeout = TimeSpan.FromSeconds(95);

    public CustomRuleApiClient(string baseUrl, string customRuleDataDirectory)
    {
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(100) };
        if (!string.IsNullOrWhiteSpace(baseUrl)) _http.BaseAddress = new Uri(baseUrl);
        _tokenFilePath = Path.Combine(customRuleDataDirectory, "secrets", "gekko_api_token.dpapi");
    }

    public bool TryGetToken(out string token)
    {
        token = "";
        if (!File.Exists(_tokenFilePath)) return false;
        try
        {
            var blob = File.ReadAllBytes(_tokenFilePath);
            var decrypted = DpapiUnprotect.TryUnprotect(blob);
            if (string.IsNullOrEmpty(decrypted)) return false;
            token = decrypted;
            return true;
        }
        catch (IOException) { return false; }
    }

    /// <summary>/api/health is exempt from auth (Round 3 fail-closed design), so this
    /// succeeds even before a token is available and tells the wizard whether the API
    /// process is up at all versus just unauthenticated.</summary>
    public async Task<CustomRuleApiResult> CheckHealthAsync(CancellationToken ct = default) =>
        await SendAsync(HttpMethod.Get, "/api/health", null, ct);

    public async Task<CustomRuleApiResult> GetWatcherRuntimeAsync(CancellationToken ct = default) =>
        await SendAsync(HttpMethod.Get, "/api/watcher-runtime", null, ct);

    public async Task<CustomRuleApiResult> GetAlertsAsync(int page = 0, int limit = 100, CancellationToken ct = default) =>
        await SendAsync(HttpMethod.Get, $"/api/alerts?page={Math.Max(0, page)}&limit={Math.Clamp(limit, 1, 100)}", null, ct);

    /// <summary>FORU.TXT 0.5.B (Watcher Coverage): the complete searchable capability map across
    /// every supported collector, not only the five native telemetry pages.</summary>
    public async Task<CustomRuleApiResult> GetWatcherCapabilitiesAsync(CancellationToken ct = default) =>
        await SendAsync(HttpMethod.Get, "/api/watcher-capabilities", null, ct);

    /// <summary>FORU.TXT 0.5.E (Watcher Activity): bounded, sanitized watcher diagnostics -- proves
    /// whether a real event was observed, matched, and saved, without retaining unmatched raw logs.</summary>
    public async Task<CustomRuleApiResult> GetWatcherActivityAsync(int limit = 100, CancellationToken ct = default) =>
        await SendAsync(HttpMethod.Get, $"/api/watcher-activity?limit={Math.Clamp(limit, 1, 500)}&compact=true", null, ct);

    /// <summary>FORU.TXT 0.5.C (Approved Rules): sanitizes and promotes an approved rule into the
    /// local authoring knowledge base. Evidence and unmatched telemetry are never indexed.</summary>
    public async Task<CustomRuleApiResult> PromoteRuleAsync(string ruleId, CancellationToken ct = default) =>
        await SendAsync(HttpMethod.Post, $"/api/knowledge/promote/{Uri.EscapeDataString(ruleId)}", new { }, ct);

    public async Task<CustomRuleApiResult> DeleteRuleAsync(string ruleId, CancellationToken ct = default) =>
        await SendAsync(HttpMethod.Delete, $"/api/rules/{Uri.EscapeDataString(ruleId)}", null, ct);

    public async Task<CustomRuleApiResult> DeleteAllRulesAsync(CancellationToken ct = default) =>
        await SendAsync(HttpMethod.Delete, "/api/rules", null, ct);

    /// <summary>Deletes semantically-duplicate approved-rule records; the oldest copy and its
    /// evidence links are preserved (backend: DELETE /api/rule-maintenance/duplicates).</summary>
    public async Task<CustomRuleApiResult> DeleteDuplicateRulesAsync(CancellationToken ct = default) =>
        await SendAsync(HttpMethod.Delete, "/api/rule-maintenance/duplicates", null, ct);

    public async Task<CustomRuleApiResult> GetEvidenceAsync(string instanceId, CancellationToken ct = default) =>
        await SendAsync(HttpMethod.Get, $"/api/evidence/{Uri.EscapeDataString(instanceId)}", null, ct);

    public async Task<CustomRuleApiResult> ParseRuleAsync(string ruleText, CancellationToken ct = default) =>
        await SendAsync(HttpMethod.Post, "/api/parse-rule", new { rule_text = ruleText }, ct, ParseRuleCallTimeout);

    /// <summary>FORU.TXT section 13.3: "When Groq is at quota or unavailable, allow the user to
    /// enter or import YAML and call POST /api/rules/from-yaml. Do not send YAML through the LLM
    /// endpoint." — deliberately a different endpoint than ParseRuleAsync, never routes through
    /// the LLM.</summary>
    public async Task<CustomRuleApiResult> FromYamlAsync(string yamlText, CancellationToken ct = default) =>
        await SendAsync(HttpMethod.Post, "/api/rules/from-yaml", new { yaml_text = yamlText }, ct);

    /// <summary>FORU.TXT section 13.6: "Revalidate and rerun simulation after every edit; never
    /// approve stale pre-edit simulation output." Re-runs the exact same structural/contextual/
    /// capability/simulation pipeline a fresh LLM or YAML draft goes through, against a
    /// user-edited IR.</summary>
    public async Task<CustomRuleApiResult> DraftCheckAsync(object draft, CancellationToken ct = default) =>
        await SendAsync(HttpMethod.Post, "/api/rules/draft-check", new { draft }, ct);

    public async Task<CustomRuleApiResult> ApproveAsync(
        string ruleText, JsonElement ir, IReadOnlyList<string> injectionFlags,
        IReadOnlyList<string> capabilityGaps, IReadOnlyList<string> responseActions,
        JsonElement? retrievalTrace, CancellationToken ct = default)
    {
        var payload = new Dictionary<string, object?>
        {
            ["rule_text"] = ruleText,
            ["ir"] = ir,
            ["injection_flags"] = injectionFlags,
            ["capability_gaps"] = capabilityGaps,
            ["response_actions"] = responseActions,
            ["original_ir"] = null,
            ["edit_mode"] = null,
            ["retrieval_trace"] = retrievalTrace
        };
        return await SendAsync(HttpMethod.Post, "/api/rules/approve", payload, ct);
    }

    /// <summary>Santosh, 2026-08-06: "add option to save the logs ... keep it off until the user
    /// turns it on". Reads the live on/off state of the watcher's opt-in consolidated activity
    /// archive (separate from the always-on bounded feed the Watcher Activity tab already shows).</summary>
    public async Task<CustomRuleApiResult> GetSaveLogsStatusAsync(CancellationToken ct = default) =>
        await SendAsync(HttpMethod.Get, "/api/watcher/save-logs", null, ct);

    public async Task<CustomRuleApiResult> SetSaveLogsAsync(bool enabled, CancellationToken ct = default) =>
        await SendAsync(HttpMethod.Post, "/api/watcher/save-logs", new { enabled }, ct);

    private async Task<CustomRuleApiResult> SendAsync(HttpMethod method, string path, object? jsonPayload,
        CancellationToken ct, TimeSpan? timeout = null)
    {
        var effectiveTimeout = timeout ?? DefaultCallTimeout;
        using var timeoutCts = new CancellationTokenSource(effectiveTimeout);
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);
        try
        {
            using var request = new HttpRequestMessage(method, path);
            if (TryGetToken(out var token))
                request.Headers.Add("X-GEKKO-Token", token);
            if (jsonPayload is not null)
                request.Content = new StringContent(JsonSerializer.Serialize(jsonPayload), Encoding.UTF8, "application/json");

            using var response = await _http.SendAsync(request, linkedCts.Token);
            var raw = await response.Content.ReadAsStringAsync(linkedCts.Token);
            JsonElement? body = null;
            try { body = JsonDocument.Parse(raw).RootElement.Clone(); } catch (JsonException) { /* non-JSON body — leave null, RawBody still has it */ }

            return new CustomRuleApiResult
            {
                Success = response.IsSuccessStatusCode,
                StatusCode = (int)response.StatusCode,
                Body = body,
                RawBody = raw
            };
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or InvalidOperationException or OperationCanceledException)
        {
            // Distinguish "the caller's own token was cancelled" from "this call's own per-request
            // timeout elapsed" (the common, expected case when the API simply isn't running) so the
            // reported message is accurate instead of .NET's generic, misleadingly-precise-sounding
            // "HttpClient.Timeout of 100 seconds elapsing" text, which no longer matches what actually
            // governed this specific call.
            var message = timeoutCts.IsCancellationRequested && !ct.IsCancellationRequested
                ? $"Custom Rule API did not respond within {effectiveTimeout.TotalSeconds:0}s."
                : ex.Message;
            return new CustomRuleApiResult { Success = false, StatusCode = 0, TransportError = message };
        }
    }

    public void Dispose() => _http.Dispose();
}
