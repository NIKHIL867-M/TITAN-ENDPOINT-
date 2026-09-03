using System.Text;
using System.Text.Json;
using TitanEndpoint.Core.Config;

namespace TitanEndpoint.Core.Evidence;

public sealed record EvidenceReference(string Endpoint, string RecordId, string SessionId,
    string SourceFile, long ByteOffset, string ContentHash, string EmbeddedSource = "");
public enum EvidenceResolutionState { Verified, EmbeddedOnly, Expired, IdentityMismatch, InvalidReference, ReadFailed }
public sealed record EvidenceResolution(EvidenceResolutionState State, string Message, string Content, string? ResolvedPath = null);

/// <summary>Bounded, source-directory-confined resolver for native durable evidence references.</summary>
public static class EvidenceResolver
{
    private const int MaxEvidenceLineBytes = 2 * 1024 * 1024;
    public static EvidenceResolution Resolve(EvidenceReference reference, IEnumerable<EndpointDefinition> definitions)
    {
        if (string.IsNullOrWhiteSpace(reference.RecordId) || string.IsNullOrWhiteSpace(reference.SourceFile) || reference.ByteOffset < 0)
            return Fallback(reference, EvidenceResolutionState.InvalidReference, "The member has no complete durable evidence reference.");
        var definition = FindDefinition(reference.Endpoint, definitions);
        if (definition is null || string.IsNullOrWhiteSpace(definition.LogDirectory))
            return Fallback(reference, EvidenceResolutionState.InvalidReference, "No configured source directory exists for this endpoint.");
        var sourceName = Path.GetFileName(reference.SourceFile);
        if (!string.Equals(sourceName, reference.SourceFile, StringComparison.Ordinal) || sourceName.Length == 0)
            return Fallback(reference, EvidenceResolutionState.InvalidReference, "The source filename was rejected because it is not a safe basename.");
        string root;
        try { root = Path.GetFullPath(Environment.ExpandEnvironmentVariables(definition.LogDirectory)); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        { return Fallback(reference, EvidenceResolutionState.InvalidReference, $"Invalid source directory: {ex.Message}"); }
        var path = Path.Combine(root, sourceName);
        if (!File.Exists(path))
            return Fallback(reference, EvidenceResolutionState.Expired,
                "The referenced archive is no longer retained. The embedded copy is shown without claiming live source verification.");
        return ReadAndValidate(path, reference);
    }

    private static EvidenceResolution ReadAndValidate(string path, EvidenceReference reference)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.RandomAccess);
            if (reference.ByteOffset > stream.Length)
                return Fallback(reference, EvidenceResolutionState.Expired, "The source file is shorter than the recorded offset; it was likely replaced or rotated.");
            stream.Position = reference.ByteOffset;
            using var line = new MemoryStream();
            while (line.Length <= MaxEvidenceLineBytes)
            {
                var value = stream.ReadByte();
                if (value < 0 || value == '\n') break;
                line.WriteByte((byte)value);
            }
            if (line.Length > MaxEvidenceLineBytes)
                return Fallback(reference, EvidenceResolutionState.ReadFailed, "The evidence line exceeds the 2 MiB safety limit.");
            var text = Encoding.UTF8.GetString(line.ToArray()).TrimEnd('\r');
            using var document = JsonDocument.Parse(text);
            var root = document.RootElement;
            string Field(string name) => root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() ?? "" : "";
            var mismatches = new List<string>();
            Compare("record ID", reference.RecordId, Field("native_record_id"), mismatches);
            Compare("session ID", reference.SessionId, Field("native_session_id"), mismatches);
            Compare("source file", Path.GetFileName(reference.SourceFile), Field("native_source_file"), mismatches);
            Compare("content hash", reference.ContentHash, Field("native_content_hash"), mismatches);
            if (mismatches.Count > 0)
                return Fallback(reference, EvidenceResolutionState.IdentityMismatch,
                    "The retained line does not match the durable reference (" + string.Join(", ", mismatches) + ").");
            return new EvidenceResolution(EvidenceResolutionState.Verified,
                $"Verified source record at byte offset {reference.ByteOffset:N0}.", text, path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        { return Fallback(reference, EvidenceResolutionState.ReadFailed, $"Source verification failed: {ex.Message}"); }
    }

    private static void Compare(string label, string expected, string actual, List<string> mismatches)
    {
        if (!string.IsNullOrWhiteSpace(expected) && !string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase)) mismatches.Add(label);
    }
    private static EvidenceResolution Fallback(EvidenceReference reference, EvidenceResolutionState state, string message) =>
        new(state, message, string.IsNullOrWhiteSpace(reference.EmbeddedSource) ? "No embedded evidence copy is available." : reference.EmbeddedSource);
    private static EndpointDefinition? FindDefinition(string endpoint, IEnumerable<EndpointDefinition> definitions)
    {
        var id = endpoint.ToLowerInvariant() switch
        {
            "process" => EndpointId.Process, "network" => EndpointId.Network, "application" => EndpointId.Application,
            "file" or "file_integrity" => EndpointId.File, "port" or "usb" => EndpointId.Port,
            "correlator" => EndpointId.Correlator, _ => (EndpointId?)null
        };
        return id is null ? null : definitions.FirstOrDefault(def => def.Id == id);
    }
}
