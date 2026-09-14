using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;

namespace ACPScanner;

/// <summary>Decision stage. Probes collect facts; the database supplies severity caps and file policy.</summary>
internal static class EngineDecisionPolicy
{
    private static readonly Dictionary<string, string> Inventories = new()
    {
        ["modules"] = "module", ["hlFiles"] = "hl-file", ["processes"] = "process", ["drivers"] = "driver"
    };

    internal static string Text(Dictionary<string, object?> row, string key) => Convert.ToString(row.GetValueOrDefault(key)) ?? "";
    private static string Key(string path) => path.Trim().Replace('\\', '/').ToLowerInvariant();
    private static string Basename(string path) => Key(path).Split('/').Last();
    private static string Read(JsonElement e, string key, string fallback = "") =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? fallback : fallback;
    private static int Rank(string severity) => severity == "DETECTED" ? 2 : severity == "WARNING" ? 1 : 0;

    internal static string Cap(JsonElement database, string id, string severity)
    {
        if (database.ValueKind != JsonValueKind.Object || !database.TryGetProperty("enginePolicy", out var policy)
            || !policy.TryGetProperty("ruleSeverityCaps", out var caps)) return severity;
        if (id.StartsWith("acs-", StringComparison.Ordinal)) id = "acp-" + id.Substring(4);
        string cap = id.StartsWith("acp-usn-", StringComparison.Ordinal) ? "INFO" : Read(caps, id, severity);
        return Rank(severity) > Rank(cap) ? cap : severity;
    }

    private static (string List, JsonElement Entry)? Decision(JsonElement lists, string source, string path, string sha)
    {
        foreach (var pair in new[] { ("whitelist", "sha256"), ("blacklist", "sha256"), ("blacklist", "filename"), ("whitelist", "filename") })
        {
            if (!lists.TryGetProperty(pair.Item1, out var entries)) continue;
            foreach (var entry in entries.EnumerateArray())
            {
                if (entry.TryGetProperty("enabled", out var enabled) && enabled.ValueKind == JsonValueKind.False) continue;
                if (Read(entry, "matchType") != pair.Item2 || !entry.GetProperty("scopes").EnumerateArray().Any(s => s.GetString() == source)) continue;
                string value = Read(entry, "value").ToLowerInvariant();
                bool match = pair.Item2 == "sha256" ? sha.Length == 64 && sha.Equals(value, StringComparison.OrdinalIgnoreCase) : Basename(path) == value;
                if (match) return (pair.Item1, entry);
            }
        }
        return null;
    }

    internal static void Apply(JsonElement database, Dictionary<string, object?> report)
    {
        var findings = (List<Dictionary<string, object?>>)report["findings"]!;
        foreach (var finding in findings)
        {
            string severity = Text(finding, "severity");
            string capped = Cap(database, Text(finding, "ruleId"), severity);
            if (capped != severity)
            {
                finding["originalSeverity"] = finding.GetValueOrDefault("originalSeverity", severity);
                finding["severity"] = capped;
                finding["policyReason"] = "Engine policy v3: this observation alone does not identify cheat code.";
            }
        }
        report["findingPolicyVersion"] = 3;
        if (!database.TryGetProperty("fileLists", out var lists)) return;
        var decisions = new Dictionary<string, (string Source, string Path, string Sha, string List, JsonElement Entry)>(StringComparer.OrdinalIgnoreCase);
        foreach (var inventory in Inventories)
        {
            if (!(report.GetValueOrDefault(inventory.Key) is List<Dictionary<string, object?>> rows)) continue;
            foreach (var row in rows)
            {
                string path = Text(row, "path");
                if (path == "") path = Text(row, "relativePath");
                if (path == "") continue;
                string sha = Text(row, "sha256");
                var match = Decision(lists, inventory.Value, path, sha);
                if (match.HasValue) decisions[inventory.Value + "|" + Key(path)] = (inventory.Value, path, sha, match.Value.List, match.Value.Entry);
            }
        }
        foreach (var finding in findings)
        {
            string path = Text(finding, "artifactPath");
            if (path == "") path = Text(finding, "subject");
            if (!decisions.TryGetValue(Text(finding, "source") + "|" + Key(path), out var d) || d.List != "whitelist") continue;
            string kind = Text(finding, "evidenceKind");
            bool eligible = kind == "signature-hash" || kind == "signature-name" || new[] {
                "acp-cheat-named-module", "acp-cheat-named-game-file", "acp-foreign-module", "acp-local-opengl-hook"
            }.Contains(Text(finding, "ruleId"));
            if (!eligible || (Read(d.Entry, "matchType") == "filename" && (kind == "signature-hash" || Text(finding, "severity") == "DETECTED"))) continue;
            finding["filePolicyOriginalSeverity"] = finding["severity"];
            finding["severity"] = "INFO";
            finding["filePolicy"] = d.Entry;
            finding["suppressed"] = true;
        }
        foreach (var d in decisions.Values.Where(d => d.List == "blacklist"))
        {
            findings.Add(new Dictionary<string, object?> {
                ["ruleId"] = "acs-file-policy-" + Read(d.Entry, "id"), ["ruleName"] = "Admin blacklist: " + Read(d.Entry, "value"),
                ["severity"] = Read(d.Entry, "severity"), ["confidence"] = Read(d.Entry, "matchType") == "sha256" ? "high" : "policy",
                ["category"] = d.Source == "module" ? "injected" : "loaded", ["source"] = d.Source,
                ["subject"] = d.Path, ["artifactPath"] = d.Path, ["artifactSha256"] = d.Sha, ["evidenceKind"] = "admin-policy",
                ["reason"] = "Administrator rule (" + Read(d.Entry, "matchType") + "): " + Read(d.Entry, "reason"), ["filePolicy"] = d.Entry
            });
        }
        report["fileListsRevision"] = lists.TryGetProperty("revision", out var revision) ? revision.GetInt32() : 0;
    }
}
