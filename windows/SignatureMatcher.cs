using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ACPScanner;

public static partial class ScannerEngine
{
	private sealed class RuleSet
	{
		private readonly Dictionary<string, List<CompiledRule>> _bySource = new Dictionary<string, List<CompiledRule>>(StringComparer.OrdinalIgnoreCase);

		private readonly List<CompiledRule> _all = new List<CompiledRule>();

		public IReadOnlyList<CompiledRule> All => _all;

		public static RuleSet Build(JsonElement root)
		{
			RuleSet ruleSet = new RuleSet();
			if (!root.TryGetProperty("signatures", out var value) || value.ValueKind != JsonValueKind.Array)
			{
				return ruleSet;
			}
			foreach (JsonElement item in value.EnumerateArray())
			{
				if (item.ValueKind != JsonValueKind.Object)
				{
					continue;
				}
				CompiledRule compiledRule = CompiledRule.From(item);
				ruleSet._all.Add(compiledRule);
				string[] matchSources = MatchSources;
				foreach (string text in matchSources)
				{
					if (compiledRule.AppliesToSource(text))
					{
						if (!ruleSet._bySource.TryGetValue(text, out List<CompiledRule> value2))
						{
							value2 = new List<CompiledRule>();
							ruleSet._bySource[text] = value2;
						}
						value2.Add(compiledRule);
					}
				}
			}
			return ruleSet;
		}

		public List<CompiledRule> RulesFor(string source)
		{
			List<CompiledRule> value;
			return _bySource.TryGetValue(source, out value) ? value : new List<CompiledRule>();
		}
	}

	private sealed class CompiledRule
	{
		public string Id { get; private set; } = "unknown-rule";

		public string Name { get; private set; } = "unknown-rule";

		public string Severity { get; private set; } = "INFO";

		public string Confidence { get; private set; } = "medium";
        public string NameSeverity { get; private set; } = "WARNING";

		public bool Enabled { get; private set; } = true;

		public bool Valid => CompileErrors.Count == 0;

		public List<string> CompileErrors { get; } = new List<string>();

		public List<string> Scopes { get; } = new List<string>();

		public List<MatchCondition> Conditions { get; } = new List<MatchCondition>();

		public static CompiledRule From(JsonElement rule)
		{
			CompiledRule compiledRule = new CompiledRule();
			compiledRule.Id = ReadString(rule, "id", "unknown-rule");
            compiledRule.NameSeverity = ReadString(rule, "nameSeverity", "WARNING");
			compiledRule.Name = ReadString(rule, "name", compiledRule.Id);
			compiledRule.Severity = ReadString(rule, "severity", "INFO").ToUpperInvariant();
			compiledRule.Confidence = ReadString(rule, "confidence", (compiledRule.Severity == "DETECTED") ? "high" : "medium").ToLowerInvariant();
			compiledRule.Enabled = !rule.TryGetProperty("enabled", out var value) || value.ValueKind != JsonValueKind.False;
			if (rule.TryGetProperty("scopes", out var value2) && value2.ValueKind == JsonValueKind.Array)
			{
				foreach (JsonElement item in value2.EnumerateArray())
				{
					string text = item.GetString();
					if (!string.IsNullOrWhiteSpace(text))
					{
						compiledRule.Scopes.Add(text);
					}
				}
			}
			if (rule.TryGetProperty("match", out var value3) && value3.ValueKind == JsonValueKind.Object)
			{
				foreach (JsonProperty item2 in value3.EnumerateObject())
				{
					string name = item2.Name;
					bool flag = name.EndsWith("_regex", StringComparison.OrdinalIgnoreCase);
					bool flag2 = flag;
					if (!flag2)
					{
						bool flag3;
						switch (name)
						{
						case "report_regex":
						case "output_regex":
						case "path_regex":
							flag3 = true;
							break;
						default:
							flag3 = false;
							break;
						}
						flag2 = flag3;
					}
					bool flag4 = flag2;
					MatchCondition matchCondition = new MatchCondition
					{
						Key = name,
						IsRegex = flag4
					};
					if (flag4)
					{
						string[] array = CollectStrings(item2.Value);
						foreach (string value4 in array)
						{
							var (pattern, regexOptions) = ConvertPhpRegex(value4);
							try
							{
								matchCondition.Regexes.Add(new Regex(pattern, regexOptions | RegexOptions.CultureInvariant | RegexOptions.Compiled, TimeSpan.FromMilliseconds(150L)));
							}
							catch (Exception ex)
							{
								compiledRule.CompileErrors.Add($"{name}: {ex.Message}");
							}
						}
					}
					else
					{
						string[] array2 = CollectStrings(item2.Value);
						foreach (string text2 in array2)
						{
							matchCondition.Values.Add(text2.ToLowerInvariant());
						}
					}
					compiledRule.Conditions.Add(matchCondition);
				}
			}
			if (!compiledRule.Valid)
			{
				compiledRule.Enabled = false;
			}
			return compiledRule;
		}

		public bool AppliesToSource(string source)
		{
			if (Scopes.Count == 0)
			{
				return true;
			}
			foreach (string scope in Scopes)
			{
				if (scope.Equals(source, StringComparison.OrdinalIgnoreCase) || scope.Equals("client-live", StringComparison.OrdinalIgnoreCase))
				{
					return true;
				}
			}
			return false;
		}
	}

	private sealed class MatchCondition
	{
		public string Key { get; init; } = "";

		public bool IsRegex { get; init; }

		public List<string> Values { get; } = new List<string>();

		public List<Regex> Regexes { get; } = new List<Regex>();
	}

	private static void MatchRules(JsonElement database, string source, string surface, string subject, List<Dictionary<string, object?>> findings, HashSet<string> findingKeys, string time = "", string hashSurface = "")
	{
		_scanToken.ThrowIfCancellationRequested();
		
		RuleSet ruleSet = _activeRules ?? RuleSet.Build(database);
		List<CompiledRule> list = ruleSet.RulesFor(source);
		if (list.Count == 0)
		{
			return;
		}
		string lowSurface = surface.ToLowerInvariant();
		foreach (CompiledRule item2 in list)
		{
			if (!item2.Enabled)
			{
				continue;
			}
			string item = $"{item2.Id}|{source}|{subject}";
			if (!findingKeys.Contains(item) && RuleConditionsMatch(item2, source, surface, lowSurface, hashSurface, out int matchedHashLength, subject))
			{
				string text = EffectiveRuleSeverity(item2, matchedHashLength);
                // Name floods cannot displace exact cheat hashes. Inventory remains complete.
                if (matchedHashLength == 0 && findings.Count >= 400) continue;
				findingKeys.Add(item);
				string text2;
				if (text == "DETECTED")
				{
					bool flag = (source == "live-behavior");
					text2 = (flag ? "High-confidence integrated behavior evidence." : "High-confidence live client evidence.");
				}
				else
				{
					bool flag = (source == "live-behavior");
					text2 = (flag ? "Integrated live behavior review evidence." : "Review evidence only. ACS does not call this a cheat without live module/driver evidence.");
				}
				string value = text2;
				findings.Add(new Dictionary<string, object>
				{
					["ruleId"] = item2.Id,
					["ruleName"] = item2.Name,
					["severity"] = text,
					["confidence"] = matchedHashLength >= 32 ? item2.Confidence : "low",
                    ["evidenceKind"] = matchedHashLength > 0 ? "signature-hash" : "signature-name",
                    ["matchedHashLength"] = matchedHashLength,
                    ["artifactPath"] = subject,
                    ["artifactSha256"] = hashSurface.Split(' ').FirstOrDefault(h => h.Length == 64 && IsHex(h)) ?? "",
					["category"] = CategoryForSource(source, subject),
					["source"] = source,
					["subject"] = subject,
					["reason"] = value,
					["time"] = time
				});
			}
		}
	}

	// Small deterministic seam for regression tests; it exercises the same compiled rule and
	// severity path as a live scan without opening another process.
	internal static (bool Matched, int HashLength, string Severity, bool Valid) EvaluateRuleForTest(
		string ruleJson, string source, string surface, string hashSurface)
	{
		using JsonDocument document = JsonDocument.Parse("{\"signatures\":[" + ruleJson + "]}");
		RuleSet set = RuleSet.Build(document.RootElement);
		CompiledRule rule = set.All.Single();
		int hashLength = 0;
		bool matched = rule.Enabled && rule.Valid && rule.AppliesToSource(source) && RuleConditionsMatch(rule, source, surface, surface.ToLowerInvariant(), hashSurface, out hashLength);
		string severity = matched ? EffectiveRuleSeverity(rule, hashLength) : rule.Severity;
		return (matched, hashLength, severity, rule.Valid);
	}

	private static bool IsHashCondition(string key)
	{
		switch (key)
		{
		case "sha256":
		case "hash_sha256":
		case "sha1":
		case "hash_sha1":
		case "md5":
		case "hash_md5":
		case "file_md5hash":
		case "file_hash":
			return true;
		default:
			return false;
		}
	}

	/// <summary>
	/// Evaluates signature match using "Hash OR Name, not AND" semantics.
	/// A renamed cheat matching a known cryptographic hash hits as authoritative DETECTED.
	/// A file matching a filename or path regex without a verified hash hits only as review WARNING.
	/// </summary>
	private static bool RuleConditionsMatch(CompiledRule rule, string source, string surface, string lowSurface, string hashSurface, out int matchedHashLength, string? subject = null)
	{
		matchedHashLength = 0;
		List<MatchCondition> hashConditions = new List<MatchCondition>();
		List<MatchCondition> patternConditions = new List<MatchCondition>();

		foreach (MatchCondition condition in rule.Conditions)
		{
			if (!MatchKeyAppliesToSource(condition.Key, source))
			{
				continue;
			}
			if (IsHashCondition(condition.Key))
			{
				hashConditions.Add(condition);
			}
			else
			{
				patternConditions.Add(condition);
			}
		}

		if (hashConditions.Count == 0 && patternConditions.Count == 0)
		{
			return false;
		}

		// 1. Hash matching: cryptographic hash of the artifact is ban-grade proof
		if (hashConditions.Count > 0 && !string.IsNullOrWhiteSpace(hashSurface))
		{
			string[] actual = hashSurface.Split(' ', StringSplitOptions.RemoveEmptyEntries);
			foreach (MatchCondition condition in hashConditions)
			{
				if (HashValueMatches(condition.Key, condition.Values, actual, out int conditionHashLength))
				{
					matchedHashLength = Math.Max(matchedHashLength, conditionHashLength);
				}
			}
			if (matchedHashLength > 0)
			{
				return true;
			}
		}

		// 2. Pattern matching: filenames, paths, strings are review-grade evidence
		bool matchedPattern = false;
		if (patternConditions.Count > 0)
		{
			foreach (MatchCondition condition in patternConditions)
			{
                string candidateSurface = condition.Key.StartsWith("filename_", StringComparison.Ordinal)
                    ? (subject ?? surface).Replace('\\', '/').Split('/').Last()
                    : condition.Key.StartsWith("path_", StringComparison.Ordinal) ? subject ?? surface : surface;
                string lowCandidate = candidateSurface.ToLowerInvariant();
				if (condition.IsRegex)
				{
					foreach (Regex regex in condition.Regexes)
					{
						try
						{
							if (regex.IsMatch(candidateSurface))
							{
								matchedPattern = true;
								break;
							}
						}
						catch (RegexMatchTimeoutException)
						{
						}
					}
				}
				else
				{
					foreach (string value in condition.Values)
					{
						if (value.Length > 0 && lowCandidate.IndexOf(value, StringComparison.Ordinal) >= 0)
						{
							matchedPattern = true;
							break;
						}
					}
				}
				if (matchedPattern)
				{
					break;
				}
			}
		}

		if (matchedPattern)
		{
			// Name-only match without verified hash: matchedHashLength = 0 ensures
			// IsStrongEvidence evaluates to false, downgrading any DETECTED rule to WARNING.
			matchedHashLength = 0;
			return true;
		}

		return false;
	}

	/// <summary>
	/// Match a rule's hash values against the hashes of the current artifact.
	/// A full digest matches exactly; a truncated digest matches as a prefix. Server-side
	/// cheat databases (ReChecker and its forks) publish 4-byte MD5s, so prefix matching turns
	/// a filename-only signature into real file evidence and removes its false positives.
	/// Values shorter than the 8 hex characters (4 bytes) those databases use are ignored so a
	/// stray short string cannot match by accident.
	/// </summary>
    private static bool HashValueMatches(string key, List<string> values, string[] actual, out int matchedLength)
    {
        matchedLength = 0;
        int expectedLength = key.Contains("sha256") ? 64 : key.Contains("sha1") ? 40 : key.Contains("md5") ? 32 : 0;
        foreach (string value in values)
        {
            // Only complete, correctly typed digests or legacy 4-byte MD5 hints.
            bool prefix = value.Length == 8 && expectedLength == 32;
            if (!IsHex(value) || (!prefix && value.Length != expectedLength && !(expectedLength == 0 && new[] {32,40,64}.Contains(value.Length)))) continue;
            foreach (string candidate in actual)
            {
                if (!IsHex(candidate) || candidate.Length != (expectedLength == 0 ? value.Length : expectedLength)) continue;
                if (prefix ? candidate.StartsWith(value, StringComparison.OrdinalIgnoreCase) : candidate.Equals(value, StringComparison.OrdinalIgnoreCase))
                    matchedLength = Math.Max(matchedLength, value.Length);
            }
        }
        return matchedLength > 0;
    }

    private static string EffectiveRuleSeverity(CompiledRule rule, int hashLength)
    {
        if (rule.Severity == "INFO") return "INFO";
        if (hashLength == 0) return rule.NameSeverity == "INFO" ? "INFO" : "WARNING";
        return rule.Severity == "DETECTED" && !IsStrongEvidence(rule.Severity, rule.Confidence, hashLength) ? "WARNING" : rule.Severity;
    }

	private static bool IsHex(string value)
	{
		foreach (char character in value)
		{
			if (!Uri.IsHexDigit(character))
			{
				return false;
			}
		}
		return value.Length > 0;
	}

	private static string[] CollectStrings(JsonElement element)
	{
		if (element.ValueKind == JsonValueKind.String)
		{
			return new string[1] { element.GetString() ?? "" };
		}
		if (element.ValueKind == JsonValueKind.Array)
		{
			List<string> list = new List<string>();
			foreach (JsonElement item in element.EnumerateArray())
			{
				if (item.ValueKind == JsonValueKind.String)
				{
					list.Add(item.GetString() ?? "");
				}
			}
			return list.ToArray();
		}
		return Array.Empty<string>();
	}

	private static bool IsStrongEvidence(string configuredSeverity, string confidence, int matchedHashLength)
	{
		if (configuredSeverity != "DETECTED" || confidence != "high")
		{
			return false;
		}
		// Names and paths are triage evidence, not proof. Require at least a complete MD5
		// before a database rule can produce a red verdict. Four-byte ReChecker prefixes
		// remain useful review evidence but carry too much collision risk for DETECTED.
		return matchedHashLength >= 32;
	}

	private static bool MatchKeyAppliesToSource(string key, string source)
	{
		if (key.StartsWith("output_", StringComparison.OrdinalIgnoreCase))
		{
			return source == "live-behavior";
		}
		if (key.StartsWith("config_", StringComparison.OrdinalIgnoreCase))
		{
			return source == "hl-config";
		}
		bool result;
		if (key.StartsWith("file_contains", StringComparison.OrdinalIgnoreCase))
		{
			switch (source)
			{
			case "hl-file":
			case "hl-config":
			case "live-behavior":
				result = true;
				break;
			default:
				result = false;
				break;
			}
			return result;
		}
		if (key.StartsWith("report_", StringComparison.OrdinalIgnoreCase))
		{
			switch (source)
			{
			case "process":
			case "module":
			case "driver":
			case "download-trace":
			case "execution-trace":
			case "game-process":
			case "memory":
			case "live-behavior":
				result = true;
				break;
			default:
				result = false;
				break;
			}
			return result;
		}
		if (key.StartsWith("path_", StringComparison.OrdinalIgnoreCase) || key.StartsWith("filename_", StringComparison.OrdinalIgnoreCase))
		{
			switch (source)
			{
			case "process":
			case "module":
			case "driver":
			case "download-trace":
			case "execution-trace":
			case "game-process":
			case "hl-file":
			case "live-behavior":
				result = true;
				break;
			default:
				result = false;
				break;
			}
			return result;
		}
		switch (key)
		{
		case "sha256":
		case "hash_sha256":
		case "sha1":
		case "hash_sha1":
		case "md5":
		case "hash_md5":
		case "file_md5hash":
		case "file_hash":
			result = true;
			break;
		default:
			result = false;
			break;
		}
		if (result)
		{
			return true;
		}
		return false;
	}

	private static (string Pattern, RegexOptions Options) ConvertPhpRegex(string value)
	{
		bool flag = value.Length > 2;
		bool flag2 = flag;
		if (flag2)
		{
			char c = value[0];
			bool flag3 = ((c == '#' || c == '/' || c == '~') ? true : false);
			flag2 = flag3;
		}
		if (flag2)
		{
			char c2 = value[0];
			int num = value.LastIndexOf(c2);
			if (num > 0)
			{
				string item = value.Substring(1, num - 1).Replace("\\" + c2, c2.ToString());
				int num2 = num + 1;
				string text = value.Substring(num2, value.Length - num2);
				RegexOptions item2 = (text.Contains('i') ? RegexOptions.IgnoreCase : RegexOptions.None);
				return (Pattern: item, Options: item2);
			}
		}
		return (Pattern: value, Options: RegexOptions.IgnoreCase);
	}

}
