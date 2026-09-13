using System.Text;
using System.Text.RegularExpressions;

namespace ACPScanner;

/// <summary>
/// What the running GoldSrc client actually is, established from the client itself.
///
/// The previous answer to "which Counter-Strike is this?" was a substring search over the
/// names of the loaded DLLs, the install path and the window title, with this at the end:
///
///     steamclient.dll is loaded OR a Steam install exists in the registry -> "Steam"
///
/// Both halves of that fall over. The registry key says only that Steam is installed
/// somewhere on the machine, which says nothing at all about the game being scanned - a
/// real scan of a non-Steam client in C:\Counter-Strike ESK reported "GENUINE STEAM"
/// purely because Steam existed on the same PC. And a loaded steamclient.dll is what every
/// Steam emulator ships: the one in that scan was loaded out of the game folder, which is
/// the opposite of genuine Steam and was the single strongest piece of evidence available.
///
/// So nothing here infers. Every field is something observed about the files this process
/// has actually mapped: where they were loaded from, whether Windows can verify their
/// signature, what their version resources say, their hashes, and the build stamp compiled
/// into the engine. Each one is reported with the source it came from, so a wrong answer is
/// visible as a wrong fact rather than as a confident label with nothing behind it.
///
/// Non-Steam is not cheating. A large part of the surviving CS 1.6 population runs one of
/// these clients, and this class exists to identify them correctly, not to punish them:
/// the verdict it produces is descriptive, the findings it raises are informational, and
/// classifying a build as known-good stays server-side with the client profiles.
/// </summary>
public static class EngineIdentity
{
    /// <summary>One observed fact and where it came from.</summary>
    public sealed record Fact(string Name, string Value, string Source);

    public sealed record EngineFinding(string Id, string Name, string Severity, string Subject, string Reason);

    public sealed record Result(
        string Distribution,
        string Family,
        bool SteamVerified,
        string Confidence,
        string Trust,
        string GameBuild,
        string EngineModule,
        string EngineBuildDate,
        string EngineFileVersion,
        string EngineSha256,
        string LauncherSha256,
        bool LauncherSigned,
        string LauncherSigner,
        string SteamClientOrigin,
        IReadOnlyList<Fact> Evidence,
        IReadOnlyList<EngineFinding> Findings);

    /// <summary>
    /// Emulator families, matched against the module names, their load paths and the install
    /// directory. Order matters only in that the first match wins; the families are
    /// mutually exclusive in practice.
    /// </summary>
    private static readonly (string Family, string Label, string[] Markers)[] Families =
    {
        ("nextclient",    "NextClient",        new[] { "nextclient" }),
        ("gsclient",      "GSClient",          new[] { "gsclient" }),
        ("goldclient",    "GoldClient",        new[] { "goldclient" }),
        ("esk",           "ESK Edition",       new[] { "counter-strike esk", "cs esk", "\\esk\\" }),
        ("warzone",       "Warzone",           new[] { "warzone" }),
        ("revemu",        "RevEmu / RevCrew",  new[] { "revemu", "rev_emu", "revloader", "revcrew", "revsrvbrowser" }),
        ("smartsteamemu", "SmartSteamEmu",     new[] { "smartsteamemu", "sselauncher", "smartsteamloader" }),
        ("goldberg",      "Goldberg emulator", new[] { "goldberg", "steam_settings", "libsteam_api" }),
        ("multiemulator", "MultiEmulator",     new[] { "multiemulator", "multiemu", "avsmp" }),
        ("creamapi",      "CreamAPI",          new[] { "cream_api", "creamapi" }),
        ("greenluma",     "GreenLuma",         new[] { "greenluma" }),
        ("platinum",      "Platinum emulator", new[] { "platinum_emu", "platinumemu", "platinum.ini" }),
        ("steamemu",      "Steam emulator",    new[] { "crackedsteam", "steamless", "steam_emu", "steamemu" }),
        ("rehlds",        "ReHLDS / DProto",   new[] { "reunion_mm", "dproto", "regamedll", "swds.dll" })
    };

    /// <summary>The engine's __DATE__ stamp, e.g. "Nov 11 2016".</summary>
    private static readonly Regex BuildStamp = new(
        @"\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) {1,2}(\d{1,2}) (\d{4})\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    /// <summary>
    /// Reads the identity out of the modules the game has already mapped. Nothing is fetched
    /// or inferred from the machine at large: if a fact is not present in this process, it is
    /// reported as absent rather than filled in from somewhere else.
    /// </summary>
    public static Result Inspect(string hlPath, string gameRoot, List<Dictionary<string, object?>> modules)
    {
        var evidence = new List<Fact>();
        var findings = new List<EngineFinding>();

        // The launcher is matched by PATH, not by name: "the module called hl.exe" is
        // whatever a cheat chose to call itself, while the path is the one the OS reports
        // for the process being scanned.
        var launcher = ByPath(modules, hlPath) ?? ByName(modules, "hl.exe", "cstrike.exe", "cs.exe");
        var engine = InGameRoot(modules, gameRoot, "hw.dll", "sw.dll", "swds.dll");
        var clientDll = InGameRoot(modules, gameRoot, "client.dll");
        var steamClient = ByName(modules, "steamclient.dll");
        var steamApi = ByName(modules, "steam_api.dll", "steam_api_c.dll");

        var launcherSigned = Flag(launcher, "signatureValid");
        var launcherSigner = Str(launcher, "signer");
        var launcherCompany = Str(launcher, "company");
        var launcherSha = Str(launcher, "sha256");

        evidence.Add(new Fact("Launcher", Str(launcher, "path", hlPath), "process image path"));
        evidence.Add(new Fact("Launcher signature",
            launcherSigned ? $"valid — {Or(launcherSigner, "unnamed signer")}" : "not signed / not verifiable",
            "Authenticode (WinVerifyTrust)"));
        if (launcherCompany != "")
        {
            evidence.Add(new Fact("Launcher version resource",
                $"{launcherCompany} · {Or(Str(launcher, "product"), "no product")} · {Or(Str(launcher, "fileVersion"), "no version")}",
                "PE version resource"));
        }

        // Engine binary. This is the file that actually implements the game, so its build
        // stamp is the closest thing GoldSrc has to a version number.
        var engineName = engine is null ? "" : Str(engine, "name");
        var enginePath = Str(engine, "path");
        var engineSha = Str(engine, "sha256");
        var engineVersion = Str(engine, "fileVersion");
        var engineCompany = Str(engine, "company");
        var buildDate = enginePath == "" ? "" : ReadBuildStamp(enginePath);

        if (engine is not null)
        {
            evidence.Add(new Fact("Engine module", $"{engineName} — {enginePath}", "loaded module list"));
            evidence.Add(new Fact("Engine SHA-256", Or(engineSha, "unreadable"), "file on disk"));
            evidence.Add(new Fact("Engine build stamp", Or(buildDate, "no build stamp found"), $"{engineName} binary"));
            evidence.Add(new Fact("Engine version resource",
                engineVersion == "" && engineCompany == ""
                    ? "none — binary carries no version resource"
                    : $"{Or(engineCompany, "no company")} · {Or(engineVersion, "no version")}",
                "PE version resource"));
        }
        else
        {
            evidence.Add(new Fact("Engine module", "not found among the loaded modules", "loaded module list"));
        }

        // Where steamclient.dll came from is the single most decisive fact about whether
        // this is Steam. Genuine Steam loads it out of the Steam install; every emulator
        // ships its own copy next to the game.
        var steamClientPath = Str(steamClient, "path");
        var steamClientInGame = steamClientPath != "" && IsUnder(steamClientPath, gameRoot);
        var steamApiPath = Str(steamApi, "path");
        var steamApiInGame = steamApiPath != "" && IsUnder(steamApiPath, gameRoot);
        var steamClientOrigin = steamClientPath == ""
            ? "not loaded"
            : steamClientInGame ? "game folder (emulator)" : "Steam installation";

        if (steamClientPath != "")
        {
            evidence.Add(new Fact("steamclient.dll origin", $"{steamClientOrigin} — {steamClientPath}", "loaded module list"));
        }
        if (steamApiPath != "")
        {
            evidence.Add(new Fact("steam_api.dll origin",
                $"{(steamApiInGame ? "game folder" : "outside game folder")} — {steamApiPath}", "loaded module list"));
        }

        // A steam_appid.txt next to the game is an emulator convention; retail Steam does
        // not need one.
        var appIdFile = SafeCombine(gameRoot, "steam_appid.txt");
        if (appIdFile != "" && File.Exists(appIdFile))
        {
            evidence.Add(new Fact("steam_appid.txt", "present in the game folder", "file on disk"));
        }

        // ── The verdict ──────────────────────────────────────────────────────
        // Genuine Steam has to be proven, not assumed. Two things must hold: Windows can
        // verify the launcher's signature and it is Valve's, and nothing is loading Steam
        // out of the game folder. Anything short of that is reported as non-Steam.
        var surface = BuildSurface(modules, gameRoot, hlPath);
        var (family, label) = MatchFamily(surface);

        string distribution;
        string confidence;
        bool steamVerified;

        var valveSigned = launcherSigned && launcherSigner.Contains("Valve", StringComparison.OrdinalIgnoreCase);
        var emulatorPresent = steamClientInGame || steamApiInGame || family != "";

        if (valveSigned && !emulatorPresent)
        {
            distribution = "Steam (retail)";
            confidence = "verified";
            steamVerified = true;
        }
        else if (family != "")
        {
            distribution = "Non-Steam — " + label;
            confidence = steamClientInGame || steamApiInGame ? "verified" : "high";
            steamVerified = false;
        }
        else if (emulatorPresent)
        {
            distribution = "Non-Steam — Steam emulator";
            confidence = "verified";
            steamVerified = false;
        }
        else
        {
            // No emulator marker and no Valve signature. Saying "Steam" here is what the old
            // code did; it is a guess, and it is the guess that was wrong.
            distribution = "Unverified — could not be attributed";
            confidence = "none";
            steamVerified = false;
        }

        var trust = valveSigned ? "valve-signed"
            : engineSha == "" ? "unknown"
            : "unverified";

        var gameBuild = "Counter-Strike 1.6 — " + distribution;
        if (buildDate != "")
        {
            gameBuild += $" · engine {buildDate}";
        }

        evidence.Add(new Fact("Distribution verdict", $"{distribution} ({confidence})",
            valveSigned ? "Valve Authenticode signature" : "module origin and emulator markers"));

        // ── Findings ─────────────────────────────────────────────────────────
        // Informational by design. Running a non-Steam client is not evidence of cheating
        // and must not push a scan toward SUSPICIOUS on its own - what matters is that the
        // report states plainly what was found instead of labelling it Steam.
        if (!steamVerified)
        {
            findings.Add(new EngineFinding(
                "acs-client-distribution",
                "Non-Steam Counter-Strike client",
                "INFO",
                Or(enginePath, hlPath),
                $"The client was identified as {distribution}. " +
                (steamClientInGame
                    ? "steamclient.dll is loaded from the game folder rather than from a Steam installation, which is how Steam emulators work. "
                    : "") +
                "This is not evidence of cheating - many Counter-Strike 1.6 players run a non-Steam client - but the engine binary cannot be attributed to Valve, so module integrity is judged against the client profile rather than against a retail build."));
        }

        if (engine is not null && engineVersion == "" && engineCompany == "")
        {
            findings.Add(new EngineFinding(
                "acs-engine-no-version-resource",
                "Engine binary carries no version resource",
                "INFO",
                enginePath,
                $"{engineName} has no company or version information compiled into it. Valve's engine binaries always carry one, so this file has been rebuilt or repacked. Expected for a modified client; recorded here so the build is identified by hash instead."));
        }

        if (engine is null)
        {
            findings.Add(new EngineFinding(
                "acs-engine-module-missing",
                "Engine module not found in the game process",
                "WARNING",
                Or(gameRoot, hlPath),
                "Neither hw.dll nor sw.dll was found loaded from the game folder. The engine could not be identified or verified, so this scan cannot establish what build is running."));
        }

        return new Result(
            distribution, family, steamVerified, confidence, trust, gameBuild,
            engineName, buildDate, engineVersion, engineSha,
            launcherSha, launcherSigned, launcherSigner, steamClientOrigin,
            evidence, findings);
    }

    /// <summary>
    /// Pulls the compiler's __DATE__ stamp out of the engine binary.
    ///
    /// GoldSrc has no version number worth the name - retail hw.dll reports 1.0.0.1 and has
    /// for twenty years - but every build carries the date it was compiled, and that is what
    /// the engine prints for "Exe build". Several dates can appear in a binary (third-party
    /// code carries its own), so the latest is taken: the engine is linked last.
    /// </summary>
    private static string ReadBuildStamp(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length <= 0 || info.Length > 64L * 1024 * 1024)
            {
                return "";
            }

            var bytes = File.ReadAllBytes(path);
            var text = Encoding.ASCII.GetString(bytes);

            DateTime? best = null;
            var bestText = "";
            foreach (Match match in BuildStamp.Matches(text))
            {
                if (!DateTime.TryParseExact(
                        $"{match.Groups[1].Value} {match.Groups[2].Value} {match.Groups[3].Value}",
                        new[] { "MMM d yyyy", "MMM dd yyyy" },
                        System.Globalization.CultureInfo.InvariantCulture,
                        System.Globalization.DateTimeStyles.None,
                        out var parsed))
                {
                    continue;
                }

                // Half-Life shipped in 1998; a stamp in the future is not a build date.
                if (parsed.Year < 1998 || parsed > DateTime.UtcNow.AddDays(2))
                {
                    continue;
                }

                if (best is null || parsed > best)
                {
                    best = parsed;
                    bestText = match.Value;
                }
            }

            return bestText;
        }
        catch
        {
            return "";   // an unreadable engine is reported as absent, never as a default
        }
    }

    private static string BuildSurface(List<Dictionary<string, object?>> modules, string gameRoot, string hlPath)
    {
        var sb = new StringBuilder();
        sb.Append(gameRoot).Append(' ').Append(hlPath).Append(' ');
        foreach (var module in modules)
        {
            sb.Append(Str(module, "name")).Append(' ').Append(Str(module, "path")).Append(' ');
        }
        return sb.ToString().ToLowerInvariant();
    }

    private static (string Family, string Label) MatchFamily(string surface)
    {
        foreach (var (family, label, markers) in Families)
        {
            foreach (var marker in markers)
            {
                if (surface.Contains(marker, StringComparison.Ordinal))
                {
                    return (family, label);
                }
            }
        }
        return ("", "");
    }

    // ── Module lookup ────────────────────────────────────────────────────────

    private static Dictionary<string, object?>? ByPath(List<Dictionary<string, object?>> modules, string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }
        return modules.FirstOrDefault(m => string.Equals(Str(m, "path"), path, StringComparison.OrdinalIgnoreCase));
    }

    private static Dictionary<string, object?>? ByName(List<Dictionary<string, object?>> modules, params string[] names)
    {
        return modules.FirstOrDefault(m => names.Any(n => string.Equals(Str(m, "name"), n, StringComparison.OrdinalIgnoreCase)));
    }

    /// <summary>
    /// The module of this name that the game loaded from its own install. A hw.dll mapped
    /// from anywhere else is not this game's engine, whatever it calls itself.
    /// </summary>
    private static Dictionary<string, object?>? InGameRoot(List<Dictionary<string, object?>> modules, string gameRoot, params string[] names)
    {
        return modules.FirstOrDefault(m =>
                   names.Any(n => string.Equals(Str(m, "name"), n, StringComparison.OrdinalIgnoreCase))
                   && IsUnder(Str(m, "path"), gameRoot))
               ?? ByName(modules, names);
    }

    // ── Small helpers ────────────────────────────────────────────────────────

    private static string Str(Dictionary<string, object?>? map, string key, string fallback = "")
    {
        if (map is null || !map.TryGetValue(key, out var value) || value is null)
        {
            return fallback;
        }
        return Convert.ToString(value) ?? fallback;
    }

    private static bool Flag(Dictionary<string, object?>? map, string key)
    {
        return map is not null && map.TryGetValue(key, out var value) && value is bool b && b;
    }

    private static string Or(string value, string fallback) => string.IsNullOrWhiteSpace(value) ? fallback : value;

    private static bool IsUnder(string path, string root)
    {
        if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(root))
        {
            return false;
        }

        try
        {
            var full = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            var under = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
            return full.StartsWith(under, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static string SafeCombine(string root, string name)
    {
        try
        {
            return string.IsNullOrWhiteSpace(root) ? "" : Path.Combine(root, name);
        }
        catch
        {
            return "";
        }
    }
}
