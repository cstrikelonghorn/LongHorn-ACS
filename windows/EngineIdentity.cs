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
        IReadOnlyList<EngineFinding> Findings,
        bool NonSteamDistribution,
        string EngineCompiled,          // "Oct 7 2024 19:06:31", from the engine's "Exe build" string
        int? EngineBuildNumber,         // what the engine prints as "Exe build: ... (N)"
        string EngineBuildNumberSource,
        string EngineVersion,           // "1.1.2.7/Stdio"
        string EngineVersionSource,
        string GameDirectory);

    /// <summary>
    /// Emulator families, matched against the module names, their load paths and the install
    /// directory. Order matters only in that the first match wins; the families are
    /// mutually exclusive in practice.
    /// </summary>
    private static readonly (string Family, string Label, string[] Markers)[] Families =
    {
        ("nextclient",    "NextClient",        new[] { "nextclient", "nitro_api", "next_engine", "next_lib", "filesystem_proxy" }),
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

    private const string MonthPattern = "(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)";

    /// <summary>
    /// The engine's own version-output format string, compiled as
    /// <c>"Exe build: " __BUILD_TIME__ " " __BUILD_DATE__ " (%i)\n"</c> (engine/host.cpp).
    /// Its time and date are the exact moment the engine was compiled.
    /// </summary>
    private static readonly Regex ExeBuildString = new(
        @"Exe build: (\d\d:\d\d:\d\d) (" + MonthPattern + @" [ \d]\d \d{4}) \(%i\)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    /// <summary>
    /// The date build_number() reads: <c>static char *date = __BUILD_DATE__</c> in
    /// engine/buildnum.cpp. The compiler places it directly in front of that file's month-name
    /// table (<c>mon[12] = { "Jan", "Feb", ... }</c>), so it is the date followed by
    /// "\0Jan\0Feb\0Mar\0" - in both engines checked. What comes before it varies (a NUL in the
    /// Steam engine, the days-per-month table in ESK's), so only the table after it is matched.
    /// It is compiled separately from host.cpp and can carry an earlier date: the ESK engine was
    /// compiled Jun 15 2009, but its build number comes from "Apr 13 2009" - build 4554.
    /// </summary>
    private static readonly Regex StandaloneDate = new(
        @"(" + MonthPattern + @" [ \d]\d \d{4})\x00Jan\x00Feb\x00Mar\x00",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    /// <summary>
    /// Reads the identity out of the modules the game has already mapped. Nothing is fetched
    /// or inferred from the machine at large: if a fact is not present in this process, it is
    /// reported as absent rather than filled in from somewhere else.
    /// </summary>
    public static Result Inspect(string hlPath, string gameRoot, List<Dictionary<string, object?>> modules, string liveVersion = "")
    {
        var evidence = new List<Fact>();
        var findings = new List<EngineFinding>();

        // The launcher is matched by PATH, not by name: "the module called hl.exe" is
        // whatever a cheat chose to call itself, while the path is the one the OS reports
        // for the process being scanned.
        var launcher = ByPath(modules, hlPath);
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
        var engineSigned = Flag(engine, "signatureValid");
        var engineSigner = Str(engine, "signer");
        var build = enginePath == "" ? EngineBuild.None : ReadEngineBuild(enginePath);

        // Version: the live string the engine holds in memory when it could be read, otherwise
        // the steam.inf the engine reads it from, in the game directory the client runs.
        var gameDirectory = GameDirectoryOf(Str(clientDll, "path"), gameRoot);
        var (patchVersion, _, versionFile) = ReadVersionFile(gameRoot, gameDirectory);
        var engineVersionString = liveVersion != "" ? liveVersion : patchVersion;
        var engineVersionSource = liveVersion != "" ? "live engine memory" : versionFile;

        if (engine is not null)
        {
            evidence.Add(new Fact("Engine module", $"{engineName} — {enginePath}", "loaded module list"));
            evidence.Add(new Fact("Engine signature",
                engineSigned
                    ? $"valid — {Or(engineSigner, "unnamed signer")}"
                    : Str(engine, "signatureStatus") == "modified"
                        ? $"{Or(engineSigner, "publisher")} certificate present, but the file was modified after signing"
                        : "not signed / not verifiable",
                "Authenticode (WinVerifyTrust)"));
            evidence.Add(new Fact("Engine SHA-256", Or(engineSha, "unreadable"), "file on disk"));
            evidence.Add(new Fact("Engine compiled", Or(build.Compiled, "no build string found"), $"{engineName} \"Exe build\" string"));
            evidence.Add(new Fact("Engine build number", build.Number?.ToString() ?? "not determined", build.NumberSource));
            evidence.Add(new Fact("Engine version", Or(engineVersionString, "not found"), Or(engineVersionSource, "steam.inf not found")));
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
        // steam_api.dll is different: retail Steam ships it next to the game too (checked -
        // Half-Life's copy sits in the game folder, Valve-signed). What an emulator does is
        // replace it. So its location proves nothing and its signature is the test.
        var steamApiPath = Str(steamApi, "path");
        var steamApiName = Str(steamApi, "name", "steam_api.dll");
        var steamApiValve = Flag(steamApi, "signatureValid") && IsValveSigner(Str(steamApi, "signer"));
        var steamApiInGame = steamApiPath != "" && IsUnder(steamApiPath, gameRoot) && !steamApiValve;
        var steamClientOrigin = steamClientPath == ""
            ? "not loaded"
            : steamClientInGame ? "game folder (emulator)" : "Steam installation";

        if (steamClientPath != "")
        {
            evidence.Add(new Fact("steamclient.dll origin", $"{steamClientOrigin} — {steamClientPath}", "loaded module list"));
        }
        if (steamApiPath != "")
        {
            evidence.Add(new Fact(steamApiName,
                (steamApiValve ? "Valve-signed" : "not Valve-signed (replaced)") + $" — {steamApiPath}",
                "Authenticode (WinVerifyTrust)"));
        }

        // A steam_appid.txt next to the game is an emulator convention; retail Steam does
        // not need one.
        var appIdFile = SafeCombine(gameRoot, "steam_appid.txt");
        if (appIdFile != "" && File.Exists(appIdFile))
        {
            evidence.Add(new Fact("steam_appid.txt", "present in the game folder", "file on disk"));
        }

        // ── The verdict ──────────────────────────────────────────────────────
        // Genuine Steam has to be proven, not assumed, and the proof is the signature - not
        // the version resource. Checked against a real install: Steam's hl.exe and hw.dll are
        // both Authenticode-signed by Valve Corp., while the ESK client's hl.exe carries a
        // byte-for-byte copy of the genuine version text ("Valve · Steam Half-Life Launcher ·
        // 1, 1, 1, 1") and no signature at all. Text can be copied; a signature that Windows
        // validates to a trusted root cannot.
        //
        // So three things must hold: the launcher is Valve-signed, the engine is Valve-signed,
        // and nothing loads Steam out of the game folder. The engine is required as well as the
        // launcher because a genuine signed hl.exe in front of a patched hw.dll is exactly how
        // a modified engine would try to pass as retail.
        var (family, label) = MatchFamily(modules, gameRoot, hlPath);

        string distribution;
        string confidence;
        bool steamVerified;

        var launcherValve = launcherSigned && IsValveSigner(launcherSigner);
        var engineValve = engineSigned && IsValveSigner(engineSigner);
        var emulatorPresent = steamClientInGame || steamApiInGame || family != "";

        if (launcherValve && engineValve && !emulatorPresent)
        {
            distribution = "Steam (retail)";
            confidence = "verified";
            steamVerified = true;
        }
        else if (launcherValve && !emulatorPresent)
        {
            // A real Steam launcher, but the engine behind it is not Valve's. Not called
            // non-Steam - the install is Steam - and not called retail either.
            distribution = engine is null
                ? "Steam — engine module not found"
                : "Steam — engine binary is not Valve-signed";
            confidence = "review";
            steamVerified = false;
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

        var trust = launcherValve && engineValve ? "valve-signed"
            : engineSha == "" ? "unknown"
            : "unverified";

        var gameBuild = "Counter-Strike 1.6 — " + distribution;
        if (engineVersionString != "")
        {
            gameBuild += $" · v{engineVersionString}";
        }
        if (build.Number is not null)
        {
            gameBuild += $" · build {build.Number}";
        }

        evidence.Add(new Fact("Distribution verdict", $"{distribution} ({confidence})",
            launcherValve ? "Valve Authenticode signature" : "module origin and emulator markers"));

        // ── Findings ─────────────────────────────────────────────────────────
        // Running a non-Steam client is whitelisted: it is not evidence of cheating and is not
        // raised for review. The identity is still recorded in full - distribution, signatures
        // and evidence - in the report's engine block, not as a finding.
        //
        // The exception is a contradiction inside a Steam install: Valve's launcher running
        // an engine Valve did not sign. There is no legitimate reason for that combination -
        // Steam verifies and replaces game files - so it is raised for review.
        if (launcherValve && !emulatorPresent && engine is not null && !engineValve)
        {
            findings.Add(new EngineFinding(
                "acs-engine-replaced-in-steam-install",
                "Engine binary replaced in a Steam install",
                "WARNING",
                enginePath,
                $"hl.exe is genuinely signed by Valve, but {engineName} is " +
                (engineSigned ? $"signed by '{Or(engineSigner, "an unnamed signer")}', not Valve" : "not signed") +
                ". A retail Steam install ships a Valve-signed engine and Steam restores it on verification, so this file was replaced after install. A modified engine can hide aim, wallhack or speed patches from checks that trust the launcher. Compare the SHA-256 against the retail build."));
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
            engineName, build.Compiled, engineVersion, engineSha,
            launcherSha, launcherSigned, launcherSigner, steamClientOrigin,
            evidence, findings,
            // A non-Steam edition was positively identified: a named family, or Steam being
            // loaded out of the game folder. What that explains - an engine patched to run
            // without Steam - is decided by the caller, not assumed here.
            !steamVerified && emulatorPresent,
            build.Compiled, build.Number, build.NumberSource,
            engineVersionString, engineVersionSource, gameDirectory);
    }

    /// <summary>
    /// Whether a certificate subject names Valve. Exact names only: a substring test would
    /// accept any certificate a stranger chose to call "Not Valve". This is meaningful only
    /// alongside a signature Windows has validated - the name on its own proves nothing.
    /// </summary>
    private static bool IsValveSigner(string signer)
    {
        return signer.Trim() is var s
               && (s.Equals("Valve Corp.", StringComparison.OrdinalIgnoreCase)
                   || s.Equals("Valve Corporation", StringComparison.OrdinalIgnoreCase)
                   || s.Equals("Valve", StringComparison.OrdinalIgnoreCase));
    }

    private sealed record EngineBuild(string Compiled, int? Number, string NumberSource)
    {
        public static readonly EngineBuild None = new("", null, "engine module not found");
    }

    /// <summary>
    /// The engine's compile time and build number, exactly as the engine reports them.
    ///
    /// GoldSrc prints "Exe build: HH:MM:SS Mon DD YYYY (N)". The time and date are literals in
    /// that format string. N is computed at runtime by build_number() from a separate date
    /// literal, with the formula ported below verbatim. Both are read from the file itself; the
    /// earlier "latest date anywhere in the binary" guess happened to give the right day for
    /// the two engines checked but gave no time and no build number.
    /// </summary>
    private static EngineBuild ReadEngineBuild(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length <= 0 || info.Length > 64L * 1024 * 1024)
            {
                return new EngineBuild("", null, "engine file unreadable");
            }

            // Latin-1 maps every byte to one character, so NUL terminators survive for the regexes.
            var text = Encoding.Latin1.GetString(File.ReadAllBytes(path));

            var exe = ExeBuildString.Match(text);
            var compiled = exe.Success ? $"{NormalizeDate(exe.Groups[2].Value)} {exe.Groups[1].Value}" : "";

            var standalone = StandaloneDate.Matches(text)
                .Select(m => m.Groups[1].Value)
                .Where(IsPlausibleDate)
                .Distinct()
                .ToList();

            if (standalone.Count == 1)
            {
                return new EngineBuild(compiled, BuildNumber(standalone[0]),
                    $"engine build_number() over its build date literal \"{NormalizeDate(standalone[0])}\"");
            }
            if (standalone.Count == 0 && exe.Success)
            {
                return new EngineBuild(compiled, BuildNumber(exe.Groups[2].Value),
                    "engine build_number() over the compile date (no separate build date literal)");
            }
            return new EngineBuild(compiled, null,
                standalone.Count == 0 ? "no build date found in the engine" : "several build date literals in the engine; not determined");
        }
        catch
        {
            return new EngineBuild("", null, "engine file unreadable");   // never a default value
        }
    }

    /// <summary>
    /// GoldSrc's build_number(), ported line for line from engine/buildnum.cpp. The input is
    /// the raw 11-character __DATE__ form, "Mmm dd yyyy", where a one-digit day is space-padded.
    /// </summary>
    public static int BuildNumber(string date)
    {
        string[] mon = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
        int[] mond = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

        int m, d = 0;
        for (m = 0; m < 11; m++)
        {
            if (string.Compare(date, 0, mon[m], 0, 3, StringComparison.OrdinalIgnoreCase) == 0)
            {
                break;
            }
            d += mond[m];
        }

        d += Atoi(date, 4) - 1;
        var y = Atoi(date, 7) - 1900;
        var b = d + (int)((y - 1) * 365.25);
        if (y % 4 == 0 && m > 1)
        {
            b += 1;
        }
        return b - 34995;   // days since Oct 24 1996
    }

    /// <summary>C's atoi from an offset: skip leading whitespace, read digits, stop at the first non-digit.</summary>
    private static int Atoi(string text, int offset)
    {
        var i = offset;
        while (i < text.Length && char.IsWhiteSpace(text[i]))
        {
            i++;
        }
        var value = 0;
        while (i < text.Length && text[i] is >= '0' and <= '9')
        {
            value = value * 10 + (text[i] - '0');
            i++;
        }
        return value;
    }

    private static string NormalizeDate(string date) => Regex.Replace(date, " {2,}", " ");

    private static bool IsPlausibleDate(string date)
    {
        return DateTime.TryParseExact(NormalizeDate(date), "MMM d yyyy",
                   System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out var parsed)
               && parsed.Year >= 1998 && parsed <= DateTime.UtcNow.AddDays(2);
    }

    /// <summary>The game directory the client runs, taken from where its client.dll was loaded.</summary>
    public static string GameDirectoryOf(string clientDllPath, string gameRoot)
    {
        try
        {
            // <root>\<gamedir>\cl_dlls\client.dll
            var clDlls = Path.GetDirectoryName(clientDllPath);
            var gameDir = clDlls is null ? null : Path.GetDirectoryName(clDlls);
            if (gameDir is not null && IsUnder(gameDir + Path.DirectorySeparatorChar, gameRoot))
            {
                return Path.GetFileName(gameDir);
            }
        }
        catch
        {
            // fall through
        }
        return "";
    }

    /// <summary>
    /// PatchVersion and ProductName from steam.inf, looked up the way the engine's file system
    /// finds it: the game directory first, then valve.
    /// </summary>
    public static (string PatchVersion, string Product, string Source) ReadVersionFile(string gameRoot, string gameDirectory)
    {
        foreach (var dir in new[] { gameDirectory, "valve" }.Where(d => !string.IsNullOrWhiteSpace(d)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var file = SafeCombine(Path.Combine(gameRoot, dir), "steam.inf");
            if (file == "" || !File.Exists(file))
            {
                continue;
            }
            try
            {
                string patch = "", product = "";
                foreach (var line in File.ReadLines(file).Take(50))
                {
                    var trimmed = line.Trim();
                    if (trimmed.StartsWith("PatchVersion=", StringComparison.OrdinalIgnoreCase))
                    {
                        patch = trimmed["PatchVersion=".Length..].Trim();
                    }
                    else if (trimmed.StartsWith("ProductName=", StringComparison.OrdinalIgnoreCase))
                    {
                        product = trimmed["ProductName=".Length..].Trim();
                    }
                }
                if (patch != "")
                {
                    return (patch, product, dir + "/steam.inf");
                }
            }
            catch
            {
                // unreadable: try the next directory
            }
        }
        return ("", "", "");
    }

    private static bool HasFamilyMarker(List<Dictionary<string, object?>> modules, string gameRoot, string hlPath, string marker)
    {
        var normalizedMarker = marker.Replace('\\', '/').Trim('/').ToLowerInvariant();
        if (normalizedMarker == "") return false;
        var values = new List<string> { gameRoot, hlPath };
        foreach (var module in modules)
        {
            values.Add(Str(module, "name"));
            values.Add(Str(module, "path"));
        }
        foreach (var raw in values)
        {
            var value = raw.Replace('\\', '/').Trim('/').ToLowerInvariant();
            if (value == "") continue;
            var parts = value.Split('/', StringSplitOptions.RemoveEmptyEntries);
            var file = parts.LastOrDefault() ?? "";
            var stem = Path.GetFileNameWithoutExtension(file);
            if (normalizedMarker.Contains('.'))
            {
                if (file == normalizedMarker) return true;
            }
            else if (parts.Contains(normalizedMarker, StringComparer.Ordinal)
                || stem == normalizedMarker || stem.StartsWith(normalizedMarker + "_", StringComparison.Ordinal))
            {
                return true;
            }
        }
        return false;
    }

    private static (string Family, string Label) MatchFamily(List<Dictionary<string, object?>> modules, string gameRoot, string hlPath)
    {
        foreach (var (family, label, markers) in Families)
        {
            foreach (var marker in markers)
            {
                if (HasFamilyMarker(modules, gameRoot, hlPath, marker))
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
            && IsUnder(Str(m, "path"), gameRoot));
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
