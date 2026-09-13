namespace ACPScanner;

// GoldSrc config / script analysis.
//
// WHY THIS EXISTS
//   The original config channel was two regexes looking for the literal words "aimbot" and
//   "wallhack" inside six hard-coded filenames. No real script contains those words, and every
//   distributed script ships in a custom .cfg reached through exec, so the channel detected
//   nothing at all.
//
//   Scripts do not hide behind words -- they hide behind indirection. A bunny-hop script is a set
//   of aliases with meaningless names that call each other in a cycle, with "wait" between the
//   +jump and -jump. Once the alias graph is RESOLVED, the obfuscation is gone and the behaviour
//   is plain, because a wait-driven loop that toggles +jump has no innocent explanation.
//
//   That is what makes this channel high-detection AND low-false-positive at the same time: we
//   are not matching names, we are matching a control-flow shape that only a script produces.
internal static class ConfigAnalyzer
{
    internal sealed record Finding(
        string RuleId,
        string RuleName,
        string Severity,        // DETECTED | WARNING | INFO
        string Subject,         // file the evidence came from
        string Evidence,        // the resolved chain or the offending line
        string Reason);

    internal sealed record Command(string Name, IReadOnlyList<string> Args, string Raw)
    {
        internal string Arg(int i) => i < Args.Count ? Args[i] : "";
    }

    // Movement/attack tokens whose scripted toggling is the whole point of a script.
    private static readonly string[] JumpTokens = { "+jump", "-jump" };
    private static readonly string[] AttackTokens = { "+attack", "-attack", "+attack2", "-attack2" };
    private static readonly string[] DuckTokens = { "+duck", "-duck" };
    private static readonly string[] RecoilCvars = { "m_pitch", "cl_pitchspeed", "cl_pitchdown", "cl_pitchup", "cl_yawspeed" };

    // Mouse-wheel binds cannot be held down, so a wheel bound to +jump is the classic
    // "scroll to bunny-hop" setup rather than a normal keybind.
    private static readonly string[] WheelKeys = { "mwheelup", "mwheeldown" };

    // ---------------------------------------------------------------------------------------
    // Entry point
    // ---------------------------------------------------------------------------------------

    // files: relative path -> file contents. Analysed as one set, because a script routinely
    // defines its aliases in one file and binds them in another.
    internal static List<Finding> Analyze(IReadOnlyDictionary<string, string> files)
    {
        var findings = new List<Finding>();
        var aliases = new Dictionary<string, List<Command>>(StringComparer.OrdinalIgnoreCase);
        var aliasSource = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var binds = new List<(string Key, string Body, string File)>();
        var cvars = new List<(string Name, string Value, string File)>();

        foreach (var (path, content) in files)
        {
            foreach (var cmd in Tokenize(content))
            {
                switch (cmd.Name.ToLowerInvariant())
                {
                    case "alias":
                        if (cmd.Args.Count >= 2)
                        {
                            aliases[cmd.Arg(0)] = Tokenize(cmd.Arg(1)).ToList();
                            aliasSource[cmd.Arg(0)] = path;
                        }
                        break;

                    case "bind":
                        if (cmd.Args.Count >= 2) {
                            binds.Add((cmd.Arg(0), cmd.Arg(1), path));
                        }
                        break;

                    default:
                        if (cmd.Args.Count >= 1) {
                            cvars.Add((cmd.Name, cmd.Arg(0), path));
                        }
                        break;
                }
            }
        }

        DetectScriptLoops(aliases, aliasSource, binds, findings);
        // A mouse-wheel +jump bind is a normal manual keybind, not automation.
        DetectRecoilScripts(aliases, aliasSource, findings);
        DetectCvarAbuse(cvars, findings);
        DetectFileAnomalies(files, findings);

        return findings;
    }

    private static void DetectFileAnomalies(IReadOnlyDictionary<string, string> files, List<Finding> findings)
    {
        foreach (var (path, content) in files)
        {
            if (string.IsNullOrEmpty(content)) continue;

            // 1. Binary executable check
            if (content.StartsWith("MZ", StringComparison.Ordinal) || content.IndexOf('\0') >= 0)
            {
                findings.Add(new Finding(
                    "acp-config-binary-disguise",
                    "Binary file disguised as configuration",
                    "DETECTED",
                    path,
                    "File contains binary null bytes or starts with PE header marker (MZ)",
                    "An executable or library binary is disguised as a configuration (.cfg) file in the game directory."));
                continue;
            }

            // 2. Big CFG check (WarGods / ECD parity)
            // Normal configs are < 500 lines and < 35 KB. Files > 1500 lines or > 64 KB are classified as Big CFG.
            int lineCount = 1;
            for (int i = 0; i < content.Length; i++)
            {
                if (content[i] == '\n') lineCount++;
            }
            long byteCount = System.Text.Encoding.UTF8.GetByteCount(content);

            if (lineCount > 1500 || byteCount > 64 * 1024)
            {
                findings.Add(new Finding(
                    "acp-config-big-cfg",
                    "Abnormally large configuration script (Big CFG)",
                    "WARNING",
                    path,
                    $"{lineCount} lines, {byteCount / 1024} KB",
                    "Configuration file exceeds normal script size limits (Big CFG), frequently used to hide complex automation script chains."));
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // Tokenizer
    // ---------------------------------------------------------------------------------------
    //
    // GoldSrc console syntax: commands separated by ';' or newline, arguments separated by
    // whitespace, double quotes group an argument, '//' starts a comment. Quoted argument bodies
    // are kept verbatim so a nested script body can be re-tokenized on its own.

    internal static IEnumerable<Command> Tokenize(string text)
    {
        if (string.IsNullOrEmpty(text)) {
            yield break;
        }

        var args = new List<string>();
        var current = new System.Text.StringBuilder();
        var raw = new System.Text.StringBuilder();
        var inQuotes = false;
        var hasCurrent = false;

        void Flush(List<Command> sink)
        {
            if (hasCurrent) { args.Add(current.ToString()); current.Clear(); hasCurrent = false; }
            if (args.Count > 0) {
                sink.Add(new Command(args[0], args.Skip(1).ToList(), raw.ToString().Trim()));
            }
            args.Clear();
            raw.Clear();
        }

        var output = new List<Command>();

        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];

            if (!inQuotes && c == '/' && i + 1 < text.Length && text[i + 1] == '/')
            {
                while (i < text.Length && text[i] != '\n') { i++; }
                Flush(output);
                continue;
            }

            if (c == '"')
            {
                inQuotes = !inQuotes;
                hasCurrent = true;      // an empty quoted string is still an argument
                raw.Append(c);
                continue;
            }

            if (!inQuotes && (c == ';' || c == '\n' || c == '\r'))
            {
                Flush(output);
                continue;
            }

            if (!inQuotes && (c == ' ' || c == '\t'))
            {
                if (hasCurrent) { args.Add(current.ToString()); current.Clear(); hasCurrent = false; }
                raw.Append(c);
                continue;
            }

            current.Append(c);
            hasCurrent = true;
            raw.Append(c);
        }

        Flush(output);

        foreach (var cmd in output)
        {
            if (!string.IsNullOrWhiteSpace(cmd.Name)) {
                yield return cmd;
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // Alias graph
    // ---------------------------------------------------------------------------------------

    // Walk everything reachable from an alias, following alias-to-alias calls, and report what
    // the resolved chain actually does. Depth-limited so a self-referencing script cannot hang
    // the scan -- hitting the limit is itself the signal that the graph contains a cycle.
    private static ChainFacts Resolve(string entry, IReadOnlyDictionary<string, List<Command>> aliases)
    {
        var facts = new ChainFacts();
        var visiting = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var steps = 0;

        void Walk(string name, int depth)
        {
            if (depth > 24 || steps > 512) { return; }
            if (!aliases.TryGetValue(name, out var body)) { return; }

            if (!visiting.Add(name))
            {
                facts.HasCycle = true;   // an alias reached itself: this is a loop, not a macro
                return;
            }

            foreach (var cmd in body)
            {
                steps++;
                var lower = cmd.Name.ToLowerInvariant();
                facts.Commands.Add(lower);

                if (lower == "wait") { facts.HasWait = true; }
                if (JumpTokens.Contains(lower)) { facts.TouchesJump = true; }
                if (AttackTokens.Contains(lower)) { facts.TouchesAttack = true; }
                if (DuckTokens.Contains(lower)) { facts.TouchesDuck = true; }
                if (RecoilCvars.Contains(lower)) { facts.TouchesRecoilCvar = true; }
                if (lower == "special" || lower == "+special") { facts.TouchesSpecial = true; }

                Walk(cmd.Name, depth + 1);

                // A script commonly re-points an alias at itself to advance a state machine
                // ("alias _special jump"). The redefinition target is part of the chain.
                if (lower == "alias" && cmd.Args.Count >= 2)
                {
                    facts.RedefinesAlias = true;
                    Walk(cmd.Arg(1).Split(' ', ';').FirstOrDefault() ?? "", depth + 1);
                }
            }

            visiting.Remove(name);
        }

        Walk(entry, 0);
        return facts;
    }

    private sealed class ChainFacts
    {
        internal bool HasCycle;
        internal bool HasWait;
        internal bool TouchesJump;
        internal bool TouchesAttack;
        internal bool TouchesDuck;
        internal bool TouchesRecoilCvar;
        internal bool TouchesSpecial;
        internal bool RedefinesAlias;
        internal List<string> Commands = new();

        internal string Summary(string entry) =>
            $"{entry} -> [{string.Join(" ", Commands.Distinct().Take(12))}]"
            + (HasCycle ? " (cycle)" : "")
            + (HasWait ? " (wait)" : "");
    }

    private static void DetectScriptLoops(
        IReadOnlyDictionary<string, List<Command>> aliases,
        IReadOnlyDictionary<string, string> aliasSource,
        List<(string Key, string Body, string File)> binds,
        List<Finding> findings)
    {
        var reported = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var name in aliases.Keys)
        {
            var facts = Resolve(name, aliases);
            var file = aliasSource.TryGetValue(name, out var f) ? f : "(config)";

            // The defining shape of a script: a self-referencing alias chain with a wait in it.
            var isLoop = facts.HasCycle || facts.RedefinesAlias;
            if (!isLoop || !facts.HasWait) {
                continue;
            }

            if (facts.TouchesJump && reported.Add("bhop"))
            {
                findings.Add(new Finding(
                    "acp-script-bunnyhop",
                    "Bunny-hop script in game config",
                    "DETECTED",
                    file,
                    facts.Summary(name),
                    "Resolved alias graph contains a self-referencing chain that toggles +jump with 'wait' between "
                    + "steps. This is an automated jump-timing script; a human keybind cannot produce this shape."));
            }
            else if (facts.TouchesAttack && reported.Add("rapid"))
            {
                findings.Add(new Finding(
                    "acp-script-rapidfire",
                    "Rapid-fire / auto-fire script in game config",
                    "DETECTED",
                    file,
                    facts.Summary(name),
                    "Resolved alias graph contains a self-referencing chain that toggles +attack with 'wait' between "
                    + "steps, which fires faster than the weapon's manual rate allows."));
            }
            else if (facts.TouchesDuck && reported.Add("duck"))
            {
                findings.Add(new Finding(
                    "acp-script-duckspam",
                    "Duck-spam script in game config",
                    "WARNING",
                    file,
                    facts.Summary(name),
                    "Resolved alias graph toggles +duck in a wait-driven loop. Review against server rules -- some "
                    + "communities permit this."));
            }
            else if (reported.Add("generic"))
            {
                findings.Add(new Finding(
                    "acp-script-wait-loop",
                    "Scripted wait-loop in game config",
                    "WARNING",
                    file,
                    facts.Summary(name),
                    "Resolved alias graph contains a self-referencing chain with 'wait' in it. This is the engine "
                    + "primitive every automation script is built on; review what the chain drives."));
            }
        }
    }

    private static void DetectWheelJump(List<(string Key, string Body, string File)> binds, List<Finding> findings)
    {
        foreach (var (key, body, file) in binds)
        {
            if (!WheelKeys.Contains(key.ToLowerInvariant())) {
                continue;
            }

            var lower = body.ToLowerInvariant();
            if (lower.Contains("+jump") || lower.Contains("jump"))
            {
                findings.Add(new Finding(
                    "acp-script-wheel-jump",
                    "Jump bound to the mouse wheel",
                    "WARNING",
                    file,
                    $"bind {key} \"{body}\"",
                    "The mouse wheel cannot be held, so binding jump to it produces machine-timed repeated jumps. "
                    + "Widely treated as a bunny-hop aid; check the server's rules before acting on this alone."));
                return;
            }
        }
    }

    private static void DetectRecoilScripts(
        IReadOnlyDictionary<string, List<Command>> aliases,
        IReadOnlyDictionary<string, string> aliasSource,
        List<Finding> findings)
    {
        foreach (var name in aliases.Keys)
        {
            var facts = Resolve(name, aliases);
            if (!facts.TouchesAttack || !facts.TouchesRecoilCvar) {
                continue;
            }

            findings.Add(new Finding(
                "acp-script-norecoil",
                "Recoil-compensation script in game config",
                "DETECTED",
                aliasSource.TryGetValue(name, out var f) ? f : "(config)",
                facts.Summary(name),
                "Resolved alias graph alters view-pitch cvars (m_pitch / cl_pitchspeed / cl_pitchdown) from the same "
                + "chain that drives +attack. That is automated recoil compensation."));
            return;
        }
    }

    // ---------------------------------------------------------------------------------------
    // Cvar policy
    // ---------------------------------------------------------------------------------------
    //
    // These are graded lower than the script rules on purpose. Most are better ENFORCED by the
    // server than detected on the client, and several have legitimate uses, so they accumulate
    // evidence rather than convicting on their own.

    private static void DetectCvarAbuse(List<(string Name, string Value, string File)> cvars, List<Finding> findings)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var (name, value, file) in cvars)
        {
            var cvar = name.ToLowerInvariant();
            if (!double.TryParse(value, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var n)) {
                n = double.NaN;
            }

            string? id = null, title = null, severity = null, reason = null;

            switch (cvar)
            {
                case "cl_forwardspeed":
                case "cl_sidespeed":
                case "cl_backspeed":
                    if (n > 400) {
                        id = "acp-cvar-movespeed"; title = "Movement speed cvar above engine default"; severity = "WARNING";
                        reason = "Client movement speed set above the 400 default. The server clamps this, but it is a "
                               + "standard component of speed and strafe scripts.";
                    }
                    break;

                case "gl_wireframe":
                    if (n >= 1) {
                        id = "acp-cvar-wireframe"; title = "Wireframe rendering enabled"; severity = "DETECTED";
                        reason = "gl_wireframe draws world geometry as wireframe, making players visible through walls. "
                               + "This is a rendering wallhack that needs no external module.";
                    }
                    break;

                case "r_fullbright":
                    if (n >= 1) {
                        id = "acp-cvar-fullbright"; title = "Fullbright rendering enabled"; severity = "WARNING";
                        reason = "r_fullbright removes world lighting, eliminating shadow concealment.";
                    }
                    break;

                case "r_novis":
                    if (n >= 1) {
                        id = "acp-cvar-novis"; title = "Visibility culling disabled"; severity = "WARNING";
                        reason = "r_novis disables PVS culling so geometry behind walls is drawn.";
                    }
                    break;

                case "r_drawentities":
                    if (n >= 2) {
                        id = "acp-cvar-drawentities"; title = "Non-default entity rendering mode"; severity = "WARNING";
                        reason = "r_drawentities above 1 renders players as boxes or skeletons, which is an ESP-style "
                               + "rendering change.";
                    }
                    break;

                case "gl_max_size":
                    if (!double.IsNaN(n) && n <= 1) {
                        id = "acp-cvar-texturesize"; title = "Textures collapsed to a single pixel"; severity = "WARNING";
                        reason = "gl_max_size 1 flattens textures, a known trick for removing visual noise and seeing "
                               + "player models more clearly.";
                    }
                    break;

                case "cl_lw":
                case "cl_lc":
                    if (!double.IsNaN(n) && n == 0) {
                        id = "acp-cvar-lag-comp"; title = "Client prediction or lag compensation disabled"; severity = "INFO";
                        reason = "Disabling client-side weapon prediction or lag compensation is a component of fake-lag "
                               + "setups. Informational on its own.";
                    }
                    break;

                case "fps_override":
                    if (n >= 1) {
                        id = "acp-cvar-fps-override"; title = "Engine FPS limiter overridden"; severity = "WARNING";
                        reason = "fps_override unlocks the engine frame limiter, which changes movement physics and is a "
                               + "component of speed and jump exploits.";
                    }
                    break;
            }

            if (id is not null && seen.Add(id))
            {
                findings.Add(new Finding(id, title!, severity!, file, $"{name} {value}", reason!));
            }
        }
    }
}
