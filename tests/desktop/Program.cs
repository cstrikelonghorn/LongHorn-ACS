using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Threading;
using System.Windows.Forms;
using ACS;
using ACPScanner;
using System.Diagnostics;
using System.Reflection;
using System.Text.Json;

internal static class Checks
{
    private static int _passed;
    private static void Check(bool value, string name)
    {
        if (!value) throw new Exception(name);
        _passed++;
        Console.WriteLine("PASS " + name);
    }

    [STAThread]
    private static void Main(string[] args)
    {
        HybridChecks.Run(Check);
        if (args.Length == 2 && args[0] == "--render-ui")
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            using var preview = new MainForm();
            preview.ShowInTaskbar = false;
            preview.StartPosition = FormStartPosition.Manual;
            preview.Location = new Point(-32000, -32000);
            preview.Show();
            Application.DoEvents();
            using var bitmap = new Bitmap(preview.Width, preview.Height);
            preview.DrawToBitmap(bitmap, new Rectangle(0, 0, preview.Width, preview.Height));
            bitmap.Save(Path.GetFullPath(args[1]));
            Console.WriteLine("UI rendered: " + args[1]);
            return;
        }
        Check(ConfigAnalyzer.Analyze(new Dictionary<string, string> { ["config.cfg"] = "bind mwheelup +jump\nbind mouse1 +attack" }).Count == 0, "ordinary wheel-jump and attack binds are not automation");
        var script = ConfigAnalyzer.Analyze(new Dictionary<string, string> { ["a.cfg"] = "alias hop \"+jump;wait;-jump;wait;hop\"\nbind space hop" });
        Check(script.Any(f => f.RuleId == "acp-script-bunnyhop"), "recursive jump script remains detectable");
        Check(ConfigAnalyzer.Analyze(new Dictionary<string, string> { ["a.cfg"] = "// alias hop +jump\necho \"wallhack\"" }).Count == 0, "comments and quoted cheat words do not create script evidence");
        var bigCfg = ConfigAnalyzer.Analyze(new Dictionary<string, string> { ["big.cfg"] = string.Join("\n", Enumerable.Repeat("echo x", 1600)) });
        Check(bigCfg.Any(f => f.RuleId == "acp-config-big-cfg"), "big cfg detected by line threshold");
        var binaryCfg = ConfigAnalyzer.Analyze(new Dictionary<string, string> { ["fake.cfg"] = "MZ\x90\0\0" });
        Check(binaryCfg.Any(f => f.RuleId == "acp-config-binary-disguise"), "binary executable disguised as config detected");
        var match = typeof(ScannerEngine).GetMethod("MatchRules", BindingFlags.NonPublic | BindingFlags.Static)!;
        var findings = new List<Dictionary<string, object?>>();
        using var rules = JsonDocument.Parse("""{"signatures":[{"id":"info-test","name":"Informational marker","severity":"INFO","scopes":["module"],"match":{"report_contains":["fixture"]}}]}""");
        match.Invoke(null, new object[] { rules.RootElement, "module", "fixture", "fixture.dll", findings, new HashSet<string>(), "", "" });
        Check(findings.Count == 1 && (string)findings[0]["severity"]! == "INFO", "informational signature is never promoted to warning");
        using var hashRules = JsonDocument.Parse("""{"signatures":[{"id":"hash-test","severity":"DETECTED","confidence":"high","scopes":["module"],"match":{"sha256":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}}]}""");
        findings.Clear();
        var fakeName = new string('a', 64);
        match.Invoke(null, new object[] { hashRules.RootElement, "module", fakeName, fakeName + ".dll", findings, new HashSet<string>(), "", "" });
        Check(findings.Count == 0, "hash-looking filenames cannot match a content signature");
        match.Invoke(null, new object[] { hashRules.RootElement, "module", "renamed.dll", "renamed.dll", findings, new HashSet<string>(), "", fakeName });
        Check(findings.Count == 1 && (string)findings[0]["severity"]! == "DETECTED", "verified hash matches even after a file is renamed");
        using var prefixRules = JsonDocument.Parse("""{"signatures":[{"id":"prefix-test","severity":"DETECTED","confidence":"high","scopes":["module"],"match":{"md5":["9c1764e3"]}}]}""");
        findings.Clear();
        match.Invoke(null, new object[] { prefixRules.RootElement, "module", "renamed.dll", "renamed.dll", findings, new HashSet<string>(), "", "aaaa 9c1764e3bcd6e0a0bcd6e0a0bcd6e0a0 1111" });
        Check(findings.Count == 1, "a 4-byte MD5 from a server ban DB matches a file by prefix");
        Check((string)findings[0]["severity"]! == "WARNING", "a 4-byte MD5 collision risk cannot produce a red verdict");
        findings.Clear();
        match.Invoke(null, new object[] { prefixRules.RootElement, "module", "clean.dll", "clean.dll", findings, new HashSet<string>(), "", "aaaa deadbeefbcd6e0a0bcd6e0a0bcd6e0a0 1111" });
        Check(findings.Count == 0, "a different digest does not match the same prefix rule");
        using var fullHashRules = JsonDocument.Parse("""{"signatures":[{"id":"full-test","severity":"DETECTED","confidence":"high","scopes":["module"],"match":{"md5":["9c1764e3bcd6e0a0bcd6e0a0bcd6e0a0"]}}]}""");
        findings.Clear();
        match.Invoke(null, new object[] { fullHashRules.RootElement, "module", "renamed.dll", "renamed.dll", findings, new HashSet<string>(), "", "aaaa 9c1764e3bcd6e0a0bcd6e0a0bcd6e0a0 1111" });
        Check(findings.Count == 1, "a full MD5 still matches exactly");
        const string combinedRule = """{"id":"combined","severity":"DETECTED","confidence":"high","scopes":["module"],"match":{"path_regex":"aimbot\\.dll$","md5":["9c1764e3bcd6e0a0bcd6e0a0bcd6e0a0"]}}""";
        var nameOnly = ScannerEngine.EvaluateRuleForTest(combinedRule, "module", @"C:\cs\aimbot.dll", "deadbeefdeadbeefdeadbeefdeadbeef");
        Check(nameOnly.Matched && nameOnly.Severity == "WARNING", "a filename match with non-matching hash matches as review WARNING");
        var renamed = ScannerEngine.EvaluateRuleForTest(combinedRule, "module", @"C:\cs\clean_renamed.dll", "9c1764e3bcd6e0a0bcd6e0a0bcd6e0a0");
        Check(renamed.Matched && renamed.Severity == "DETECTED", "a renamed cheat with verified hash matches as DETECTED");
        var confirmed = ScannerEngine.EvaluateRuleForTest(combinedRule, "module", @"C:\cs\aimbot.dll", "9c1764e3bcd6e0a0bcd6e0a0bcd6e0a0");
        Check(confirmed.Matched && confirmed.Severity == "DETECTED", "matching both name and full hash produces DETECTED");
        var clean = ScannerEngine.EvaluateRuleForTest(combinedRule, "module", @"C:\cs\clean.dll", "deadbeefdeadbeefdeadbeefdeadbeef");
        Check(!clean.Matched, "neither name nor hash matching produces no match");
        var invalidRule = ScannerEngine.EvaluateRuleForTest("""{"id":"bad-regex","severity":"DETECTED","confidence":"high","scopes":["module"],"match":{"path_regex":"["}}""", "module", "anything", "");
        Check(!invalidRule.Valid && !invalidRule.Matched, "invalid database regex disables the rule explicitly");
        var verified = typeof(ScannerEngine).GetMethod("IsIntegrityVerifiedModule", BindingFlags.NonPublic | BindingFlags.Static)!;
        string hlRoot = @"C:\Program Files (x86)\Steam\steamapps\common\Half-Life";
        string hlLauncher = hlRoot + @"\hl.exe";
        bool V(string name, string path) => (bool)verified.Invoke(null, new object[] { name, path, hlRoot, hlLauncher })!;
        Check(V("hw.dll", hlRoot + @"\hw.dll"), "engine module in the install root is integrity-verified");
        Check(V("opengl32.dll", @"C:\Windows\SysWOW64\opengl32.dll"), "render module is always integrity-verified");
        Check(V("client.dll", hlRoot + @"\cstrike\client.dll"), "a module dropped in a mod folder is integrity-verified");
        Check(!V("avcodec-53.dll", hlRoot + @"\avcodec-53.dll"), "Steam's FFmpeg runtime is not treated as game code");
        Check(!V("libcef.dll", hlRoot + @"\libcef.dll"), "Steam's CEF runtime is not treated as game code");
        Check(!V("icudt.dll", hlRoot + @"\icudt.dll"), "Steam's ICU data is not treated as game code");
        try
        {
            ScannerEngine.ScanAndUploadAsync("http://example.invalid/api.php", "", new Progress<string>(), CancellationToken.None).GetAwaiter().GetResult();
            Check(false, "insecure remote endpoint rejected");
        }
        catch (InvalidOperationException ex) { Check(ex.Message.Contains("HTTPS"), "insecure remote endpoint rejected"); }
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        try
        {
            ScannerEngine.ScanAndUploadAsync("http://localhost/api.php", "", new Progress<string>(), cancelled.Token).GetAwaiter().GetResult();
            Check(false, "pre-cancelled scan rejected");
        }
        catch (OperationCanceledException) { Check(true, "pre-cancelled scan rejected"); }

        // File selection: a cheat DLL must never be dropped because of where it happens to
        // sort in the directory walk. The old code took the first 2500 files and stopped,
        // and a real install logged that it had hit that limit.
        var fileRoot = Path.Combine(Path.GetTempPath(), "acs_file_budget_test");
        if (Directory.Exists(fileRoot)) Directory.Delete(fileRoot, recursive: true);
        Directory.CreateDirectory(fileRoot);
        // Assets first, well past the budget, then code files that the old cap would eat.
        for (var i = 0; i < 3000; i++)
            File.WriteAllText(Path.Combine(fileRoot, $"asset_{i:D5}.spr"), "x");
        var deepDir = Path.Combine(fileRoot, "zzz_last");
        Directory.CreateDirectory(deepDir);
        File.WriteAllText(Path.Combine(deepDir, "zzz_cheat.dll"), "x");
        File.WriteAllText(Path.Combine(deepDir, "zzz_script.cfg"), "x");

        var select = typeof(ScannerEngine).GetMethod("SelectHlCandidates", BindingFlags.NonPublic | BindingFlags.Static)!;
        var selected = (string[])select.Invoke(null, new object[] { fileRoot, new List<string>() })!;
        var names = selected.Select(Path.GetFileName).ToHashSet(StringComparer.OrdinalIgnoreCase);

        Check(names.Contains("zzz_cheat.dll"), "a DLL past the old 2500-file cap is still scanned");
        Check(names.Contains("zzz_script.cfg"), "a config past the old 2500-file cap is still scanned");
        Check(selected.Count(p => p.EndsWith(".spr", StringComparison.OrdinalIgnoreCase)) <= 2500,
              "asset files remain budgeted");
        var notes = new List<string>();
        select.Invoke(null, new object[] { fileRoot, notes });
        Check(notes.Any(n => n.Contains("Asset scan covered")), "truncated asset coverage is reported in the notes");
        Directory.Delete(fileRoot, recursive: true);

        // Upload consent is given once, on the privacy screen before the scan, and the report
        // then uploads automatically. The gate still fails closed for any caller that skips it.
        var scanEntry = typeof(ScannerEngine).GetMethod("ScanAndUploadAsync", BindingFlags.Public | BindingFlags.Static)!;
        var consentParam = scanEntry.GetParameters().Single(p => p.Name == "uploadConsented");
        Check(consentParam.HasDefaultValue && (bool)consentParam.DefaultValue! == false, "upload consent defaults to not given (fails closed)");
        var notice = (string)typeof(ScannerEngine).Assembly.GetType("ACPScanner.ScanPrivacy")!
            .GetField("Disclosure", BindingFlags.NonPublic | BindingFlags.Static)!.GetRawConstantValue()!;
        Check(notice.Contains("uploaded automatically") && notice.Contains("Cancel now"), "privacy notice says the upload is automatic before the scan starts");
        Check(!notice.Contains("review the complete report", StringComparison.OrdinalIgnoreCase), "privacy notice no longer promises a review step that does not exist");

        SignatureChecks();
        EngineIdentityChecks();
        LiveTrafficChecks();
        LegitFilesChecks();

        if (args.Length > 0)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            using var form = new MainForm();
            form.ShowInTaskbar = false;
            form.Opacity = 0;
            form.StartPosition = FormStartPosition.Manual;
            form.Location = new Point(-32000, -32000);
            form.Show();
            Application.DoEvents();
            using var bitmap = new Bitmap(form.Width, form.Height);
            form.DrawToBitmap(bitmap, new Rectangle(0, 0, form.Width, form.Height));
            bitmap.Save(Path.GetFullPath(args[0]));
            Check(true, "desktop UI rendered");
        }
        Console.WriteLine($"{_passed} passed");
    }

    // ── Signatures: modified is not forged ────────────────────────────────────
    //
    // A real ESK scan got DETECTED "acp-forged-signature: hw.dll claims 'Valve'". Windows
    // reports that file as HashMismatch: Valve's genuine 2009 signature over an engine patched
    // afterwards, as every non-Steam edition patches it. Nobody forged a certificate.
    private static void SignatureChecks()
    {
        const BindingFlags S = BindingFlags.NonPublic | BindingFlags.Static;
        var status = typeof(ScannerEngine).GetMethod("SignatureStatus", S)!;
        string Status(uint code) => (string)status.Invoke(null, new object[] { code })!;
        Check(Status(0x80096010u) == "modified", "TRUST_E_BAD_DIGEST is classified as modified, not forged");
        Check(Status(0x800B0109u) == "untrusted", "an untrusted root is classified as a forged certificate");
        Check(Status(0x800B0100u) == "not-signed" && Status(0u) == "valid", "unsigned and valid are told apart");

        var hlTargetType = typeof(ScannerEngine).GetNestedType("HlTarget", S)!;
        var evidenceEngine = typeof(ScannerEngine).GetMethod("RunAcpEvidenceEngine", S)!;
        const string root = @"C:\Counter-Strike ESK\Counter Strike";

        List<Dictionary<string, object?>> Run(string signatureStatus, bool nonSteam, string path = root + @"\hw.dll")
        {
            using var self = Process.GetCurrentProcess();
            var target = Activator.CreateInstance(hlTargetType, self, root + @"\hl.exe", root, "", "", 1, 1)!;
            var module = new Dictionary<string, object?>
            {
                ["name"] = Path.GetFileName(path), ["path"] = path, ["signer"] = "Valve",
                ["signatureValid"] = false, ["signatureStatus"] = signatureStatus, ["trusted"] = true
            };
            var found = new List<Dictionary<string, object?>>();
            evidenceEngine.Invoke(null, new object[] { target, new List<Dictionary<string, object?>> { module },
                new List<Dictionary<string, object?>>(), found, new HashSet<string>(), nonSteam });
            return found;
        }

        string? Severity(List<Dictionary<string, object?>> found, string id) =>
            found.FirstOrDefault(f => (string?)f["ruleId"] == id)?["severity"] as string;

        var esk = Run("modified", nonSteam: true);
        Check(Severity(esk, "acp-forged-signature") is null, "patched Valve engine in a non-Steam client is not called forged");
        Check(Severity(esk, "acs-signed-module-modified") is null, "and, as that whitelisted client, is not raised for review at all");

        var unexplained = Run("modified", nonSteam: false);
        Check(Severity(unexplained, "acs-signed-module-modified") == "WARNING", "a modified signed engine nothing explains is raised for review");

        var outside = Run("modified", nonSteam: true, path: @"C:\Users\player\AppData\Local\Temp\hw.dll");
        Check(Severity(outside, "acs-signed-module-modified") == "WARNING", "a modified signed module outside the install is not excused by the client");

        var forged = Run("untrusted", nonSteam: true);
        Check(Severity(forged, "acp-forged-signature") == "DETECTED", "a certificate that does not chain is still DETECTED as forged, even on a non-Steam client");
    }

    // ── Client & engine identity ──────────────────────────────────────────────
    //
    // A real scan of the ESK client reported "Counter-Strike: 1.6 (Steam)" because Steam was
    // installed elsewhere on the machine. The module values below are what the scanner read
    // off two real installs (retail Steam Half-Life and ESK), so these checks pin the verdict
    // to observed evidence without needing either game installed where the tests run.
    private static Dictionary<string, object?> Module(string path, bool signed, string signer,
        string company = "", string product = "", string version = "") => new()
    {
        ["name"] = Path.GetFileName(path), ["path"] = path, ["sha256"] = "ab",
        ["signatureValid"] = signed, ["signer"] = signer,
        ["company"] = company, ["product"] = product, ["fileVersion"] = version
    };

    private static void EngineIdentityChecks()
    {
        const string steam = @"C:\Program Files (x86)\Steam";
        const string hl = steam + @"\steamapps\common\Half-Life";
        const string esk = @"C:\Counter-Strike ESK\Counter Strike";

        var retail = EngineIdentity.Inspect(hl + @"\hl.exe", hl, new()
        {
            Module(hl + @"\hl.exe", true, "Valve Corp.", "Valve", "Steam Half-Life Launcher", "1, 1, 1, 1"),
            Module(hl + @"\hw.dll", true, "Valve Corp."),
            Module(hl + @"\steam_api.dll", true, "Valve Corp.", "Valve Corporation", "Steam Client API"),
            Module(steam + @"\steamclient.dll", true, "Valve Corp.", "Valve Corporation", "Steam")
        });
        Check(retail.SteamVerified && retail.Distribution == "Steam (retail)", "retail Steam is verified from Valve signatures");
        Check(retail.Findings.All(f => f.Severity == "INFO"), "retail Steam raises no warning");

        // The ESK launcher carries a byte-for-byte copy of retail's version resource. Only the
        // missing signature and the emulator's own steamclient.dll give it away.
        var eskResult = EngineIdentity.Inspect(esk + @"\hl.exe", esk, new()
        {
            Module(esk + @"\hl.exe", false, "", "Valve", "Steam Half-Life Launcher", "1, 1, 1, 1"),
            Module(esk + @"\hw.dll", false, ""),
            Module(esk + @"\steamclient.dll", false, ""),
            Module(esk + @"\steam_api.dll", false, "", "Valve Corporation", "Steam Client API")
        });
        Check(!eskResult.SteamVerified && eskResult.Family == "esk", "ESK client with copied Valve version text is not Steam");
        Check(eskResult.SteamClientOrigin.StartsWith("game folder"), "steamclient.dll loaded beside the game is reported as an emulator");
        Check(eskResult.Findings.Count == 0 && eskResult.NonSteamDistribution, "a non-Steam client is whitelisted: identified, but no finding to review");

        // Retail ships steam_api.dll beside the game too. Its location alone must not make
        // a genuine install look like an emulator.
        Check(retail.Family == "" && !retail.Distribution.Contains("emulator"), "Valve-signed steam_api.dll in the game folder is not an emulator marker");

        var swapped = EngineIdentity.Inspect(hl + @"\hl.exe", hl, new()
        {
            Module(hl + @"\hl.exe", true, "Valve Corp."),
            Module(hl + @"\hw.dll", false, ""),
            Module(steam + @"\steamclient.dll", true, "Valve Corp.")
        });
        Check(!swapped.SteamVerified, "signed launcher in front of an unsigned engine is not retail");
        Check(swapped.Findings.Any(f => f.Id == "acs-engine-replaced-in-steam-install" && f.Severity == "WARNING"), "engine replaced inside a Steam install is raised for review");

        // A signature is only proof when Windows validated it AND it names Valve exactly.
        var forgedName = EngineIdentity.Inspect(hl + @"\hl.exe", hl, new()
        {
            Module(hl + @"\hl.exe", false, "Valve Corp."),
            Module(hl + @"\hw.dll", false, "Valve Corp.")
        });
        Check(!forgedName.SteamVerified, "a Valve signer name without a valid signature proves nothing");
        var lookalike = EngineIdentity.Inspect(hl + @"\hl.exe", hl, new()
        {
            Module(hl + @"\hl.exe", true, "Not Valve Corp."),
            Module(hl + @"\hw.dll", true, "Not Valve Corp.")
        });
        Check(!lookalike.SteamVerified, "a validly signed look-alike publisher is not Valve");

        // Steam installed somewhere on the machine is no longer evidence of anything.
        var unattributed = EngineIdentity.Inspect(@"D:\cs16\hl.exe", @"D:\cs16", new()
        {
            Module(@"D:\cs16\hl.exe", false, ""),
            Module(@"D:\cs16\hw.dll", false, "")
        });
        Check(!unattributed.SteamVerified && unattributed.Confidence == "none", "no signature and no marker is unverified, never assumed Steam");

        var foreignEngine = EngineIdentity.Inspect(@"D:\cs16\hl.exe", @"D:\cs16", new()
        {
            Module(@"D:\cs16\hl.exe", false, ""),
            Module(@"C:\Temp\hw.dll", true, "Valve Corp.")
        });
        Check(foreignEngine.EngineModule == "", "same-named engine outside the game root is not accepted as the game engine");

        // Trust by module name: a DLL called client.dll only inherits it inside the install.
        var isTrusted = typeof(ScannerEngine).GetMethod("IsTrustedModule", BindingFlags.NonPublic | BindingFlags.Static)!;
        var installRoot = typeof(ScannerEngine).GetField("_gameInstallRoot", BindingFlags.NonPublic | BindingFlags.Static)!;
        bool Trusted(string path) => (bool)isTrusted.Invoke(null, new object[] { "client.dll", path, "", false })!;
        installRoot.SetValue(null, esk);
        try
        {
            Check(Trusted(esk + @"\cstrike\cl_dlls\client.dll"), "client.dll inside the game install keeps name trust");
            Check(!Trusted(@"C:\Users\player\AppData\Local\Temp\client.dll"), "client.dll injected from outside the install is not trusted");
        }
        finally
        {
            installRoot.SetValue(null, "");
        }
        Check(!Trusted(esk + @"\cstrike\cl_dlls\client.dll"), "outside a scan the name whitelist grants nothing");

        // Signer extraction: the old loader threw on every signed PE, leaving signer empty.
        // Any signed system binary proves the fix; skipped only if none can be found.
        var readMeta = typeof(ScannerEngine).GetMethod("ReadFileMetadata", BindingFlags.NonPublic | BindingFlags.Static)!;
        var signedSample = new[] { "notepad.exe", "explorer.exe" }
            .Select(n => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), n))
            .Concat(new[] { Path.Combine(Environment.SystemDirectory, "ntdll.dll") })
            .FirstOrDefault(p => File.Exists(p) && HasEmbeddedSignature(p));
        if (signedSample is not null)
        {
            var meta = readMeta.Invoke(null, new object[] { signedSample })!;
            var signer = (string)meta.GetType().GetProperty("Signer")!.GetValue(meta)!;
            Check(signer.Length > 0, $"Authenticode signer is read from a signed PE ({Path.GetFileName(signedSample)} -> {signer})");
        }
    }

    // ── Live game traffic: the server, exactly ────────────────────────────────────────
    //
    // Two approaches failed in real scans: memory text named servers the player had left, and
    // an engine structure layout taken from ReHLDS found nothing while a player was joined.
    // The server now comes from the game's live UDP traffic. These checks cover everything
    // that does not need administrator rights: packet parsing, the verdict rule, the socket
    // table read, and the refusal to guess without rights.
    private static byte[] UdpPacket(byte[] source, int sourcePort, byte[] destination, int destinationPort, int fragmentOffset = 0)
    {
        var packet = new byte[20 + 8 + 16];
        packet[0] = 0x45;                           // IPv4, 20-byte header
        packet[2] = 0; packet[3] = (byte)packet.Length;
        packet[6] = (byte)((fragmentOffset >> 8) & 0x1F); packet[7] = (byte)fragmentOffset;
        packet[8] = 64;                             // TTL
        packet[9] = 17;                             // UDP
        source.CopyTo(packet, 12);
        destination.CopyTo(packet, 16);
        packet[20] = (byte)(sourcePort >> 8); packet[21] = (byte)sourcePort;
        packet[22] = (byte)(destinationPort >> 8); packet[23] = (byte)destinationPort;
        return packet;
    }

    private static void LiveTrafficChecks()
    {
        var player = new byte[] { 192, 168, 1, 20 };
        var server = new byte[] { 217, 156, 22, 149 };

        var outgoing = UdpPacket(player, 27005, server, 27015);
        Check(GameTraffic.TryParseUdp(outgoing, out var src, out var srcPort, out var dst, out var dstPort)
              && src.ToString() == "192.168.1.20" && srcPort == 27005 && dst.ToString() == "217.156.22.149" && dstPort == 27015,
            "IPv4/UDP header parsed to exact addresses and ports");
        Check(!GameTraffic.TryParseUdp(UdpPacket(player, 27005, server, 27015, fragmentOffset: 185), out _, out _, out _, out _),
            "a later IP fragment is skipped, not misread as a UDP header");
        var tcp = UdpPacket(player, 27005, server, 27015);
        tcp[9] = 6;
        Check(!GameTraffic.TryParseUdp(tcp, out _, out _, out _, out _), "non-UDP traffic is ignored");

        var ports = new List<int> { 27005 };
        var now = DateTimeOffset.UtcNow;

        var joined = GameTraffic.Decide(new Dictionary<string, (int, int)>
        {
            ["217.156.22.149:27015"] = (72, 64),    // a joined client: dozens of packets a second
            ["85.10.20.7:27015"] = (1, 1)            // one server-browser ping
        }, 2500, ports, now);
        Check(joined.Status == "connected" && joined.Endpoint == "217.156.22.149:27015" && joined.Sent == 72 && joined.Received == 64,
            "sustained traffic names the exact server IP:Port the game is joined to");

        var outboundOnly = GameTraffic.Decide(new Dictionary<string, (int, int)> { ["217.156.22.149:27015"] = (70, 0) }, 2500, ports, now);
        Check(outboundOnly.Status == "connected", "outgoing traffic alone is enough (a firewall may hide incoming packets from capture)");

        var menu = GameTraffic.Decide(new Dictionary<string, (int, int)>
        {
            ["85.10.20.7:27015"] = (2, 1), ["85.10.20.8:27015"] = (1, 1), ["85.10.20.9:27016"] = (1, 0)
        }, 2500, ports, now);
        Check(menu.Status == "not-connected" && menu.Endpoint == "", "server-browser queries in the menu are No Server Detected");

        var silent = GameTraffic.Decide(new Dictionary<string, (int, int)>(), 2500, ports, now);
        Check(silent.Status == "not-connected", "no traffic at all is No Server Detected");

        // The socket table read, against a real UDP socket opened by this test.
        using (var probe = new System.Net.Sockets.UdpClient(new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, 0)))
        {
            var own = ((System.Net.IPEndPoint)probe.Client.LocalEndPoint!).Port;
            var selfPid = Process.GetCurrentProcess().Id;
            var listed = GameTraffic.UdpPortsOf(selfPid);
            Check(listed.Contains(own), $"Windows UDP socket table read correctly (found this process's port {own})");
            Check(!GameTraffic.UdpPortsOf(selfPid + 1_000_000).Contains(own), "ports are attributed to their owning process only");
        }

        // The authoritative connected-peer read: the OS UDP endpoint table must expose the
        // exact remote server a connected socket is talking to (the data netstat prints).
        // This is what lets the scanner report the true server rather than guessing from memory.
        using (var connected = new System.Net.Sockets.UdpClient())
        {
            connected.Connect("8.8.8.8", 53);
            System.Threading.Thread.Sleep(200);
            var selfPid = Process.GetCurrentProcess().Id;
            var peers = GameTraffic.ConnectedUdpPeersOf(selfPid);
            Check(peers.Any(p => p.RemoteAddress.ToString() == "8.8.8.8" && p.RemotePort == 53),
                "connected UDP peer exposes the exact remote server IP:port");
            Check(GameTraffic.ConnectedUdpPeersOf(selfPid + 1_000_000).Count == 0,
                "connected peers are attributed to their owning process only");
        }

        // After the socket above is closed, the same process must read as not connected.
        {
            var afterClose = GameTraffic.Capture(Process.GetCurrentProcess().Id, CancellationToken.None, 300);
            Check(afterClose.Status == "not-connected",
                "a process with no connected UDP socket is No Server Detected");
        }

        if (!GameTraffic.IsElevated())
        {
            var capture = GameTraffic.Capture(Process.GetCurrentProcess().Id, CancellationToken.None, 300);
            Check(capture.Status == "not-connected",
                "without administrator rights user-space detection runs cleanly without elevation");
        }

        Check(ValveA2S.TryParseEndpoint("127.0.0.1:27015", out var ep1) && ep1?.Port == 27015, "ValveA2S parses valid IPv4:port endpoints");
        Check(!ValveA2S.TryParseEndpoint("invalid:endpoint", out _), "ValveA2S rejects invalid endpoints");

        var version = new List<byte> { 0 };
        version.AddRange(System.Text.Encoding.ASCII.GetBytes("1.1.2.7/Stdio"));
        version.Add(0);
        Check(LiveEngineState.FindVersionString(new[] { (0x10000000L, version.ToArray()) }, "1.1.2.7") == "1.1.2.7/Stdio",
            "live engine version string is read exactly, including the file-system suffix");

        Check(EngineIdentity.BuildNumber("Apr 13 2009") == 4554, "engine build number formula: Apr 13 2009 is build 4554");
        Check(EngineIdentity.BuildNumber("Nov 16 2023") == 9884, "engine build number formula: Nov 16 2023 is build 9884");

        // Against the real engine files when this machine has them.
        const string eskRoot = @"C:\Counter-Strike ESK\Counter Strike";
        if (File.Exists(Path.Combine(eskRoot, "hw.dll")))
        {
            var esk = EngineIdentity.Inspect(Path.Combine(eskRoot, "hl.exe"), eskRoot, new()
            {
                Module(Path.Combine(eskRoot, "hw.dll"), false, ""),
                Module(Path.Combine(eskRoot, @"cstrike\cl_dlls\client.dll"), false, "")
            });
            Check(esk.EngineBuildNumber == 4554 && esk.EngineCompiled == "Jun 15 2009 16:05:41" && esk.EngineVersion == "1.1.2.6",
                $"real ESK engine: v{esk.EngineVersion}, build {esk.EngineBuildNumber}, compiled {esk.EngineCompiled}");
        }

        var hl = Environment.GetEnvironmentVariable("ACS_LIVE_TESTS") == "1" ? Process.GetProcessesByName("hl").FirstOrDefault() : null;
        if (hl is not null)
        {
            var res = GameTraffic.Capture(hl.Id, CancellationToken.None, 3000);
            Check(res.Status == "connected" ? (res.A2S is not null && res.A2S.Success) : !string.IsNullOrEmpty(res.Status),
                res.Status == "connected"
                    ? $"live hl.exe server resolved: {res.Endpoint} ('{res.A2S?.Name}', Map: '{res.A2S?.Map}')"
                    : $"live hl.exe detected in idle/menu state ({res.Status})");
        }
    }

    private static bool HasEmbeddedSignature(string path)
    {
        try
        {
#pragma warning disable SYSLIB0057
            using var cert = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(path);
#pragma warning restore SYSLIB0057
            return true;
        }
        catch
        {
            return false;   // catalog-signed only: nothing embedded to read
        }
    }

    private static void LegitFilesChecks()
    {
        var legitDir = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../tools/legit_files"));
        if (!Directory.Exists(legitDir))
        {
            legitDir = Path.GetFullPath("tools/legit_files");
        }
        if (!Directory.Exists(legitDir))
        {
            Console.WriteLine("Warning: tools/legit_files not found; skipping disk checks");
            return;
        }

        var isTrusted = typeof(ScannerEngine).GetMethod("IsTrustedModule", BindingFlags.NonPublic | BindingFlags.Static)!;
        var installRoot = typeof(ScannerEngine).GetField("_gameInstallRoot", BindingFlags.NonPublic | BindingFlags.Static)!;

        installRoot.SetValue(null, legitDir);
        try
        {
            var files = Directory.GetFiles(legitDir, "*.dll");
            Check(files.Length >= 20, $"legit_files directory populated (found {files.Length} DLLs)");

            foreach (var file in files)
            {
                var name = Path.GetFileName(file);
                bool trusted = (bool)isTrusted.Invoke(null, new object[] { name, file, "", false })!;
                Check(trusted, $"legitimate file '{name}' is trusted inside game install");
            }
        }
        finally
        {
            installRoot.SetValue(null, "");
        }

        // Test Steam CS 1.6 verification from Valve source files
        const string steam = @"C:\Program Files (x86)\Steam";
        const string hl = steam + @"\steamapps\common\Half-Life";

        var steamFiles = new List<Dictionary<string, object?>>
        {
            Module(hl + @"\hl.exe", true, "Valve Corp."),
            Module(hl + @"\hw.dll", true, "Valve Corp."),
            Module(hl + @"\Core.dll", true, "Valve"),
            Module(hl + @"\DemoPlayer.dll", true, "Valve"),
            Module(hl + @"\FileSystem_Stdio.dll", true, "Valve"),
            Module(hl + @"\proxy.dll", true, "Valve"),
            Module(hl + @"\vgui.dll", true, "Valve"),
            Module(hl + @"\vgui2.dll", true, "Valve"),
            Module(hl + @"\avcodec-53.dll", true, "Valve"),
            Module(hl + @"\avformat-53.dll", true, "Valve"),
            Module(hl + @"\avutil-51.dll", true, "Valve"),
            Module(hl + @"\icudt.dll", true, "Valve"),
            Module(hl + @"\libcef.dll", true, "Valve"),
            Module(hl + @"\chromehtml.dll", false, ""),
            Module(hl + @"\a3dapi.dll", false, ""),
            Module(hl + @"\tier0.dll", false, ""),
            Module(hl + @"\vstdlib.dll", false, ""),
            Module(hl + @"\Mss32.dll", false, ""),
            Module(hl + @"\SDL2.dll", false, ""),
            Module(hl + @"\steam_api.dll", true, "Valve Corp."),
            Module(steam + @"\steamclient.dll", true, "Valve Corp.")
        };

        var steamResult = EngineIdentity.Inspect(hl + @"\hl.exe", hl, steamFiles);
        Check(steamResult.SteamVerified && steamResult.Distribution == "Steam (retail)", "Steam CS from Valve source is verified as retail");
        Check(steamResult.Findings.Count == 0, "Steam CS from Valve source raises 0 warning findings");

        // Test NextClient attribution with NextClient legitimate files
        var nextClientFiles = new List<Dictionary<string, object?>>
        {
            Module(hl + @"\hl.exe", false, ""),
            Module(hl + @"\hw.dll", false, ""),
            Module(hl + @"\next_engine_mini.dll", false, "NextClient"),
            Module(hl + @"\next_lib.dll", false, "NextClient"),
            Module(hl + @"\nitro_api2.dll", false, "NextClient"),
            Module(hl + @"\FileSystem_Proxy.dll", false, "NextClient"),
            Module(hl + @"\steam_api.dll", false, "NextClient")
        };

        var nextClientResult = EngineIdentity.Inspect(hl + @"\hl.exe", hl, nextClientFiles);
        Check(nextClientResult.Family == "nextclient", "NextClient files attributed to NextClient family");
        Check(nextClientResult.NonSteamDistribution, "NextClient recognized as non-Steam distribution");

        // Test Recycle Bin forensics
        var dbPath = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../database/cheats_database.json"));
        if (!File.Exists(dbPath)) dbPath = Path.GetFullPath("database/cheats_database.json");
        using var dbDoc = JsonDocument.Parse(File.ReadAllBytes(dbPath));
        var binFindings = new List<Dictionary<string, object?>>();
        var scanRecycle = typeof(ScannerEngine).GetMethod("ScanRecycleBin", BindingFlags.NonPublic | BindingFlags.Static)!;
        scanRecycle.Invoke(null, new object[] { dbDoc.RootElement, binFindings, new HashSet<string>(), new List<string>() });
        Check(binFindings.Any(f => (string?)f["subject"] != null && ((string)f["subject"]!).Contains("Alternative", StringComparison.OrdinalIgnoreCase)),
            "Recycle Bin forensics detects deleted Alternative Hack / unknowncheats archive");
    }
}
