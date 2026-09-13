using ACPScanner;
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

        var consent = typeof(ScannerEngine).GetMethod("RequestUploadConsentAsync", BindingFlags.NonPublic | BindingFlags.Static)!;
        Task<bool> Decide(Func<string, CancellationToken, Task<bool>>? callback, CancellationToken token = default) =>
            (Task<bool>)consent.Invoke(null, new object?[] { "{\"fixture\":true}", token, callback })!;
        Check(!Decide(null).GetAwaiter().GetResult(), "missing upload consent fails closed");
        Check(!Decide((_, _) => Task.FromResult(false)).GetAwaiter().GetResult(), "declining the preview prevents upload");
        Check(Decide((json, _) => Task.FromResult(json.Contains("fixture"))).GetAwaiter().GetResult(), "approval receives the exact report");
        try { Decide((_, _) => Task.FromResult(true), cancelled.Token).GetAwaiter().GetResult(); Check(false, "cancelled consent rejected"); }
        catch (OperationCanceledException) { Check(true, "cancelled consent rejected"); }

        if (args.Length > 0)
        {
            ApplicationConfiguration.Initialize();
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
}
