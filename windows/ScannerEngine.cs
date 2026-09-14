using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;

namespace ACPScanner;

public static class ScannerEngine
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

		public bool Enabled { get; private set; } = true;

		public bool Valid => CompileErrors.Count == 0;

		public List<string> CompileErrors { get; } = new List<string>();

		public List<string> Scopes { get; } = new List<string>();

		public List<MatchCondition> Conditions { get; } = new List<MatchCondition>();

		public static CompiledRule From(JsonElement rule)
		{
			CompiledRule compiledRule = new CompiledRule();
			compiledRule.Id = ReadString(rule, "id", "unknown-rule");
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
			return source.Equals("live-behavior", StringComparison.OrdinalIgnoreCase) && Scopes.Any((string s) => s.Equals("demo-file", StringComparison.OrdinalIgnoreCase));
		}
	}

	private sealed class MatchCondition
	{
		public string Key { get; init; } = "";

		public bool IsRegex { get; init; }

		public List<string> Values { get; } = new List<string>();

		public List<Regex> Regexes { get; } = new List<Regex>();
	}

	/// <summary>
	/// The game server as the engine reported it at the moment the scan started. Status is
	/// "connected", "local", "not-connected" or "unverified"; Address, Name and Map are only
	/// ever filled for "connected", and Name/Map only from the server's own reply.
	/// </summary>
	private sealed record ConnectedServer(string Status, string Address, string Name, string Map, string NameSource, GameTraffic.Result Traffic, string LiveVersion, ValveA2S.ServerInfo? A2S = null);

	private sealed record HlTarget(Process Process, string Path, string Root, string Hash, string StartTime, int TotalGameProcesses, int ActiveGameProcesses = 1);

	private sealed record SteamIdentity(string SteamId64, string AccountId, string Steam2, string Steam3, string Source, List<Dictionary<string, object?>> Candidates)
	{
		public static SteamIdentity Empty { get; } = new SteamIdentity("", "", "", "", "", new List<Dictionary<string, object>>());
	}

	private sealed record GameWindowInfo(string Title, string Mode, bool IsFullscreen, string Bounds);

	private sealed record ModuleRange(string Name, string Path, long Base, long Size);

	private sealed record InlineHookResult(bool Hooked, string? HookedAddr);

	private sealed record DemoEntry(int Type, string Description, int Flags, int CDTrack, float TrackTime, int Frames, int Offset, int FileLength);

	private readonly record struct DemoFrame(float Time, float ViewPitch, float ViewYaw, float ViewRoll, float ForwardMove, float SideMove, float UpMove, ushort Buttons, float PunchX, float PunchY, float PunchZ)
	{
		public static DemoFrame Empty { get; } = new DemoFrame(0f, 0f, 0f, 0f, 0f, 0f, 0f, 0, 0f, 0f, 0f);
	}

	private readonly record struct LiveInputSample(double Time, int X, int Y, bool Attack, bool Jump, bool Forward, bool Back, bool Left, bool Right, bool Duck, bool InGame, double MouseDelta);

	private sealed class LiveBehaviorResult
	{
		public string StartedAt { get; }

		public int TotalSamples { get; set; }

		public int ActiveSamples { get; set; }

		public double DurationSeconds { get; set; }

		public int AttackSamples { get; set; }

		public int AttackPresses { get; set; }

		public int LowMoveAttackPresses { get; set; }

		public int SnapAttackPresses { get; set; }

		public int JumpStrafeSamples { get; set; }

		public int StrafeAlternations { get; set; }

		public double MouseMoveTotal { get; set; }

		public double MaxMouseDelta { get; set; }

		public string ScannerOutput { get; set; } = "";

		public LiveBehaviorResult(string startedAt)
		{
			StartedAt = startedAt;
		}

		public Dictionary<string, object?> ToDictionary()
		{
			return new Dictionary<string, object>
			{
				["startedAt"] = StartedAt,
				["durationSeconds"] = DurationSeconds.ToString("0.0"),
				["activeSamples"] = ActiveSamples,
				["totalSamples"] = TotalSamples,
				["attackPresses"] = AttackPresses,
				["lowMoveAttackPresses"] = LowMoveAttackPresses,
				["snapAttackPresses"] = SnapAttackPresses,
				["jumpStrafeSamples"] = JumpStrafeSamples,
				["strafeAlternations"] = StrafeAlternations,
				["maxMouseDelta"] = MaxMouseDelta.ToString("0.0"),
				["output"] = ScannerOutput
			};
		}
	}

	private sealed class DemoBehaviorResult
	{
		public string Path { get; }

		public long Bytes { get; }

		public string LastWriteUtc { get; }

		public bool Valid { get; set; }

		public int DemoProtocol { get; set; }

		public int NetProtocol { get; set; }

		public string Map { get; set; } = "";

		public string GameDir { get; set; } = "";

		public int Frames { get; set; }

		public double DurationSeconds { get; set; }

		public int AttackFrames { get; set; }

		public int AttackPresses { get; set; }

		public int MicroAngleAttackPresses { get; set; }

		public int AttackSnapFrames { get; set; }

		public double AttackSnapDeltaTotal { get; set; }

		public double MaxAngleDelta { get; set; }

		public double AngleDeltaTotal { get; set; }

		public int AngleSamples { get; set; }

		public int PunchSamples { get; set; }

		public double PunchTotal { get; set; }

		public int ZeroPunchAttackFrames { get; set; }

		public int JumpMoveFrames { get; set; }

		public int InvalidMoveFrames { get; set; }

		public bool PreviousAttack { get; set; }

		public string ScannerOutput { get; set; } = "";

		public DemoBehaviorResult(string path, long bytes, string lastWriteUtc)
		{
			Path = path;
			Bytes = bytes;
			LastWriteUtc = lastWriteUtc;
		}

		public Dictionary<string, object?> ToDictionary(string root)
		{
			return new Dictionary<string, object>
			{
				["file"] = SafeRelative(root, Path),
				["path"] = Path,
				["bytes"] = Bytes,
				["lastWriteUtc"] = LastWriteUtc,
				["valid"] = Valid,
				["map"] = Map,
				["gameDir"] = GameDir,
				["frames"] = Frames,
				["durationSeconds"] = DurationSeconds.ToString("0.0"),
				["attackPresses"] = AttackPresses,
				["attackSnapFrames"] = AttackSnapFrames,
				["maxAngleDelta"] = MaxAngleDelta.ToString("0.0"),
				["invalidMoveFrames"] = InvalidMoveFrames,
				["output"] = ScannerOutput
			};
		}
	}

	private sealed record SteamIdentityCandidate(string SteamId64, string AccountId, string Steam2, string Steam3, string Source, bool IsPrimary)
	{
		public static SteamIdentityCandidate FromAccountId(ulong accountId, string source, bool primary)
		{
			return new SteamIdentityCandidate((76561197960265728L + accountId).ToString(), accountId.ToString(), $"STEAM_0:{accountId & 1}:{accountId >> 1}", $"[U:1:{accountId}]", source, primary);
		}

		public Dictionary<string, object?> ToDictionary()
		{
			return new Dictionary<string, object>
			{
				["steamId"] = SteamId64,
				["steamAccountId"] = AccountId,
				["steamId2"] = Steam2,
				["steamId3"] = Steam3,
				["source"] = Source,
				["primary"] = IsPrimary
			};
		}
	}

	private sealed record FileHashes(string Sha256, string Sha1, string Md5, string Crc32 = "")
	{
		public static FileHashes Empty { get; } = new FileHashes("", "", "");
	}

	private sealed record FileMetadata(string FileVersion, string Company, string Product, string Signer)
	{
		public static FileMetadata Empty { get; } = new FileMetadata("", "", "", "");
	}

	private sealed record VolumeIdentity(string Volume, string Serial);

	private struct MemoryBasicInformation
	{
		public nint BaseAddress;

		public nint AllocationBase;

		public uint AllocationProtect;

		public nuint RegionSize;

		public uint State;

		public uint Protect;

		public uint Type;
	}

	private struct NativeRect
	{
		public int Left;

		public int Top;

		public int Right;

		public int Bottom;
	}

	private struct NativePoint
	{
		public int X;

		public int Y;
	}

	private struct WintrustFileInfo
	{
		public uint cbStruct;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string pcwszFilePath;

		public nint hFile;

		public nint pgKnownSubject;
	}

	private struct WintrustData
	{
		public uint cbStruct;

		public nint pPolicyCallbackData;

		public nint pSIPClientData;

		public uint dwUIChoice;

		public uint fdwRevocationChecks;

		public uint dwUnionChoice;

		public nint pFile;

		public uint dwStateAction;

		public nint hWVTStateData;

		public nint pwszURLReference;

		public uint dwProvFlags;

		public uint dwUIContext;

		public nint pSignatureSettings;
	}

	private const int MaxFindings = 500;

	// Budget for assets only (sprites, models, sounds, maps). Code and config files are
	// never dropped - see SelectHlCandidates.
	private const int MaxHlFiles = 2500;

	// Sanity ceiling for code/config files, so a pathological folder cannot make a scan
	// run forever. A CS 1.6 install is nowhere near this.
	private const int MaxHlCodeFiles = 20000;

	private const int MaxMemoryArtifacts = 80;

	private const int MaxDemoFiles = 8;

	private const int MaxConfigFiles = 400;

	private const long MaxDemoBytes = 134217728L;

	private const long MaxHashBytes = 67108864L;

	private const int ProcessQueryInformation = 1024;

	private const int ProcessVmRead = 16;

	private const uint MemCommit = 4096u;

	private const uint MemImage = 16777216u;

	private const uint MemMapped = 262144u;

	private const uint MemPrivate = 131072u;

	private const uint PageGuard = 256u;

	private const uint PageNoAccess = 1u;

	private const uint PageReadWrite = 4u;

	private const uint PageWriteCopy = 8u;

	private const uint PageExecute = 16u;

	private const uint PageExecuteRead = 32u;

	private const uint PageExecuteReadWrite = 64u;

	private const uint PageExecuteWriteCopy = 128u;

	private const int DemoHeaderSize = 544;

	private const int DemoEntrySize = 92;

	private const int DemoInfoSize = 440;

	private const int DemoSequenceInfoSize = 28;

	private const int DemoClientDataSize = 32;

	private const int DemoEventSize = 72;

	private const int DemoMaxMessage = 65536;

	private const ushort InAttack = 1;

	private const ushort InJump = 2;

	private static readonly HashSet<string> TrustedGoldSrcModules = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
	{
		"hl.exe", "cstrike.exe", "cs.exe", "hw.dll", "sw.dll", "client.dll", "demoplayer.dll", "core.dll", "GameUI.dll", "vgui.dll",
		"vgui2.dll", "steamclient.dll", "steam_api.dll", "steam_api_c.dll", "Steam.dll", "FileSystem_Steam.dll",
		"filesystem_stdio.dll", "particleman.dll", "voice_miles.dll", "Mss32.dll", "mp3dec.asi", "mssv12.asi", "mssv29.asi", "SDL2.dll",
		"gameoverlayrenderer.dll", "proxy.dll", "a3dapi.dll", "avcodec-53.dll", "avformat-53.dll", "avutil-51.dll",
		"avcodec-54.dll", "avformat-54.dll", "avutil-52.dll", "chromehtml.dll", "icudt.dll", "libcef.dll",
		"tier0.dll", "tier0_s.dll", "vstdlib.dll", "vstdlib_s.dll", "steam_api64.dll", "crashhandler.dll",
		"mp.dll", "valve.dll", "mssmp3.asi", "mssdsp.asi", "mssvoice.asi",
		"FileSystem_Proxy.dll", "next_engine_mini.dll", "next_lib.dll", "nitro_api.dll", "nitro_api2.dll",
		"nextclient.dll", "next_client.dll"
	};

	private static readonly string[] TrustedSigners = new string[12]
	{
		"Microsoft Windows", "Microsoft Corporation", "Microsoft Windows Hardware Compatibility Publisher", "Microsoft Windows Publisher", "Valve", "NVIDIA", "Advanced Micro Devices", "Intel", "Realtek", "Google LLC",
		"Logitech", "Razer"
	};

	private static readonly string WindowsDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

	private static readonly string[] ConfigFileNames = new string[6] { "config.cfg", "autoexec.cfg", "userconfig.cfg", "listenserver.cfg", "valve.rc", "game.cfg" };

	private static RuleSet? _activeRules;

	private static readonly string[] MatchSources = new string[11]
	{
		"game-process", "process", "module", "driver", "memory", "hl-file", "hl-config", "execution-trace", "download-trace", "live-behavior",
		"demo-file"
	};

	private static readonly SemaphoreSlim ScanGate = new SemaphoreSlim(1, 1);

	private static CancellationToken _scanToken;

	private static readonly string[] GameProcessNames = new string[5] { "hl", "cstrike", "cs", "cs_new", "cstrike_new" };

	private static readonly (string Module, string Kind, string[] Exports)[] HookTargets = new(string, string, string[])[3]
	{
		("opengl32.dll", "OpenGL render (wallhack / ESP / chams)", new string[13]
		{
			"glVertex3fv", "glVertex3f", "glBegin", "glEnd", "glColor4f", "glColor4fv", "glNormal3fv", "glDrawElements", "wglSwapBuffers", "glReadPixels",
			"glClear", "glHint", "glDepthRange"
		}),
		("kernel32.dll", "timing (speedhack)", new string[3] { "GetTickCount", "GetTickCount64", "QueryPerformanceCounter" }),
		("winmm.dll", "timing (speedhack)", new string[1] { "timeGetTime" })
	};

	private static readonly string[] IntegrityCriticalModules = new string[7] { "hw.dll", "sw.dll", "client.dll", "opengl32.dll", "d3d9.dll", "gameui.dll", "vgui2.dll" };

	// Render and OS modules that legitimate overlays hook in order to draw over a game. Steam's
	// gameoverlayrenderer, NVIDIA, Discord, Xbox Game Bar and recorder tools all hook
	// wglSwapBuffers / wglSwapLayerBuffers, which is byte-for-byte what an ESP does. A hook or
	// patch here is review evidence, never an automatic DETECTED verdict on its own.
	private static readonly HashSet<string> OverlayHookableModules = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
	{
		"opengl32.dll", "d3d9.dll", "d3d8.dll", "ddraw.dll", "dxgi.dll", "winmm.dll", "gdi32.dll", "user32.dll", "dsound.dll", "wininet.dll"
	};

	// Folders that hold real game content. Third-party runtimes that ship in the root of a Steam
	// install (CEF: libcef/chromehtml/icudt, FFmpeg: avcodec/avformat/avutil) are not game code
	// and self-modify at runtime (V8 JIT, FFmpeg CPU dispatch), so they are not integrity-verified.
	private static readonly string[] GameModDirectories = new string[6] { "cstrike", "valve", "czero", "dod", "tfc", "gearbox" };

	private static readonly string[] SuspiciousTools = new string[18]
	{
		"cheatengine", "speedhack", "vehdebug", "x64dbg", "x32dbg", "ollydbg", "scylla", "extremeinjector", "xenos", "ghinjector",
		"artmoney", "squalr", "reclass", "megadumper", "tsearch", "wpe", "winject", "processhacker"
	};

	private static readonly (string Mutex, string Cheat)[] CheatMutexes = new(string, string)[1] { ("oxware_launcher_mutex", "oxware") };

	private static readonly (string Folder, string Cheat)[] CheatConfigFolders = new(string, string)[1] { ("oxware", "oxware") };

	private static readonly (string RegistryKey, string Cheat)[] CheatRegistryKeys = new(string, string)[1] { ("Software\\oxware", "oxware") };

	private static readonly object HashCacheLock = new object();

	private static readonly ConcurrentDictionary<string, FileHashes> HashCache = new ConcurrentDictionary<string, FileHashes>();

	private const int HashCacheMaxEntries = 40000;

	private const int HashChunkBytes = 1048576;

	private static readonly uint[] Crc32Table = GenerateCrc32Table();


	private const int AfInet = 2;

	private const int UdpTableOwnerPid = 1;

	/// <summary>
	/// Scans the running game and uploads the report as soon as the scan finishes.
	///
	/// Consent is given once, before the scan starts, on a screen that says the report will
	/// be uploaded automatically (ScanPrivacy). There is no second prompt at the end - the
	/// player already agreed to exactly this. <paramref name="uploadConsented"/> still fails
	/// closed: a caller that never showed that screen gets a scan and no upload.
	/// </summary>
	public static async Task<ScanUploadResult> ScanAndUploadAsync(string apiUrl, string apiToken, IProgress<string> progress, CancellationToken cancellationToken, bool uploadConsented = false)
	{
		await ScanGate.WaitAsync(cancellationToken);
		try
		{
			_scanToken = cancellationToken;
			HashCache.Clear();
			return await ScanCoreAsync(apiUrl, apiToken, progress, cancellationToken, uploadConsented);
		}
		finally
		{
			_activeRules = null;
			_scanToken = default(CancellationToken);
			_gameInstallRoot = "";
			HashCache.Clear();
			ScanGate.Release();
		}
	}

	private static async Task<ScanUploadResult> ScanCoreAsync(string apiUrl, string apiToken, IProgress<string> progress, CancellationToken cancellationToken, bool uploadConsented)
	{
		if (!Uri.TryCreate(apiUrl, UriKind.Absolute, out Uri endpoint) || (endpoint.Scheme != Uri.UriSchemeHttps && (!(endpoint.Scheme == Uri.UriSchemeHttp) || !endpoint.IsLoopback)))
		{
			throw new InvalidOperationException("Use HTTPS for the ACS server, or HTTP on localhost for development.");
		}
		List<Dictionary<string, object?>> stages = new List<Dictionary<string, object>>();
		Stopwatch stageWatch = Stopwatch.StartNew();
		DateTimeOffset scanStartedAt = DateTimeOffset.UtcNow;
		Stopwatch stopwatch = Stopwatch.StartNew();
		using (HttpClient http = new HttpClient(new HttpClientHandler
		{
			AllowAutoRedirect = true
		})
		{
			Timeout = TimeSpan.FromSeconds(60L)
		})
		{
			http.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 LongHornACS/1.0");
			if (!string.IsNullOrWhiteSpace(apiToken))
			{
				http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", apiToken.Trim());
			}
			Stage("Finding running Counter-Strike (hl.exe / cstrike.exe)...");
			HlTarget target = FindHlTarget();
			if ((object)target == null)
			{
				throw new InvalidOperationException("Counter-Strike is not running. Open the game (hl.exe or cstrike.exe), then press SCAN to finish the scan.");
			}
			// Published for IsTrustedModule: the GoldSrc name whitelist only grants trust to
			// files that are actually part of this install.
			_gameInstallRoot = target.Root;
			using (target.Process)
			{
				Stage("Downloading cheat database...");
				string databaseJson = await http.GetStringAsync(BuildUrl(apiUrl, "database"), cancellationToken);
				DateTimeOffset databaseFetchedAt = DateTimeOffset.UtcNow;
				using JsonDocument database = JsonDocument.Parse(databaseJson);
				if (!database.RootElement.TryGetProperty("signatures", out var signatures) || signatures.ValueKind != JsonValueKind.Array || signatures.GetArrayLength() == 0)
				{
					throw new InvalidOperationException("Server returned an empty or invalid signature database. Scan aborted.");
				}
				Dictionary<string, object?> databaseCounts = ReadCounts(database.RootElement);
				_activeRules = RuleSet.Build(database.RootElement);
				List<Dictionary<string, object?>> findings = new List<Dictionary<string, object>>();
				HashSet<string> findingKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
				List<string> notes = new List<string>();
				foreach (CompiledRule invalidRule in _activeRules.All.Where(r => !r.Valid))
				{
					notes.Add($"Signature rule '{invalidRule.Id}' was disabled: {string.Join("; ", invalidRule.CompileErrors)}");
				}
				List<Dictionary<string, object?>> processes = new List<Dictionary<string, object>>();
				List<Dictionary<string, object?>> modules = new List<Dictionary<string, object>>();
				List<Dictionary<string, object?>> drivers = new List<Dictionary<string, object>>();
				List<Dictionary<string, object?>> hlFiles = new List<Dictionary<string, object>>();
				List<Dictionary<string, object?>> memoryArtifacts = new List<Dictionary<string, object>>();
				List<Dictionary<string, object?>> liveBehavior = new List<Dictionary<string, object>>();
				HashSet<string> hlPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { target.Path };
				// Read the game-server connection now, at the moment the scan starts - that is
				// the moment the report describes. It samples the engine for about a second and,
				// when joined, asks the server for its name (A2S_INFO), so it runs alongside the
				// rest of the scan instead of being appended to it.
				//
				// It gets its own notes list: List<string> is not safe to append to from two
				// threads, and the main scan is writing to `notes` throughout.
				List<string> serverNotes = new List<string>();
				Task<ConnectedServer> serverLookup = Task.Run(delegate
				{
					try
					{
						return DetectConnectedServer(target, serverNotes, cancellationToken);
					}
					catch (OperationCanceledException)
					{
						throw;
					}
					catch (Exception ex)
					{
						serverNotes.Add("Connected-server lookup failed: " + ex.Message);
						return new ConnectedServer("unverified", "", "", "", "",
							new GameTraffic.Result("unverified", "", 0, 0, 0, Array.Empty<int>(), "lookup failed: " + ex.Message, DateTimeOffset.UtcNow), "");
					}
				});

				Stage("Scanning hl.exe process...");
				ScanGameProcess(database.RootElement, target, processes, modules, findings, findingKeys, notes);
				if (target.ActiveGameProcesses > 1)
				{
					AddEngineFinding(findings, findingKeys, "acp-multiple-hl-processes", "Multiple active hl.exe processes detected", "WARNING", "review", "game-process", $"{target.ActiveGameProcesses} active hl.exe processes ({target.TotalGameProcesses} total)", "Multiple active game processes detected. Check for secondary injector or hidden game instances.", target.StartTime);
				}
				if (DateTime.TryParse(target.StartTime, null, System.Globalization.DateTimeStyles.RoundtripKind, out DateTime gameStart))
				{
					TimeSpan uptime = scanStartedAt.UtcDateTime - gameStart.ToUniversalTime();
					if (uptime.TotalSeconds >= 0 && uptime.TotalSeconds < 45)
					{
						AddEngineFinding(findings, findingKeys, "acp-timestamp-restart-suspect", "Game launched immediately prior to scan", "WARNING", "environment", "game-process", $"Game uptime: {(int)uptime.TotalSeconds} seconds", "Counter-Strike was launched or restarted less than 45 seconds before the scan was initiated. Check timestamps to verify if game was restarted to clear injected modules.", target.StartTime);
					}
				}
				Stage("Scanning running processes against the unified database...");

				ScanProcesses(database.RootElement, target.Process.Id, processes, findings, findingKeys, notes);
				Stage("Scanning driver signatures...");
				ScanDrivers(database.RootElement, drivers, findings, findingKeys, notes);
				Stage("Scanning hl.exe memory evidence...");
				ScanGameMemory(database.RootElement, target, modules, memoryArtifacts, findings, findingKeys, notes);
				Stage("Scanning hl.exe code for inline hooks...");
				InlineHookResult hookResult = ScanInlineHooks(target, modules, findings, findingKeys, notes);
				Stage("Verifying game module code against the files on disk...");
				List<Dictionary<string, object?>> moduleIntegrity = VerifyGameModules(target, modules, findings, findingKeys, notes);
				GameWindowInfo windowInfo = ReadGameWindowInfo(target.Process);
				Stage("Scanning in-memory GoldSrc cvars...");
				// The old cvar probe guessed a cvar_t layout from the first pointer-shaped byte
				// sequence after a name. That layout varies across Steam and community engines and
				// produced false detections, so it remains disabled until build-specific layouts are
				// validated. Config-file cvars are still collected as review evidence.
				Stage("Checking for external readers, injected threads and overlays...");
				Dictionary<string, object?> externalSurface = ScanExternalSurface(target, modules, windowInfo, findings, findingKeys, notes);
				Stage("Scanning live hl.exe directory...");
				ScanHlDirectories(database.RootElement, hlFiles, findings, findingKeys, notes, hlPaths);
				Stage("Reading live game configs...");
				ScanGameConfigs(database.RootElement, target, findings, findingKeys, notes, hlPaths);
				Stage("Sampling game input & window responsiveness...");
				LiveBehaviorResult liveBehaviorResult = await ScanLiveBehaviorAsync(database.RootElement, target, liveBehavior, findings, findingKeys, notes, cancellationToken);
				Stage("Running ACS evidence engine...");

				// What this client actually is, read from the files the process has mapped
				// rather than guessed from their names. See EngineIdentity for why the old
				// answer reported a non-Steam install as genuine Steam. Established before the
				// evidence rules run, because whether a patched engine is expected depends on it.
				// The server lookup started with the scan and is long finished by now; its engine
				// read also carries the live version string.
				ConnectedServer serverInfo = serverLookup.GetAwaiter().GetResult();
				EngineIdentity.Result engineIdentity = EngineIdentity.Inspect(target.Path, target.Root, modules, serverInfo.LiveVersion);
				RunAcpEvidenceEngine(target, modules, hlFiles, findings, findingKeys, engineIdentity.NonSteamDistribution);
				string renderMode = DetectRenderMode(modules);
				foreach (EngineIdentity.EngineFinding engineFinding in engineIdentity.Findings)
				{
					AddEngineFinding(findings, findingKeys, engineFinding.Id, engineFinding.Name, engineFinding.Severity,
						"environment", "game-process", engineFinding.Subject, engineFinding.Reason, target.StartTime);
				}

				List<Dictionary<string, object?>> engineChecks = BuildEngineChecks(target, modules, hlFiles, memoryArtifacts, windowInfo, renderMode, scanStartedAt);
				engineChecks.Add(Check("Client distribution identified", engineIdentity.Confidence != "none", engineIdentity.Distribution));
				engineChecks.Add(Check("Launcher signed by Valve", engineIdentity.LauncherSigned,
					engineIdentity.LauncherSigned ? engineIdentity.LauncherSigner : "not signed / not verifiable"));
				engineChecks.Add(Check("Engine build identified", engineIdentity.EngineBuildNumber is not null,
					(engineIdentity.EngineModule == "" ? "engine module not found" : engineIdentity.EngineModule)
						+ (engineIdentity.EngineVersion == "" ? "" : " v" + engineIdentity.EngineVersion)
						+ (engineIdentity.EngineBuildNumber is null ? " — build not determined" : " build " + engineIdentity.EngineBuildNumber)));
				engineChecks.Add(Check("No inline hooks (render/timing)", !hookResult.Hooked, hookResult.Hooked ? ("hook -> " + hookResult.HookedAddr) : "none found"));
				int verifiedModules = moduleIntegrity.Count((Dictionary<string, object> m) => Convert.ToString(m.GetValueOrDefault("status")) == "clean");
				int patchedModules = moduleIntegrity.Count((Dictionary<string, object> m) => Convert.ToString(m.GetValueOrDefault("status")) == "patched");
				if (modules.Count == 0 || verifiedModules + patchedModules == 0)
				{
					AddEngineFinding(findings, findingKeys, "acs-incomplete-module-coverage", "Module inspection incomplete", "WARNING", "review", "game-process", target.Path, "The game modules could not be fully inspected. This scan cannot establish a clean module baseline.", target.StartTime);
				}
				engineChecks.Add(Check("Game module code matches disk", patchedModules == 0 && verifiedModules > 0, (verifiedModules == 0) ? "no module could be verified" : $"{verifiedModules} verified, {patchedModules} modified"));
				engineChecks.Add(Check("Live in-game process responsive", target.Process.Responding, target.Process.Responding ? "process responding" : "process not responding"));
				Stage("Checking for running cheat/debug tools...");
				ScanRunningTools(findings, findingKeys, notes);
				Stage("Checking known cheat artifacts (mutex/config/registry)...");
				ScanCheatArtifacts(findings, findingKeys, notes);
				Stage("Scanning launch and download traces...");
				ScanExecutionTraces(database.RootElement, findings, findingKeys, notes);
				ScanRegistryExecutionHistory(database.RootElement, findings, findingKeys, notes);
				ScanDownloadedTraces(database.RootElement, findings, findingKeys, notes);
				ScanRecycleBin(database.RootElement, findings, findingKeys, notes);
				Stage("Scanning NTFS change journal for recent deletions...");
				ScanUsnJournalDeletions(target.Root, findings, findingKeys, notes);
				int detected = findings.Count((Dictionary<string, object> f) => SeverityOf(f) == "DETECTED");
				int warnings = findings.Count((Dictionary<string, object> f) => SeverityOf(f) == "WARNING");
				string status = ((detected > 0) ? "DETECTED" : ((warnings > 0) ? "WARNING" : "CLEAN"));
				Dictionary<string, object?> detectedCheats = BuildDetectedCheats(findings);
				SteamIdentity steamId = ReadSteamId();
				VolumeIdentity hdd = ReadVolumeSerial(target.Root);
				string deviceFingerprint = StableDeviceFingerprint(steamId.SteamId64, hdd.Serial);
				Stage("Resolving the connected game server...");
				notes.AddRange(serverNotes);
				progress.Report(DescribeServer(serverInfo));
				engineChecks.Add(Check("Connected game server", serverInfo.Status == "connected",
					serverInfo.Status switch
					{
						"connected" => $"{Or(serverInfo.Name, "name not reported")} — {serverInfo.Address}" + (serverInfo.Map != "" ? " — map " + serverInfo.Map : ""),
						"not-connected" => "No Server Detected",
						_ => "not verified: " + serverInfo.Traffic.Reason
					}));
				if (serverInfo.Status == "not-connected")
				{
					AddEngineFinding(findings, findingKeys, "acp-server-not-connected", "Player not connected to game server", "INFO", "environment", "game-process", "No Server Detected", "The game was not joined to any server when the scan started (" + serverInfo.Traffic.Reason + "). Effective anticheat scanning is best performed while connected to a game server.", target.StartTime);
				}
				cancellationToken.ThrowIfCancellationRequested();

				if (target.Process.HasExited)
				{
					throw new InvalidOperationException("The game exited during scanning. No complete verdict is available.");
				}
				stopwatch.Stop();
				DateTimeOffset scanFinishedAt = DateTimeOffset.UtcNow;
				List<Dictionary<string, object?>> list = stages;
				list[list.Count - 1]["durationMs"] = stageWatch.ElapsedMilliseconds;
				Dictionary<string, object?> report = new Dictionary<string, object>
				{
					["scanner"] = "ACS",
					["scannerVersion"] = ScannerVersion,
					["scannerBuild"] = ScannerBuild.Value,
					["scanStages"] = stages.ToArray(),
					["scanMode"] = "on-demand",
					["databaseRevision"] = CryptoUtils.Sha256Hex(Encoding.UTF8.GetBytes(databaseJson)),
					["databaseFetchedAt"] = databaseFetchedAt.ToString("O"),
					["createdAt"] = DateTimeOffset.UtcNow.ToString("O"),
					["scanStartedAt"] = scanStartedAt.ToString("O"),
					["scanFinishedAt"] = scanFinishedAt.ToString("O"),
					["scanDurationMs"] = (long)stopwatch.Elapsed.TotalMilliseconds,
					["machineName"] = Environment.MachineName,
					["playerName"] = ReadPlayerName(target.Root) ?? Environment.UserName,
					["playerId"] = StablePlayerId(),
					["steamId"] = steamId.SteamId64,
					["steamAccountId"] = steamId.AccountId,
					["steamId2"] = steamId.Steam2,
					["steamId3"] = steamId.Steam3,
					["steamIdentitySource"] = steamId.Source,
					["steamIdentityCandidates"] = steamId.Candidates,
					["hddSerial"] = hdd.Serial,
					["hddVolume"] = hdd.Volume,
					["deviceFingerprint"] = deviceFingerprint,
					["osVersion"] = Environment.OSVersion.ToString(),
					["gameBuild"] = engineIdentity.GameBuild,
					["engine"] = new Dictionary<string, object?>
					{
						["distribution"] = engineIdentity.Distribution,
						["family"] = engineIdentity.Family,
						["nonSteamDistribution"] = engineIdentity.NonSteamDistribution,
						["steamVerified"] = engineIdentity.SteamVerified,
						["confidence"] = engineIdentity.Confidence,
						["trust"] = engineIdentity.Trust,
						["module"] = engineIdentity.EngineModule,
						["buildDate"] = engineIdentity.EngineBuildDate,
						["compiled"] = engineIdentity.EngineCompiled,
						["buildNumber"] = engineIdentity.EngineBuildNumber,
						["buildNumberSource"] = engineIdentity.EngineBuildNumberSource,
						["version"] = engineIdentity.EngineVersion,
						["versionSource"] = engineIdentity.EngineVersionSource,
						["gameDirectory"] = engineIdentity.GameDirectory,
						["fileVersion"] = engineIdentity.EngineFileVersion,
						["sha256"] = engineIdentity.EngineSha256,
						["launcherSha256"] = engineIdentity.LauncherSha256,
						["launcherSigned"] = engineIdentity.LauncherSigned,
						["launcherSigner"] = engineIdentity.LauncherSigner,
						["steamClientOrigin"] = engineIdentity.SteamClientOrigin,
						["evidence"] = engineIdentity.Evidence
							.Select(e => new Dictionary<string, object?>
							{
								["name"] = e.Name,
								["value"] = e.Value,
								["source"] = e.Source
							})
							.ToArray()
					},
					["renderMode"] = renderMode,
					["gameWindowTitle"] = windowInfo.Title,
					["gameWindowMode"] = windowInfo.Mode,
					["gameWindowBounds"] = windowInfo.Bounds,
					["gameLaunchTime"] = target.StartTime,
					["localTime"] = DateTimeOffset.Now.ToString("O"),
					["utcOffsetMinutes"] = (int)TimeZoneInfo.Local.GetUtcOffset(DateTimeOffset.Now).TotalMinutes,
					["timeZoneName"] = TimeZoneInfo.Local.DisplayName,
					["serverAddress"] = serverInfo.Address,
					["serverName"] = serverInfo.Name,
					["serverMap"] = serverInfo.Map,
					["serverDetection"] = new Dictionary<string, object?>
					{
						["status"] = serverInfo.Status,

						["address"] = serverInfo.Address,
						["name"] = serverInfo.Name,
						["map"] = serverInfo.Map,
						["nameSource"] = serverInfo.NameSource,
						["capturedAt"] = serverInfo.Traffic.CapturedAt.ToString("O"),
						["method"] = "zero-privilege Valve A2S server query",
						["packetsSent"] = serverInfo.Traffic.Sent,
						["packetsReceived"] = serverInfo.Traffic.Received,
						["sampleMs"] = serverInfo.Traffic.SampleMilliseconds,
						["gameUdpPorts"] = serverInfo.Traffic.LocalPorts.ToArray(),
						["reason"] = serverInfo.Traffic.Reason,
						["folder"] = serverInfo.A2S?.Folder ?? "",
						["game"] = serverInfo.A2S?.Game ?? "",
						["players"] = serverInfo.A2S?.Players ?? 0,
						["maxPlayers"] = serverInfo.A2S?.MaxPlayers ?? 0,
						["bots"] = serverInfo.A2S?.Bots ?? 0,
						["serverType"] = serverInfo.A2S?.ServerType ?? "",
						["environment"] = serverInfo.A2S?.Environment ?? "",
						["vac"] = serverInfo.A2S?.VacSecured ?? false,
						["protocol"] = serverInfo.A2S?.Protocol ?? 0,
						["version"] = serverInfo.A2S?.Version ?? ""
					},
					["gameRoot"] = target.Root,
					["steamPath"] = ReadSteamPath() ?? "",
					["configPath"] = FindConfigPath(target.Root) ?? "",
					["databaseCounts"] = databaseCounts,
					["status"] = status,
					["hooked"] = hookResult.Hooked,
					["hookedAddr"] = hookResult.HookedAddr ?? "",
					["hlPath"] = target.Path,
					["summary"] = new Dictionary<string, object>
					{
						["processes"] = processes.Count,
						["modules"] = modules.Count,
						["drivers"] = drivers.Count,
						["hlFiles"] = hlFiles.Count,
						["memoryArtifacts"] = memoryArtifacts.Count,
						["liveBehaviorSamples"] = liveBehaviorResult.ActiveSamples,
						["findings"] = findings.Count,
						["detected"] = detected,
						["warnings"] = warnings
					},
					["moduleIntegrity"] = moduleIntegrity,
					["externalSurface"] = externalSurface,
					["detectedCheats"] = detectedCheats,
					["engineChecks"] = engineChecks,
					["findings"] = findings,
					["processes"] = processes,
					["modules"] = modules,
					["drivers"] = drivers,
					["memoryArtifacts"] = memoryArtifacts,
					["liveBehavior"] = liveBehavior,
					["hlFiles"] = hlFiles,
					["notes"] = notes
				};
				cancellationToken.ThrowIfCancellationRequested();
				string reportJson = JsonSerializer.Serialize(report, JsonOptions());
				if (!uploadConsented)
					return new ScanUploadResult(false, status, detected, warnings, processes.Count, drivers.Count, hlFiles.Count, null, null, UploadDeclined: true, ServerStatus: serverInfo.Status, ServerName: serverInfo.Name, ServerAddress: serverInfo.Address, ServerMap: serverInfo.Map);
				cancellationToken.ThrowIfCancellationRequested();
				progress.Report("Uploading report...");
				string signature = string.Empty;
				if (!string.IsNullOrWhiteSpace(apiToken))
				{
					using HMACSHA256 hmac = new HMACSHA256(Encoding.UTF8.GetBytes(apiToken));
					signature = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(reportJson)));
				}
				string payload = JsonSerializer.Serialize(new Dictionary<string, object>
				{
					["reportJson"] = reportJson,
					["signature"] = signature,
					["algorithm"] = "hmac-sha256"
				}, JsonOptions());
				using StringContent content = new StringContent(payload, Encoding.UTF8, "application/json");
				using HttpResponseMessage response = await http.PostAsync(BuildUrl(apiUrl, "upload_report"), content, cancellationToken);
				string uploadBody = await response.Content.ReadAsStringAsync(cancellationToken);
				if (!response.IsSuccessStatusCode)
				{
					return new ScanUploadResult(Uploaded: false, status, detected, warnings, processes.Count, drivers.Count, hlFiles.Count, null, uploadBody, ServerStatus: serverInfo.Status, ServerName: serverInfo.Name, ServerAddress: serverInfo.Address, ServerMap: serverInfo.Map);
				}
				using JsonDocument upload = JsonDocument.Parse(uploadBody);
				JsonElement root = upload.RootElement;
				if (!root.TryGetProperty("ok", out var accepted) || accepted.ValueKind != JsonValueKind.True)
				{
					return new ScanUploadResult(Uploaded: false, status, detected, warnings, processes.Count, drivers.Count, hlFiles.Count, null, "Server did not accept the report.", ServerStatus: serverInfo.Status, ServerName: serverInfo.Name, ServerAddress: serverInfo.Address, ServerMap: serverInfo.Map);
				}
				if (root.TryGetProperty("summary", out var serverSummary))
				{
					status = ReadString(serverSummary, "status", status);
					if (serverSummary.TryGetProperty("detected", out var d) && d.TryGetInt32(out var dc))
					{
						detected = dc;
					}
					if (serverSummary.TryGetProperty("warnings", out var w) && w.TryGetInt32(out var wc))
					{
						warnings = wc;
					}
				}
				string relativeUrl = (root.TryGetProperty("url", out var urlElement) ? urlElement.GetString() : null);
				return new ScanUploadResult(ReportUrl: MakeAbsoluteReportUrl(apiUrl, relativeUrl), Uploaded: true, Status: status, Detected: detected, Warnings: warnings, Processes: processes.Count, Drivers: drivers.Count, HlFiles: hlFiles.Count, Error: null, ServerStatus: serverInfo.Status, ServerName: serverInfo.Name, ServerAddress: serverInfo.Address, ServerMap: serverInfo.Map);
			}
		}
		void Stage(string message)
		{
			cancellationToken.ThrowIfCancellationRequested();
			if (stages.Count > 0)
			{
				List<Dictionary<string, object?>> list2 = stages;
				list2[list2.Count - 1]["durationMs"] = stageWatch.ElapsedMilliseconds;
			}
			stages.Add(new Dictionary<string, object>
			{
				["name"] = message,
				["durationMs"] = 0L
			});
			stageWatch.Restart();
			progress.Report(message);
		}
	}

	private static HlTarget? FindHlTarget()
	{
		Process[] array = GameProcessNames.SelectMany((string name) => Process.GetProcessesByName(name)).ToArray();
		Process[] array2 = array.Where((Process p) => Safe(() => !p.HasExited && (p.MainWindowHandle != IntPtr.Zero || p.Threads.Count > 1))).ToArray();
		int activeGameProcesses = Math.Max(1, array2.Length);
		foreach (Process process in array.OrderByDescending((Process p) => Safe(() => p.StartTime)))
		{
			try
			{
				string text = process.MainModule?.FileName;
				if (string.IsNullOrWhiteSpace(text) || !File.Exists(text))
				{
					continue;
				}
				string directoryName = Path.GetDirectoryName(text);
				if (string.IsNullOrWhiteSpace(directoryName) || !Directory.Exists(directoryName))
				{
					continue;
				}
				return new HlTarget(process, text, directoryName, TrySha256(text) ?? "", Safe(() => process.StartTime.ToUniversalTime().ToString("O")) ?? "", array.Length, activeGameProcesses);
			}
			catch
			{
			}
		}
		return null;
	}

	private static void ScanGameProcess(JsonElement database, HlTarget target, List<Dictionary<string, object?>> processes, List<Dictionary<string, object?>> modules, List<Dictionary<string, object?>> findings, HashSet<string> findingKeys, List<string> notes)
	{
		processes.Add(new Dictionary<string, object>
		{
			["pid"] = target.Process.Id,
			["name"] = target.Process.ProcessName,
			["path"] = target.Path,
			["sha256"] = target.Hash,
			["startedAt"] = target.StartTime
		});
		MatchRules(database, "game-process", $"{target.Process.ProcessName} {target.Path} {target.Hash}", target.Path, findings, findingKeys, target.StartTime, target.Hash);
		ScanProcessModules(database, target.Process, modules, findings, findingKeys, notes);
	}

	private static void ScanProcesses(JsonElement database, int gameProcessId, List<Dictionary<string, object?>> processes, List<Dictionary<string, object?>> findings, HashSet<string> findingKeys, List<string> notes)
	{
		Process[] running = Process.GetProcesses().OrderBy<Process, string>((Process p) => p.ProcessName, StringComparer.OrdinalIgnoreCase).ToArray();
		(Process Proc, string? Path, FileHashes Hashes, long Bytes, int Id, string? Note)[] results = new(Process, string, FileHashes, long, int, string)[running.Length];
		Parallel.For(0, running.Length, new ParallelOptions
		{
			MaxDegreeOfParallelism = MathUtils.Clamp(Environment.ProcessorCount / 2, 1, 2),
			CancellationToken = _scanToken
		}, delegate(int i)
		{
			Process process2 = running[i];
			int num3 = Safe(() => process2.Id);
			string text4 = null;
			FileHashes item2 = FileHashes.Empty;
			long procBytes = 0;
			string item3 = null;
			if (num3 != gameProcessId)
			{
				try
				{
					// Works for 64-bit processes from this 32-bit app, where MainModule throws.
					text4 = ModuleIntegrity.ProcessImagePath(num3);
					if (string.IsNullOrWhiteSpace(text4))
					{
						text4 = process2.MainModule?.FileName;
					}
				}
				catch
				{
					item3 = $"Process access denied: {process2.ProcessName} ({num3})";
				}
				if (!string.IsNullOrWhiteSpace(text4))
				{
					item2 = TryFileHashes(text4);
					procBytes = Safe(() => new FileInfo(text4).Length);
				}
			}
			results[i] = (Proc: process2, Path: text4, Hashes: item2, Bytes: procBytes, Id: num3, Note: item3);
		});
		(Process, string, FileHashes, long, int, string)[] array = results;
		for (int num = 0; num < array.Length; num++)
		{
			var (process, text, procHashes, procBytes, num2, text3) = array[num];
			if (process != null)
			{
				if (text3 != null)
				{
					notes.Add(text3);
				}
				Dictionary<string, object> item = new Dictionary<string, object>
				{
					["pid"] = num2,
					["name"] = process.ProcessName,
					["path"] = text ?? "",
					["sha256"] = procHashes.Sha256,
					["md5"] = procHashes.Md5,
					["sha1"] = procHashes.Sha1,
					["bytes"] = procBytes
				};
				processes.Add(item);
				string surface = $"{process.ProcessName} {text} {procHashes.Sha256} {procHashes.Md5}";
				string hashSurface = $"{procHashes.Sha256} {procHashes.Md5} {procHashes.Sha1}";
				MatchRules(database, "process", surface, text ?? process.ProcessName, findings, findingKeys, "", hashSurface);
			}
		}
	}


	private static void ScanProcessModules(JsonElement database, Process process, List<Dictionary<string, object?>> modules, List<Dictionary<string, object?>> findings, HashSet<string> findingKeys, List<string> notes)
	{
		try
		{
			foreach (ProcessModule module in process.Modules)
			{
				string text = ModuleIntegrity.NormalizeModulePath(module.FileName ?? "");
				FileHashes fileHashes = TryFileHashes(text);
				FileMetadata fileMetadata = ReadFileMetadata(text);
				uint signatureResult = AuthenticodeResult(text);
				bool flag = signatureResult == 0;
				bool flag2 = IsTrustedModule(module.ModuleName, text, fileMetadata.Signer, flag);
				modules.Add(new Dictionary<string, object>
				{
					["name"] = module.ModuleName,
					["path"] = text,
					["baseAddress"] = ((IntPtr)module.BaseAddress).ToInt64(),
					["memorySize"] = module.ModuleMemorySize,
					["sha256"] = fileHashes.Sha256,
					["sha1"] = fileHashes.Sha1,
					["md5"] = fileHashes.Md5,
					["crc32"] = fileHashes.Crc32,
					["fileVersion"] = fileMetadata.FileVersion,
					["company"] = fileMetadata.Company,
					["product"] = fileMetadata.Product,
					["signer"] = fileMetadata.Signer,
					["signatureValid"] = flag,
					["signatureStatus"] = SignatureStatus(signatureResult),
					["trusted"] = flag2
				});
				// "trusted" is presentation metadata, never a reduced scanning surface. Attackers
				// control filenames and install-directory contents, so every module is matched using
				// its name/path metadata as well as its hashes.
				MatchRules(database, "module", $"{module.ModuleName} {text} {fileHashes.Sha256} {fileHashes.Sha1} {fileHashes.Md5} {fileHashes.Crc32} {fileMetadata.Company} {fileMetadata.Product} {fileMetadata.Signer}", text, findings, findingKeys, "", $"{fileHashes.Sha256} {fileHashes.Sha1} {fileHashes.Md5} {fileHashes.Crc32}");
			}
		}
		catch (Exception ex)
		{
			notes.Add("Unable to enumerate hl.exe modules: " + ex.Message);
		}
	}

	private static void ScanDrivers(JsonElement database, List<Dictionary<string, object?>> drivers, List<Dictionary<string, object?>> findings, HashSet<string> findingKeys, List<string> notes)
	{
		try
		{
			RegistryKey services = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Services");
			try
			{
				string[] candidates = services?.GetSubKeyNames() ?? Array.Empty<string>();
				(string Name, string Display, string Path, FileHashes Hash, FileMetadata Meta)[] results = new(string, string, string, FileHashes, FileMetadata)[candidates.Length];
				Parallel.For(0, candidates.Length, new ParallelOptions
				{
					MaxDegreeOfParallelism = MathUtils.Clamp(Environment.ProcessorCount / 2, 1, 2),
					CancellationToken = _scanToken
				}, delegate(int i)
				{
					string text3 = candidates[i];
					using RegistryKey registryKey = services?.OpenSubKey(text3);
					int num2 = ToInt(registryKey?.GetValue("Type"));
					if ((uint)(num2 - 1) <= 1u)
					{
						string item = Convert.ToString(registryKey?.GetValue("DisplayName")) ?? "";
						string text4 = NormalizeDriverPath(Convert.ToString(registryKey?.GetValue("ImagePath")) ?? "");
						bool driverFileExists = File.Exists(ModuleIntegrity.NativeFilePath(text4));
						FileHashes item2 = (driverFileExists ? TryFileHashes(text4) : FileHashes.Empty);
						FileMetadata item3 = (driverFileExists ? ReadFileMetadata(text4) : FileMetadata.Empty);
						results[i] = (Name: text3, Display: item, Path: text4, Hash: item2, Meta: item3);
					}
				});
				(string, string, string, FileHashes, FileMetadata)[] array = results;
				for (int num = 0; num < array.Length; num++)
				{
					var (text, value, text2, fileHashes, fileMetadata) = array[num];
					if (text != null)
					{
						drivers.Add(new Dictionary<string, object>
						{
							["name"] = text,
							["displayName"] = value,
							["path"] = text2,
							["sha256"] = fileHashes.Sha256,
							["sha1"] = fileHashes.Sha1,
							["md5"] = fileHashes.Md5,
							["crc32"] = fileHashes.Crc32,
							["fileVersion"] = fileMetadata.FileVersion,
							["company"] = fileMetadata.Company,
							["signer"] = fileMetadata.Signer
						});
						MatchRules(database, "driver", $"{text} {value} {text2} {fileHashes.Sha256} {fileHashes.Sha1} {fileHashes.Md5} {fileHashes.Crc32} {fileMetadata.Company} {fileMetadata.Signer}", (text2 != "") ? text2 : text, findings, findingKeys, "", $"{fileHashes.Sha256} {fileHashes.Sha1} {fileHashes.Md5} {fileHashes.Crc32}");
					}
				}
			}
			finally
			{
				if (services != null)
				{
					((IDisposable)services).Dispose();
				}
			}
		}
		catch (Exception ex)
		{
			notes.Add("Unable to scan drivers: " + ex.Message);
		}
	}

	private static void ScanGameMemory(JsonElement database, HlTarget target, List<Dictionary<string, object?>> modules, List<Dictionary<string, object?>> memoryArtifacts, List<Dictionary<string, object?>> findings, HashSet<string> findingKeys, List<string> notes)
	{
		nint num = OpenProcess(1040, bInheritHandle: false, target.Process.Id);
		if (num == IntPtr.Zero)
		{
			notes.Add("Unable to open hl.exe memory for read/query. Run ACS as administrator for deeper memory evidence.");
			return;
		}
		try
		{
			List<ModuleRange> source = (from m in modules
				select new ModuleRange(Convert.ToString(m.GetValueOrDefault("name")) ?? "", Convert.ToString(m.GetValueOrDefault("path")) ?? "", ToLong(m.GetValueOrDefault("baseAddress")), ToLong(m.GetValueOrDefault("memorySize"))) into m
				where m.Base > 0 && m.Size > 0
				select m).ToList();
			nint lpAddress = IntPtr.Zero;
			nuint dwLength = (nuint)Marshal.SizeOf<MemoryBasicInformation>();
			int num2 = 0;
			MemoryBasicInformation lpBuffer;
			while (VirtualQueryEx(num, lpAddress, out lpBuffer, dwLength) != UIntPtr.Zero && num2 < 12000)
			{
				num2++;
				long baseAddress = ((IntPtr)lpBuffer.BaseAddress).ToInt64();
				long num3 = (long)((UIntPtr)lpBuffer.RegionSize).ToUInt64();
				if (num3 <= 0)
				{
					break;
				}
				bool flag = IsExecutableProtection(lpBuffer.Protect);
				bool flag2 = (lpBuffer.Protect & 0x100) == 0 && (lpBuffer.Protect & 1) == 0;
				bool flag3 = source.Any((ModuleRange m) => baseAddress >= m.Base && baseAddress < m.Base + m.Size);
				if (((lpBuffer.State == 4096) & flag & flag2) && (lpBuffer.Type == 131072 || !flag3))
				{
					AddMemoryArtifact(database, num, target, lpBuffer, num3, flag3, memoryArtifacts, findings, findingKeys);
					if (memoryArtifacts.Count >= 80)
					{
						notes.Add($"Memory evidence scan stopped at {80} executable regions.");
						break;
					}
				}
				long num4 = baseAddress + num3;
				if (num4 <= baseAddress)
				{
					break;
				}
				lpAddress = new IntPtr(num4);
			}
		}
		catch (Exception ex)
		{
			notes.Add("Unable to scan hl.exe memory evidence: " + ex.Message);
		}
		finally
		{
			CloseHandle(num);
		}
	}

	private static void AddMemoryArtifact(JsonElement database, nint handle, HlTarget target, MemoryBasicInformation mbi, long regionSize, bool inKnownModule, List<Dictionary<string, object?>> memoryArtifacts, List<Dictionary<string, object?>> findings, HashSet<string> findingKeys)
	{
		int num = (int)Math.Min(regionSize, 4096L);
		if (num <= 0)
		{
			return;
		}
		byte[] array = new byte[num];
		if (ReadProcessMemory(handle, mbi.BaseAddress, array, num, out var lpNumberOfBytesRead) && lpNumberOfBytesRead > 0)
		{
			if (lpNumberOfBytesRead < array.Length)
			{
				Array.Resize(ref array, lpNumberOfBytesRead);
			}
			FileHashes fileHashes = HashBytes(array);
			string[] value = ExtractAsciiStrings(array, 8, 12).ToArray();
			string value2 = ProtectionName(mbi.Protect);
			string value3 = MemoryTypeName(mbi.Type);
			string text = $"0x{((IntPtr)mbi.BaseAddress).ToInt64():X} {value3} {value2}";
			string surface = $"{text} {fileHashes.Sha256} {fileHashes.Sha1} {fileHashes.Md5} {string.Join(" ", value)}";
			memoryArtifacts.Add(new Dictionary<string, object>
			{
				["baseAddress"] = $"0x{((IntPtr)mbi.BaseAddress).ToInt64():X}",
				["regionSize"] = regionSize,
				["type"] = value3,
				["protection"] = value2,
				["inKnownModule"] = inKnownModule,
				["sha256First4K"] = fileHashes.Sha256,
				["sha1First4K"] = fileHashes.Sha1,
				["md5First4K"] = fileHashes.Md5,
				["strings"] = string.Join(", ", value)
			});
			MatchRules(database, "memory", surface, text, findings, findingKeys, target.StartTime, $"{fileHashes.Sha256} {fileHashes.Sha1} {fileHashes.Md5} {fileHashes.Crc32}");
			if (mbi.Type == 131072 && mbi.Protect == 64)
			{
				AddEngineFinding(findings, findingKeys, "acp-executable-private-rwx-memory", "Executable private RWX memory in hl.exe", "WARNING", "review", "memory", text, "Review evidence: executable private read/write memory can indicate injected code. ACS does not call it detected without a matching signature or loaded module evidence.", target.StartTime);
			}
		}
	}

	private static InlineHookResult ScanInlineHooks(HlTarget target, List<Dictionary<string, object?>> modules, List<Dictionary<string, object?>> findings, HashSet<string> findingKeys, List<string> notes)
	{
		nint num = OpenProcess(1040, bInheritHandle: false, target.Process.Id);
		if (num == IntPtr.Zero)
		{
			notes.Add("Inline-hook scan skipped: cannot read hl.exe memory. Run ACS as administrator.");
			return new InlineHookResult(Hooked: false, null);
		}
		bool hooked = false;
		string text = null;
		try
		{
			(string, string, string[])[] hookTargets = HookTargets;
			for (int i = 0; i < hookTargets.Length; i++)
			{
				(string, string, string[]) tuple = hookTargets[i];
				string moduleName = tuple.Item1;
				string item = tuple.Item2;
				string[] item2 = tuple.Item3;
				Dictionary<string, object> dictionary = modules.FirstOrDefault((Dictionary<string, object> m) => string.Equals(Convert.ToString(m.GetValueOrDefault("name")), moduleName, StringComparison.OrdinalIgnoreCase));
				if (dictionary == null)
				{
					continue;
				}
				long num2 = ToLong(dictionary.GetValueOrDefault("baseAddress"));
				long num3 = ToLong(dictionary.GetValueOrDefault("memorySize"));
				if (num2 <= 0 || num3 <= 0)
				{
					continue;
				}
				foreach (var item5 in ResolveExports(num, num2, item2))
				{
					string item3 = item5.Name;
					long item4 = item5.Address;
					byte[] array = ReadRemoteBytes(num, item4, 8);
					if (array == null || array.Length < 5)
					{
						continue;
					}
					long? num4 = TrampolineTarget(num, array, item4);
					if (!num4.HasValue || num4.Value == 0)
					{
						continue;
					}
					Dictionary<string, object> dictionary2 = OwningModule(modules, num4.Value);
					// Benign: plenty of Windows exports forward with a JMP into another system
					// module - winmm!timeGetTime lands in kernel32 on a stock machine - and a
					// jump that stays inside the exporting module is an ordinary thunk. Only a
					// redirect into unbacked memory, or into a different untrusted module, is
					// a real hook.
					//
					// "trusted" is stored as a bool. Testing it with `is int` never matches a
					// boxed bool, so this guard silently never fired and every stock forwarder
					// was reported as a DETECTED inline hook.
					if (dictionary2 != null && dictionary2.GetValueOrDefault("trusted") is bool flag5 && flag5)
					{
						continue;
					}
					string text2 = ((dictionary2 == null) ? null : Convert.ToString(dictionary2.GetValueOrDefault("name")));
					if (text2 == null || !string.Equals(text2, moduleName, StringComparison.OrdinalIgnoreCase))
					{
						string value = text2 ?? "unbacked memory (injected code)";
						bool overlayModule = OverlayHookableModules.Contains(moduleName);
						string severity = (overlayModule ? "WARNING" : "DETECTED");
						string reason = (overlayModule
							? $"Review evidence: {moduleName}!{item3} starts with a JMP/CALL trampoline redirecting into {value}. Overlays (Steam, NVIDIA, Discord, Xbox Game Bar, recorders) hook render and timing functions like this legitimately - and so do wallhacks. Confirm which process owns the hook before acting."
							: $"High-confidence ACS inline-hook scan: {item3} starts with a JMP/CALL trampoline redirecting it into {value} — {item} hook.");
						AddEngineFinding(findings, findingKeys, "acp-inline-hook", $"Inline hook on {moduleName}!{item3} — {item}", severity, "injected", "memory", $"{moduleName}!{item3} @0x{item4:X} -> 0x{num4.Value:X} ({value})", reason, target.StartTime);
						hooked = true;
						if (text == null)
						{
							text = $"0x{num4.Value:X}";
						}
					}
				}
			}
		}
		catch (Exception ex)
		{
			notes.Add("Inline-hook scan error: " + ex.Message);
		}
		finally
		{
			CloseHandle(num);
		}
		return new InlineHookResult(hooked, text);
	}

	private static long? TrampolineTarget(nint handle, byte[] b, long address)
	{
		switch (b[0])
		{
		case 232:
		case 233:
			return address + 5 + BitConverter.ToInt32(b, 1);
		case 235:
			return address + 2 + (sbyte)b[1];
		case 104:
			if (b.Length < 6 || b[5] != 195)
			{
				break;
			}
			return BitConverter.ToUInt32(b, 1);
		case byte.MaxValue:
		{
			if (b[1] != 37)
			{
				break;
			}
			uint num = BitConverter.ToUInt32(b, 2);
			byte[] array = ReadRemoteBytes(handle, num, 4);
			return (array != null && array.Length == 4) ? BitConverter.ToUInt32(array, 0) : 0;
		}
		}
		return null;
	}

	private static List<(string Name, long Address)> ResolveExports(nint handle, long moduleBase, string[] wanted)
	{
		List<(string, long)> list = new List<(string, long)>();
		HashSet<string> hashSet = new HashSet<string>(wanted, StringComparer.Ordinal);
		byte[] array = ReadRemoteBytes(handle, moduleBase, 64);
		if (array == null || array.Length < 64 || array[0] != 77 || array[1] != 90)
		{
			return list;
		}
		int num = BitConverter.ToInt32(array, 60);
		byte[] array2 = ReadRemoteBytes(handle, moduleBase + num, 248);
		if (array2 == null || array2.Length < 128 || BitConverter.ToUInt32(array2, 0) != 17744)
		{
			return list;
		}
		ushort num2 = BitConverter.ToUInt16(array2, 24);
		int startIndex = ((num2 == 523) ? 136 : 120);
		int num3 = BitConverter.ToInt32(array2, startIndex);
		if (num3 == 0)
		{
			return list;
		}
		byte[] array3 = ReadRemoteBytes(handle, moduleBase + num3, 40);
		if (array3 == null || array3.Length < 40)
		{
			return list;
		}
		int num4 = BitConverter.ToInt32(array3, 24);
		int num5 = BitConverter.ToInt32(array3, 28);
		int num6 = BitConverter.ToInt32(array3, 32);
		int num7 = BitConverter.ToInt32(array3, 36);
		if (num4 <= 0 || num4 > 40000)
		{
			return list;
		}
		byte[] array4 = ReadRemoteBytes(handle, moduleBase + num6, num4 * 4);
		byte[] array5 = ReadRemoteBytes(handle, moduleBase + num7, num4 * 2);
		if (array4 == null || array5 == null)
		{
			return list;
		}
		for (int i = 0; i < num4; i++)
		{
			if (list.Count >= wanted.Length)
			{
				break;
			}
			int num8 = BitConverter.ToInt32(array4, i * 4);
			byte[] array6 = ReadRemoteBytes(handle, moduleBase + num8, 64);
			if (array6 == null)
			{
				continue;
			}
			int num9 = Array.IndexOf(array6, (byte)0);
			string text = Encoding.ASCII.GetString(array6, 0, (num9 < 0) ? array6.Length : num9);
			if (hashSet.Contains(text))
			{
				ushort num10 = BitConverter.ToUInt16(array5, i * 2);
				byte[] array7 = ReadRemoteBytes(handle, moduleBase + num5 + num10 * 4, 4);
				if (array7 != null && array7.Length >= 4)
				{
					list.Add((text, moduleBase + BitConverter.ToInt32(array7, 0)));
				}
			}
		}
		return list;
	}

	private static Dictionary<string, object?>? OwningModule(List<Dictionary<string, object?>> modules, long address)
	{
		foreach (Dictionary<string, object> module in modules)
		{
			long num = ToLong(module.GetValueOrDefault("baseAddress"));
			long num2 = ToLong(module.GetValueOrDefault("memorySize"));
			if (num > 0 && num2 > 0 && address >= num && address < num + num2)
			{
				return module;
			}
		}
		return null;
	}

	private static byte[]? ReadRemoteBytes(nint handle, long address, int count)
	{
		if (count <= 0)
		{
			return null;
		}
		byte[] array = new byte[count];
		if (!ReadProcessMemory(handle, new IntPtr(address), array, count, out var lpNumberOfBytesRead) || lpNumberOfBytesRead <= 0)
		{
			return null;
		}
		if (lpNumberOfBytesRead < array.Length)
		{
			Array.Resize(ref array, lpNumberOfBytesRead);
		}
		return array;
	}

	private static void ScanHlDirectories(JsonElement database, List<Dictionary<string, object?>> files, List<Dictionary<string, object?>> findings, HashSet<string> findingKeys, List<string> notes, HashSet<string> hlPaths)
	{
		string[] array = hlPaths.ToArray();
		foreach (string path in array)
		{
			string root = Path.GetDirectoryName(path);
			if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root))
			{
				continue;
			}
			string[] candidates = SelectHlCandidates(root, notes);
			if (candidates.Length == 0)
			{
				continue;
			}
			(string Rel, string Path, FileHashes Hash, FileMetadata Meta, long Len)[] results = new(string, string, FileHashes, FileMetadata, long)[candidates.Length];
			Parallel.For(0, candidates.Length, new ParallelOptions
			{
				MaxDegreeOfParallelism = MathUtils.Clamp(Environment.ProcessorCount / 2, 1, 2),
				CancellationToken = _scanToken
			}, delegate(int num3)
			{
				string file = candidates[num3];
				results[num3] = (Rel: PathUtils.GetRelativePath(root, file), Path: file, Hash: ShouldHashHlFile(file) ? TryFileHashes(file) : FileHashes.Empty, Meta: ShouldReadMetadata(file) ? ReadFileMetadata(file) : FileMetadata.Empty, Len: Safe(() => new FileInfo(file).Length));
			});
			(string, string, FileHashes, FileMetadata, long)[] array2 = results;
			for (int num = 0; num < array2.Length; num++)
			{
				var (value, text, fileHashes, fileMetadata, num2) = array2[num];
				files.Add(new Dictionary<string, object>
				{
					["relativePath"] = value,
					["path"] = text,
					["bytes"] = num2,
					["sha256"] = fileHashes.Sha256,
					["sha1"] = fileHashes.Sha1,
					["md5"] = fileHashes.Md5,
					["crc32"] = fileHashes.Crc32,
					["fileVersion"] = fileMetadata.FileVersion,
					["company"] = fileMetadata.Company,
					["signer"] = fileMetadata.Signer
				});
				MatchRules(database, "hl-file", $"{value} {text} {fileHashes.Sha256} {fileHashes.Sha1} {fileHashes.Md5} {fileHashes.Crc32} {fileMetadata.Company} {fileMetadata.Signer}", text, findings, findingKeys, "", $"{fileHashes.Sha256} {fileHashes.Sha1} {fileHashes.Md5} {fileHashes.Crc32}");
			}
		}
	}

	private static void ScanGameConfigs(JsonElement database, HlTarget target, List<Dictionary<string, object?>> findings, HashSet<string> findingKeys, List<string> notes, HashSet<string> hlPaths)
	{
		HashSet<string> hashSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
		Dictionary<string, string> dictionary = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
		string[] array = hlPaths.ToArray();
		foreach (string path in array)
		{
			string directoryName = Path.GetDirectoryName(path);
			if (string.IsNullOrWhiteSpace(directoryName) || !Directory.Exists(directoryName))
			{
				continue;
			}
			string[] array2 = new string[4]
			{
				Path.Combine(directoryName, "cstrike"),
				Path.Combine(directoryName, "cstrike", "cfg"),
				Path.Combine(directoryName, "valve"),
				Path.Combine(directoryName, "valve", "cfg")
			};
			string[] array3 = array2;
			foreach (string text in array3)
			{
				if (!Directory.Exists(text))
				{
					continue;
				}
				IEnumerable<string> enumerable;
				try
				{
					enumerable = (from f in Directory.EnumerateFiles(text, "*.*", SearchOption.AllDirectories)
						where f.EndsWith(".cfg", StringComparison.OrdinalIgnoreCase) || f.EndsWith(".rc", StringComparison.OrdinalIgnoreCase)
						select f).Take(400);
				}
				catch (Exception ex)
				{
					notes.Add("Unable to enumerate configs in " + text + ": " + ex.Message);
					continue;
				}
				foreach (string file in enumerable)
				{
					if (!hashSet.Add(file))
					{
						continue;
					}
					string text2;
					try
					{
						if (new FileInfo(file).Length > 524288)
						{
							continue;
						}
						text2 = File.ReadAllText(file);
						goto IL_01de;
					}
					catch (Exception ex2)
					{
						notes.Add("Unable to read config " + file + ": " + ex2.Message);
					}
					continue;
					IL_01de:
					string relativePath = PathUtils.GetRelativePath(directoryName, file);
					dictionary[relativePath] = text2;
					MatchRules(database, "hl-config", relativePath + "\n" + text2, relativePath, findings, findingKeys, Safe(() => File.GetLastWriteTimeUtc(file).ToString("O")) ?? "");
				}
			}
		}
		if (dictionary.Count == 0)
		{
			return;
		}
		try
		{
			foreach (ConfigAnalyzer.Finding item in ConfigAnalyzer.Analyze(dictionary))
			{
				string sev = (item.RuleId == "acp-config-binary-disguise") ? "DETECTED" : ((item.Severity == "DETECTED") ? "WARNING" : item.Severity);
				AddEngineFinding(findings, findingKeys, item.RuleId, item.RuleName, sev, "loaded", "hl-config", item.Subject + ": " + item.Evidence, item.Reason + " Config file presence does not prove execution in the current game.", "");
			}
		}
		catch (Exception ex3)
		{
			notes.Add("Config script analysis failed: " + ex3.Message);
		}
	}

	private static async Task<LiveBehaviorResult> ScanLiveBehaviorAsync(JsonElement database, HlTarget target, List<Dictionary<string, object?>> liveBehavior, List<Dictionary<string, object?>> findings, HashSet<string> findingKeys, List<string> notes, CancellationToken cancellationToken)
	{
		LiveBehaviorResult result = new LiveBehaviorResult(DateTimeOffset.UtcNow.ToString("O"));
		Queue<LiveInputSample> samples = new Queue<LiveInputSample>();
		bool previousAttack = false;
		int previousStrafe = 0;
		Stopwatch stopwatch = Stopwatch.StartNew();
		while (stopwatch.Elapsed < TimeSpan.FromMilliseconds(500L))
		{
			cancellationToken.ThrowIfCancellationRequested();
			double now = stopwatch.Elapsed.TotalSeconds;
			int foregroundPid = ForegroundProcessId();
			bool inGame = foregroundPid == target.Process.Id;
			GetCursorPos(out var point);
			bool attack = KeyDown(1);
			bool jump = KeyDown(32);
			bool forward = KeyDown(87);
			bool back = KeyDown(83);
			bool left = KeyDown(65);
			bool right = KeyDown(68);
			bool duck = KeyDown(17);
			int strafe = ((left != right) ? ((!left) ? 1 : (-1)) : 0);
			LiveInputSample? previous = ((samples.Count > 0) ? new LiveInputSample?(samples.Last()) : ((LiveInputSample?)null));
			int dx = (previous.HasValue ? (point.X - previous.Value.X) : 0);
			int dy = (previous.HasValue ? (point.Y - previous.Value.Y) : 0);
			double distance = Math.Sqrt(dx * dx + dy * dy);
			LiveInputSample sample = new LiveInputSample(now, point.X, point.Y, attack, jump, forward, back, left, right, duck, inGame, distance);
			samples.Enqueue(sample);
			while (samples.Count > 0 && now - samples.Peek().Time > 0.25)
			{
				samples.Dequeue();
			}
			result.TotalSamples++;
			if (inGame)
			{
				result.ActiveSamples++;
				result.MouseMoveTotal += distance;
				if (distance > result.MaxMouseDelta)
				{
					result.MaxMouseDelta = distance;
				}
				if (attack)
				{
					result.AttackSamples++;
				}
				if (attack && !previousAttack)
				{
					result.AttackPresses++;
					double recentMovement = samples.Sum((LiveInputSample s) => s.MouseDelta);
					if (recentMovement < 2.0)
					{
						result.LowMoveAttackPresses++;
					}
					if (recentMovement > 90.0)
					{
						result.SnapAttackPresses++;
					}
				}
				if (jump && strafe != 0)
				{
					result.JumpStrafeSamples++;
				}
				if (jump && strafe != 0 && previousStrafe != 0 && previousStrafe != strafe)
				{
					result.StrafeAlternations++;
				}
			}
			previousAttack = attack;
			if (strafe != 0)
			{
				previousStrafe = strafe;
			}
			await Task.Delay(16, cancellationToken);
		}
		result.DurationSeconds = stopwatch.Elapsed.TotalSeconds;
		result.ScannerOutput = BuildLiveBehaviorOutput(result);
		liveBehavior.Add(result.ToDictionary());
		if (!string.IsNullOrWhiteSpace(result.ScannerOutput))
		{
			MatchRules(database, "live-behavior", result.ScannerOutput, "Live in-game behavior capture", findings, findingKeys, result.StartedAt);
		}
		AddLiveBehaviorFindings(result, findings, findingKeys, target.StartTime);
		return result;
	}

	private static void ScanLiveCvars(HlTarget target, List<Dictionary<string, object?>> modules, List<Dictionary<string, object?>> findings, HashSet<string> findingKeys, List<string> notes)
	{
		Dictionary<string, object> dictionary = modules.FirstOrDefault((Dictionary<string, object> m) => string.Equals(Convert.ToString(m.GetValueOrDefault("name")), "hw.dll", StringComparison.OrdinalIgnoreCase));
		if (dictionary == null)
		{
			return;
		}
		long num = ToLong(dictionary.GetValueOrDefault("baseAddress"));
		long num2 = ToLong(dictionary.GetValueOrDefault("memorySize"));
		if (num <= 0 || num2 <= 0)
		{
			return;
		}
		nint num3 = OpenProcess(1040, bInheritHandle: false, target.Process.Id);
		if (num3 == IntPtr.Zero)
		{
			return;
		}
		try
		{
			(string, float, string, string)[] array = new(string, float, string, string)[2]
			{
				("r_drawentities", 0f, "WARNING", "Possible Wallhack/Chams state: r_drawentities appears to be 0 in live game memory"),
				("gl_monolights", 1f, "WARNING", "Possible fullbright state: gl_monolights appears to be 1 in live game memory")
			};
			int num4 = (int)Math.Min(num2, 4194304L);
			byte[] array2 = new byte[num4];
			if (!ReadProcessMemory(num3, new IntPtr(num), array2, num4, out var lpNumberOfBytesRead) || lpNumberOfBytesRead <= 0)
			{
				return;
			}
			(string, float, string, string)[] array3 = array;
			for (int num5 = 0; num5 < array3.Length; num5++)
			{
				(string, float, string, string) tuple = array3[num5];
				byte[] bytes = Encoding.ASCII.GetBytes(tuple.Item1 + "\0");
				int num6 = IndexOfSequence(array2, bytes, 0, lpNumberOfBytesRead);
				if (num6 < 0)
				{
					continue;
				}
				uint value = (uint)(num + num6);
				byte[] bytes2 = BitConverter.GetBytes(value);
				int startIndex = 0;
				while ((startIndex = IndexOfSequence(array2, bytes2, startIndex, lpNumberOfBytesRead)) >= 0)
				{
					if (startIndex + 16 <= lpNumberOfBytesRead)
					{
						float num7 = BitConverter.ToSingle(array2, startIndex + 12);
						if (Math.Abs(num7 - tuple.Item2) < 0.001f)
						{
							AddEngineFinding(findings, findingKeys, "acp-cvar-" + tuple.Item1, "Manipulated in-memory cvar: " + tuple.Item1, tuple.Item3, "in-game", "memory", $"{tuple.Item1} = {num7} (expected {1f - tuple.Item2})", tuple.Item4, DateTimeOffset.UtcNow.ToString("O"));
						}
					}
					startIndex += 4;
				}
			}
		}
		catch (Exception ex)
		{
			notes.Add("In-memory cvar scan failed: " + ex.Message);
		}
		finally
		{
			CloseHandle(num3);
		}
	}

	private static void ScanUsnJournalDeletions(string gameRoot, List<Dictionary<string, object?>> findings, HashSet<string> findingKeys, List<string> notes)
	{
		try
		{
			List<UsnJournalProbe.DeletedFileRecord> list = UsnJournalProbe.ScanRecentDeletions(gameRoot, TimeSpan.FromMinutes(30L), out string note);
			if (!string.IsNullOrWhiteSpace(note))
			{
				notes.Add(note);
			}
			string[] source = new string[15]
			{
				"cheat", "hack", "hook", "aim", "bhop", "esp", "inject", "loader", "wallhack", "trigger",
				"cdhack", "vermillion", "leis", "badboy", "fighter"
			};
			foreach (UsnJournalProbe.DeletedFileRecord item in list)
			{
				string lowerName = item.FileName.ToLowerInvariant();
				bool flag = source.Any((string p) => lowerName.Contains(p));
				string severity = "WARNING";
				double totalMinutes = (DateTimeOffset.UtcNow - item.DeletedAt).TotalMinutes;
				AddEngineFinding(findings, findingKeys, "acp-usn-" + item.FileName, "Recently deleted executable file: " + item.FileName, severity, "filesystem-forensics", "execution-trace", $"{item.FileName} on {item.Volume} (deleted {totalMinutes:F1}m ago at {item.DeletedAt:u})", flag ? "The deleted filename resembles a known cheat name, but deletion history and a name alone are not proof." : "An executable/library was deleted shortly before the scan; review only if corroborated by live evidence.", item.DeletedAt.ToString("O"));
			}
		}
		catch (Exception ex)
		{
			notes.Add("USN Journal analysis failed: " + ex.Message);
		}
	}

	private static int IndexOfSequence(byte[] buffer, byte[] pattern, int startIndex, int count)
	{
		if (buffer == null || pattern == null || pattern.Length == 0 || startIndex < 0 || count <= 0)
		{
			return -1;
		}
		int num = Math.Min(buffer.Length, startIndex + count) - pattern.Length;
		for (int i = startIndex; i <= num; i++)
		{
			bool flag = true;
			for (int j = 0; j < pattern.Length; j++)
			{
				if (buffer[i + j] != pattern[j])
				{
					flag = false;
					break;
				}
			}
			if (flag)
			{
				return i;
			}
		}
		return -1;
	}

	private static IEnumerable<string> FindRecentDemoFiles(string root, List<string> notes)
	{
		string[] source = new string[3]
		{
			root,
			Path.Combine(root, "cstrike"),
			Path.Combine(root, "valve")
		};
		List<string> list = new List<string>();
		foreach (string item in source.Where(Directory.Exists).Distinct<string>(StringComparer.OrdinalIgnoreCase))
		{
			try
			{
				list.AddRange(Directory.EnumerateFiles(item, "*.dem", SearchOption.TopDirectoryOnly));
			}
			catch (Exception ex)
			{
				notes.Add("Unable to enumerate demos in " + item + ": " + ex.Message);
			}
		}
		return (from path in list.Distinct<string>(StringComparer.OrdinalIgnoreCase)
			where Safe(() => new FileInfo(path).Length <= 134217728)
			orderby Safe(() => File.GetLastWriteTimeUtc(path)) descending
			select path).Take(8).ToArray();
	}

	private static DemoBehaviorResult AnalyzeGoldSrcDemo(string path)
	{
		using FileStream fileStream = File.OpenRead(path);
		using BinaryReader binaryReader = new BinaryReader(fileStream, Encoding.ASCII, leaveOpen: false);
		FileInfo fileInfo = new FileInfo(path);
		DemoBehaviorResult demoBehaviorResult = new DemoBehaviorResult(path, fileInfo.Length, fileInfo.LastWriteTimeUtc.ToString("O"));
		if (fileStream.Length < 544)
		{
			demoBehaviorResult.ScannerOutput = "[INFO] Demo file is too small for behavior analysis.";
			return demoBehaviorResult;
		}
		string text = Encoding.ASCII.GetString(binaryReader.ReadBytes(8)).TrimEnd('\0');
		demoBehaviorResult.Valid = text == "HLDEMO";
		demoBehaviorResult.DemoProtocol = binaryReader.ReadInt32();
		demoBehaviorResult.NetProtocol = binaryReader.ReadInt32();
		demoBehaviorResult.Map = ReadFixedAscii(binaryReader, 260);
		demoBehaviorResult.GameDir = ReadFixedAscii(binaryReader, 260);
		binaryReader.ReadUInt32();
		int num = binaryReader.ReadInt32();
		if (!demoBehaviorResult.Valid || num <= 0 || num >= fileStream.Length - 4)
		{
			demoBehaviorResult.ScannerOutput = "[INFO] Demo header not valid for GoldSrc behavior analysis.";
			return demoBehaviorResult;
		}
		fileStream.Position = num;
		int num2 = binaryReader.ReadInt32();
		if (num2 <= 0 || num2 > 1024)
		{
			demoBehaviorResult.ScannerOutput = "[INFO] Demo directory is invalid.";
			return demoBehaviorResult;
		}
		List<DemoEntry> list = new List<DemoEntry>();
		for (int i = 0; i < num2; i++)
		{
			if (fileStream.Position + 92 > fileStream.Length)
			{
				break;
			}
			list.Add(new DemoEntry(binaryReader.ReadInt32(), ReadFixedAscii(binaryReader, 64), binaryReader.ReadInt32(), binaryReader.ReadInt32(), binaryReader.ReadSingle(), binaryReader.ReadInt32(), binaryReader.ReadInt32(), binaryReader.ReadInt32()));
		}
		foreach (DemoEntry item in list.Where((DemoEntry e) => e.Offset > 0 && e.FileLength > 0))
		{
			ParseDemoEntry(binaryReader, fileStream, item, demoBehaviorResult);
			if (demoBehaviorResult.Frames >= 30000)
			{
				break;
			}
		}
		demoBehaviorResult.ScannerOutput = BuildDemoBehaviorOutput(demoBehaviorResult);
		return demoBehaviorResult;
	}

	private static void ParseDemoEntry(BinaryReader reader, Stream stream, DemoEntry entry, DemoBehaviorResult result)
	{
		long num = Math.Min(stream.Length, entry.Offset + Math.Max(0, entry.FileLength));
		stream.Position = entry.Offset;
		DemoFrame? previous = null;
		int num2 = 0;
		while (stream.Position + 16 < num && num2++ < 40000)
		{
			long position = stream.Position;
			bool flag = true;
			while (flag && stream.Position + 9 < num)
			{
				byte b = reader.ReadByte();
				reader.ReadSingle();
				reader.ReadInt32();
				switch (b)
				{
				case 3:
					SkipBytes(stream, 64, num);
					break;
				case 4:
					SkipBytes(stream, 32, num);
					break;
				case 5:
					return;
				case 6:
					SkipBytes(stream, 84, num);
					break;
				case 7:
					SkipBytes(stream, 8, num);
					break;
				case 8:
				{
					if (stream.Position + 8 > num)
					{
						return;
					}
					reader.ReadInt32();
					int num4 = reader.ReadInt32();
					if (num4 < 0 || num4 > 65536)
					{
						return;
					}
					SkipBytes(stream, num4 + 16, num);
					break;
				}
				case 9:
				{
					if (stream.Position + 4 > num)
					{
						return;
					}
					int num3 = reader.ReadInt32();
					if (num3 < 0 || num3 > 65536)
					{
						return;
					}
					SkipBytes(stream, num3, num);
					break;
				}
				default:
					flag = false;
					break;
				case 2:
					break;
				}
			}
			if (stream.Position + 440 + 28 + 4 > num)
			{
				stream.Position = Math.Min(num, position + 1);
				continue;
			}
			DemoFrame demoFrame = ReadDemoFrame(reader);
			SkipBytes(stream, 28, num);
			int num5 = reader.ReadInt32();
			if (num5 < 0 || num5 > 65536 || stream.Position + num5 > num)
			{
				break;
			}
			SkipBytes(stream, num5, num);
			AccumulateDemoFrame(result, previous, demoFrame);
			previous = demoFrame;
		}
	}

	private static DemoFrame ReadDemoFrame(BinaryReader reader)
	{
		byte[] array = reader.ReadBytes(440);
		if (array.Length < 440)
		{
			return DemoFrame.Empty;
		}
		return new DemoFrame(BitConverter.ToSingle(array, 0), BitConverter.ToSingle(array, 244), BitConverter.ToSingle(array, 248), BitConverter.ToSingle(array, 252), BitConverter.ToSingle(array, 256), BitConverter.ToSingle(array, 260), BitConverter.ToSingle(array, 264), BitConverter.ToUInt16(array, 270), BitConverter.ToSingle(array, 164), BitConverter.ToSingle(array, 168), BitConverter.ToSingle(array, 172));
	}

	private static void AccumulateDemoFrame(DemoBehaviorResult result, DemoFrame? previous, DemoFrame frame)
	{
		if (frame.Time <= 0f && result.Frames > 10)
		{
			return;
		}
		result.Frames++;
		result.DurationSeconds = Math.Max(result.DurationSeconds, frame.Time);
		bool flag = (frame.Buttons & 1) != 0;
		bool flag2 = (frame.Buttons & 2) != 0;
		double num = Math.Sqrt(frame.ForwardMove * frame.ForwardMove + frame.SideMove * frame.SideMove);
		if (flag)
		{
			result.AttackFrames++;
			double num2 = Math.Sqrt(frame.PunchX * frame.PunchX + frame.PunchY * frame.PunchY + frame.PunchZ * frame.PunchZ);
			result.PunchSamples++;
			result.PunchTotal += num2;
			if (num2 < 0.02)
			{
				result.ZeroPunchAttackFrames++;
			}
		}
		if (flag2 && num > 240.0)
		{
			result.JumpMoveFrames++;
		}
		if (Math.Abs(frame.ForwardMove) > 450f || Math.Abs(frame.SideMove) > 450f || Math.Abs(frame.UpMove) > 450f)
		{
			result.InvalidMoveFrames++;
		}
		if (!previous.HasValue)
		{
			result.PreviousAttack = flag;
			return;
		}
		double num3 = Math.Max(0.001, frame.Time - previous.Value.Time);
		if (num3 > 1.0)
		{
			result.PreviousAttack = flag;
			return;
		}
		float num4 = Math.Abs(frame.ViewPitch - previous.Value.ViewPitch);
		double num5 = Math.Abs(NormalizeAngleDelta(frame.ViewYaw - previous.Value.ViewYaw));
		double num6 = Math.Sqrt((double)(num4 * num4) + num5 * num5);
		result.AngleDeltaTotal += num6;
		result.AngleSamples++;
		if (num6 > result.MaxAngleDelta)
		{
			result.MaxAngleDelta = num6;
		}
		if (flag && num6 >= 30.0 && num3 <= 0.12)
		{
			result.AttackSnapFrames++;
			result.AttackSnapDeltaTotal += num6;
		}
		if (flag && !result.PreviousAttack)
		{
			result.AttackPresses++;
			if (num6 < 0.08)
			{
				result.MicroAngleAttackPresses++;
			}
		}
		result.PreviousAttack = flag;
	}

	private static string BuildDemoBehaviorOutput(DemoBehaviorResult result)
	{
		List<string> list = new List<string> { $"[INFO] Integrated demo scan: {Path.GetFileName(result.Path)} frames={result.Frames} duration={result.DurationSeconds:0.0}s attacks={result.AttackPresses} snaps={result.AttackSnapFrames} maxAngle={result.MaxAngleDelta:0.0}" };
		if (!result.Valid || result.Frames < 250)
		{
			list.Add("[INFO] Demo too short or invalid for AIM/TRIGGER behavioral verdict.");
			return string.Join("\n", list);
		}
		double num = ((result.AttackSnapFrames > 0) ? (result.AttackSnapDeltaTotal / (double)result.AttackSnapFrames) : 0.0);
		double num2 = ((result.AttackPresses > 0) ? ((double)result.MicroAngleAttackPresses / (double)result.AttackPresses) : 0.0);
		double num3 = ((result.AttackFrames > 0) ? ((double)result.ZeroPunchAttackFrames / (double)result.AttackFrames) : 0.0);
		double num4 = ((result.Frames > 0) ? ((double)result.JumpMoveFrames / (double)result.Frames) : 0.0);
		if (result.AttackSnapFrames >= 8 && num >= 35.0 && result.MaxAngleDelta >= 80.0)
		{
			list.Add("[DETECTED] [AIM TYPE 1. Integrated ACS demo behavior: repeated high-angle aim snaps on attack]");
		}
		else if (result.AttackSnapFrames >= 4 && num >= 28.0)
		{
			list.Add("[WARNING] [AIM TYPE 1. Integrated ACS demo behavior: suspicious aim snaps on attack]");
		}
		if (result.AttackPresses >= 20 && num2 >= 0.9)
		{
			list.Add("[DETECTED] [TRIGGER TYPE 1. Integrated ACS demo behavior: repeated perfect attack presses with near-zero aim movement]");
		}
		else if (result.AttackPresses >= 12 && num2 >= 0.75)
		{
			list.Add("[WARNING] [TRIGGER TYPE 1. Integrated ACS demo behavior: attack timing requires review]");
		}
		if (result.AttackFrames >= 30 && num3 >= 0.95)
		{
			list.Add("[WARNING] [NORECOIL TYPE 1. Integrated ACS demo behavior: recoil/punch angle nearly zero while firing]");
		}
		if (result.InvalidMoveFrames >= 5)
		{
			list.Add("[DETECTED] [MOVEMENT HACK TYPE 1. Integrated ACS demo behavior: impossible usercmd movement values]");
		}
		else if (result.JumpMoveFrames >= 120 && num4 >= 0.2)
		{
			list.Add("[WARNING] [SGS SCRIPT TYPE 1. Integrated ACS demo behavior: repeated jump+strafe movement pattern]");
		}
		return string.Join("\n", list);
	}

	private static string BuildLiveBehaviorOutput(LiveBehaviorResult result)
	{
		double value = ((result.TotalSamples > 0) ? ((double)result.ActiveSamples / (double)result.TotalSamples) : 0.0);
		double value2 = ((result.AttackPresses > 0) ? ((double)result.LowMoveAttackPresses / (double)result.AttackPresses) : 0.0);
		double value3 = ((result.AttackPresses > 0) ? ((double)result.SnapAttackPresses / (double)result.AttackPresses) : 0.0);
		double value4 = ((result.ActiveSamples > 0) ? ((double)result.JumpStrafeSamples / (double)result.ActiveSamples) : 0.0);
		List<string> list = new List<string> { $"[INFO] Live behavior scan: active={result.ActiveSamples}/{result.TotalSamples} ({value:P0}) attacks={result.AttackPresses} lowMoveAttacks={result.LowMoveAttackPresses} snapAttacks={result.SnapAttackPresses} jumpStrafe={result.JumpStrafeSamples} alternations={result.StrafeAlternations} maxMouseDelta={result.MaxMouseDelta:0.0}" };
		if (result.ActiveSamples < 120)
		{
			list.Add("[INFO] Not enough in-game foreground samples for AIM/TRIGGER behavior verdict.");
			return string.Join("\n", list);
		}
		list.Add($"[INFO] Cursor-derived ratios (not a verdict): lowMove={value2:P0} snap={value3:P0} jumpStrafe={value4:P0}");
		return string.Join("\n", list);
	}

	private static void AddLiveBehaviorFindings(LiveBehaviorResult result, List<Dictionary<string, object?>> findings, HashSet<string> findingKeys, string time)
	{
	}

	private static void SkipBytes(Stream stream, int count, long end)
	{
		if (count > 0)
		{
			stream.Position = Math.Min(end, stream.Position + count);
		}
	}

	private static string ReadFixedAscii(BinaryReader reader, int count)
	{
		byte[] array = reader.ReadBytes(count);
		int num = Array.IndexOf(array, (byte)0);
		return Encoding.ASCII.GetString(array, 0, (num < 0) ? array.Length : num).Trim();
	}

	private static double NormalizeAngleDelta(double value)
	{
		while (value > 180.0)
		{
			value -= 360.0;
		}
		while (value < -180.0)
		{
			value += 360.0;
		}
		return value;
	}

	private static List<(string Name, long Base, long Size)> ModuleRangesFor(List<Dictionary<string, object?>> modules)
	{
		return (from m in modules
			select (Name: Convert.ToString(m.GetValueOrDefault("name")) ?? "", Base: ToLong(m.GetValueOrDefault("baseAddress")), Size: ToLong(m.GetValueOrDefault("memorySize"))) into m
			where m.Base > 0 && m.Size > 0
			select m).ToList();
	}

	/// <summary>
	/// A module is integrity-verified only when it is actual game code: the launcher, an
	/// integrity-critical engine module, or a module loaded from a mod folder. Steam ships
	/// third-party runtimes (CEF: libcef/chromehtml/icudt, FFmpeg: avcodec/avformat/avutil)
	/// in the install root; those are not game code and self-modify at runtime, so comparing
	/// them only ever produces false "patched" findings.
	/// </summary>
	private static bool IsIntegrityVerifiedModule(string name, string path, string gameRoot, string launcherPath)
	{
		if (IntegrityCriticalModules.Contains(name, StringComparer.OrdinalIgnoreCase))
		{
			return true;
		}
		if (string.Equals(path, launcherPath, StringComparison.OrdinalIgnoreCase))
		{
			return true;
		}
		foreach (string mod in GameModDirectories)
		{
			if (IsUnderDirectory(path, Path.Combine(gameRoot, mod)))
			{
				return true;
			}
		}
		return false;
	}

	private static List<Dictionary<string, object?>> VerifyGameModules(HlTarget target, List<Dictionary<string, object?>> modules, List<Dictionary<string, object?>> findings, HashSet<string> findingKeys, List<string> notes)
	{
		List<Dictionary<string, object>> list = new List<Dictionary<string, object>>();
		nint num = OpenProcess(1040, bInheritHandle: false, target.Process.Id);
		if (num == IntPtr.Zero)
		{
			notes.Add("Module code verification skipped: cannot read hl.exe memory. Run ACS as administrator.");
			return list;
		}
		try
		{
			List<(string, long, long)> allModules = ModuleRangesFor(modules);
			foreach (Dictionary<string, object> module in modules)
			{
				string text = Convert.ToString(module.GetValueOrDefault("name")) ?? "";
				string text2 = Convert.ToString(module.GetValueOrDefault("path")) ?? "";
				long num2 = ToLong(module.GetValueOrDefault("baseAddress"));
				if (string.IsNullOrWhiteSpace(text2) || num2 <= 0 || !IsIntegrityVerifiedModule(text, text2, target.Root, target.Path))
				{
					continue;
				}
				ModuleIntegrity.Result result = ModuleIntegrity.Verify(num, text, text2, num2, allModules);
				list.Add(new Dictionary<string, object>
				{
					["module"] = text,
					["status"] = result.Status,
					["bytesCompared"] = result.BytesCompared,
					["bytesDiffering"] = result.BytesDiffering,
					["detail"] = result.Detail,
					["patchSites"] = ((IEnumerable<ModuleIntegrity.PatchSite>)result.Sites).Select((Func<ModuleIntegrity.PatchSite, object>)((ModuleIntegrity.PatchSite s) => $"0x{s.Address:X} ({s.Section}+0x{s.Rva:X}) len={s.Length} {s.Nearest} disk[{s.OnDisk}] live[{s.InMemory}]")).ToList(),
					["hookedImports"] = result.HookedImports.ToList(),
					["hookedExports"] = result.HookedExports.ToList()
				});
				if (!result.IsPatched)
				{
					continue;
				}
				bool overlayModule = OverlayHookableModules.Contains(text);
				string patchedSeverity = (overlayModule ? "WARNING" : "DETECTED");
				string patchedReason = (overlayModule
					? "Review evidence: this render/OS module's code differs from disk. Steam, NVIDIA, Discord, Xbox Game Bar and recorder overlays legitimately hook these modules to draw over the game, which looks identical to an ESP. Confirm the hooking process before acting."
					: "High-confidence ACS engine rule: the module's executable code in memory does not match the file it was loaded from, after accounting for relocation. Any inline hook, detour or mid-function patch produces this, regardless of how it was installed.");
				if (result.Sites.Count > 0)
				{
					ModuleIntegrity.PatchSite patchSite = result.Sites[0];
					string text3 = $"{patchSite.Nearest} at 0x{patchSite.Address:X} (disk {patchSite.OnDisk} -> live {patchSite.InMemory})";
					AddEngineFinding(findings, findingKeys, "acp-module-code-patched", "Game module code modified in memory", patchedSeverity, "injected", "module", text + ": " + text3, patchedReason, target.StartTime);
				}
				foreach (string item in result.HookedImports.Take(6))
				{
					AddEngineFinding(findings, findingKeys, "acp-iat-hook", "Import redirected to unmapped memory", patchedSeverity, "injected", "module", text + ": " + item, patchedReason, target.StartTime);
				}
				foreach (string item2 in result.HookedExports.Take(6))
				{
					AddEngineFinding(findings, findingKeys, "acp-eat-hook", "Export table entry rewritten", patchedSeverity, "injected", "module", text + ": " + item2, patchedReason, target.StartTime);
				}
			}
		}
		catch (Exception ex)
		{
			notes.Add("Module code verification failed: " + ex.Message);
		}
		finally
		{
			CloseHandle(num);
		}
		return list;
	}

	private static Dictionary<string, object?> ScanExternalSurface(HlTarget target, List<Dictionary<string, object?>> modules, GameWindowInfo windowInfo, List<Dictionary<string, object?>> findings, HashSet<string> findingKeys, List<string> notes)
	{
		Dictionary<string, object> dictionary = new Dictionary<string, object>();
		nint num = OpenProcess(1040, bInheritHandle: false, target.Process.Id);
		try
		{
			if (num != IntPtr.Zero)
			{
				List<SystemProbe.HandleHolder> list = SystemProbe.FindHandleHolders(target.Process.Id, num, out string note);
				if (note != null)
				{
					notes.Add(note);
				}
				dictionary["handleHolders"] = ((IEnumerable<SystemProbe.HandleHolder>)list).Select((Func<SystemProbe.HandleHolder, object>)((SystemProbe.HandleHolder h) => $"{h.ProcessName} (pid {h.ProcessId}) [{h.Access}] {h.ProcessPath}")).ToList();
				foreach (SystemProbe.HandleHolder item in list)
				{
					if (!IsTrustedHandleHolder(item.ProcessPath, item.ProcessName))
					{
						bool flag = item.Access.Contains("VM_WRITE") || item.Access.Contains("ALL_ACCESS");
						AddEngineFinding(findings, findingKeys, flag ? "acp-external-writer" : "acp-external-reader", flag ? "External process can write hl.exe memory" : "External process is reading hl.exe memory", "WARNING", "review", "process", $"{item.ProcessName} (pid {item.ProcessId}) [{item.Access}] {item.ProcessPath}", "An unrecognised process holds a memory-access handle on the live game. Debuggers, security tools and overlays can do this too, so require corroborating evidence before enforcement.", target.StartTime);
					}
				}
			}
			List<SystemProbe.ForeignThread> list2 = SystemProbe.FindForeignThreads(target.Process, ModuleRangesFor(modules), out string note2);
			if (note2 != null)
			{
				notes.Add(note2);
			}
			dictionary["foreignThreads"] = ((IEnumerable<SystemProbe.ForeignThread>)list2).Select((Func<SystemProbe.ForeignThread, object>)((SystemProbe.ForeignThread t) => $"tid {t.ThreadId} start 0x{t.StartAddress:X}")).ToList();
			foreach (SystemProbe.ForeignThread item2 in list2)
			{
				AddEngineFinding(findings, findingKeys, "acp-foreign-thread", "Thread start address is outside mapped modules", "WARNING", "review", "memory", $"tid {item2.ThreadId} start 0x{item2.StartAddress:X}", "Unmapped thread starts can indicate injected code, but runtime-generated code and instrumentation can look the same. Corroborate with executable-memory provenance or another detector.", target.StartTime);
			}
			SystemProbe.Rect? rect = ParseBounds(windowInfo.Bounds);
			List<SystemProbe.OverlayWindow> list3 = ((!rect.HasValue) ? new List<SystemProbe.OverlayWindow>() : SystemProbe.FindOverlayWindows(target.Process.Id, rect.Value));
			dictionary["overlayWindows"] = ((IEnumerable<SystemProbe.OverlayWindow>)list3).Select((Func<SystemProbe.OverlayWindow, object>)((SystemProbe.OverlayWindow o) => $"{o.ProcessName} (pid {o.ProcessId}) '{o.Title}' {o.Bounds} {o.Styles}")).ToList();
			foreach (SystemProbe.OverlayWindow item3 in list3)
			{
				if (!IsTrustedHandleHolder("", item3.ProcessName))
				{
					AddEngineFinding(findings, findingKeys, "acp-overlay-window", "Click-through overlay drawn over the game", "WARNING", "review", "process", $"{item3.ProcessName} (pid {item3.ProcessId}) '{item3.Title}' {item3.Bounds}", "A layered click-through window from another process sits over the game window. External ESP draws this way. Legitimate overlays (Steam, Discord, recording tools) look the same, so confirm the owning process before acting.", target.StartTime);
				}
			}
		}
		catch (Exception ex)
		{
			notes.Add("External-surface scan failed: " + ex.Message);
		}
		finally
		{
			if (num != IntPtr.Zero)
			{
				CloseHandle(num);
			}
		}
		return dictionary;
	}

	private static bool IsTrustedHandleHolder(string path, string name)
	{
		string[] source = new string[18]
		{
			"steam", "steamwebhelper", "gameoverlayui", "explorer", "csrss", "lsass", "services", "svchost", "taskmgr", "dwm",
			"SearchIndexer", "MsMpEng", "NisSrv", "SecurityHealthService", "conhost", "RuntimeBroker", "ApplicationFrameHost", "TextInputHost"
		};
		if (source.Any((string t) => string.Equals(t, name, StringComparison.OrdinalIgnoreCase)))
		{
			return true;
		}
		if (!string.IsNullOrWhiteSpace(path))
		{
			if (IsWindowsSystemModule(path))
			{
				return true;
			}
			string text = ReadSteamPath();
			if (!string.IsNullOrWhiteSpace(text) && IsUnderDirectory(path, text))
			{
				return true;
			}
		}
		return false;
	}

	private static SystemProbe.Rect? ParseBounds(string bounds)
	{
		try
		{
			string[] array = bounds.Split(' ', StringSplitOptions.RemoveEmptyEntries);
			if (array.Length != 2)
			{
				return null;
			}
			string[] array2 = array[0].Split(',');
			string[] array3 = array[1].Split('x');
			if (array2.Length != 2 || array3.Length != 2)
			{
				return null;
			}
			int num = int.Parse(array2[0]);
			int num2 = int.Parse(array2[1]);
			int num3 = int.Parse(array3[0]);
			int num4 = int.Parse(array3[1]);
			return new SystemProbe.Rect
			{
				Left = num,
				Top = num2,
				Right = num + num3,
				Bottom = num2 + num4
			};
		}
		catch
		{
			return null;
		}
	}

	private static void RunAcpEvidenceEngine(HlTarget target, List<Dictionary<string, object?>> modules, List<Dictionary<string, object?>> hlFiles, List<Dictionary<string, object?>> findings, HashSet<string> findingKeys, bool nonSteamDistribution = false)
	{
		string text = ReadSteamPath();
		foreach (Dictionary<string, object> module in modules)
		{
			string text2 = Convert.ToString(module.GetValueOrDefault("path")) ?? "";
			string text3 = Convert.ToString(module.GetValueOrDefault("name")) ?? Path.GetFileName(text2);
			string text4 = Convert.ToString(module.GetValueOrDefault("signer")) ?? "";
			object valueOrDefault = module.GetValueOrDefault("signatureValid");
			bool flag = valueOrDefault is bool && (bool)valueOrDefault;
			valueOrDefault = module.GetValueOrDefault("trusted");
			bool flag2 = valueOrDefault is bool && (bool)valueOrDefault;
			if (string.IsNullOrWhiteSpace(text2))
			{
				continue;
			}
			bool flag3 = IsUnderDirectory(text2, target.Root);
			bool flag4 = IsWindowsSystemModule(text2);
			if (!flag4 && IsTrustedSigner(text4) && !flag)
			{
				// A trusted publisher's name on a signature that does not validate. Which way it
				// fails decides what it means - see SignatureStatus.
				string signatureStatus = Convert.ToString(module.GetValueOrDefault("signatureStatus")) ?? "";
				if (signatureStatus == "modified")
				{
					// Genuinely signed, then changed. Every non-Steam edition ships Valve's engine
					// patched like this, so inside an identified non-Steam client's own install it is
					// that whitelisted client, not something to review - no finding; the module's
					// signature status and hash stay in the report's module list. Anywhere else - a
					// Steam install, an unattributed client, a file outside the game folder -
					// nothing explains it, so it is reviewed.
					bool expected = flag3 && nonSteamDistribution;
					if (!expected)
					{
						AddEngineFinding(findings, findingKeys, "acs-signed-module-modified", "Publisher-signed module modified after signing",
							"WARNING", "integrity", "module",
							$"{text3} signed by '{text4}', contents changed — {text2}",
							"This file carries a genuine publisher signature, but its contents were changed after it was signed, and nothing about this install explains the change. A modified engine or client module can carry aim, wallhack or speed patches. Compare its SHA-256 against the known build.",
							target.StartTime);
					}
				}
				else if (signatureStatus == "untrusted")
				{
					AddEngineFinding(findings, findingKeys, "acp-forged-signature", "Forged signer on module in hl.exe", "DETECTED", "injected", "module", $"{text3} claims '{text4}' — {text2}", "High-confidence ACS engine rule: the module presents a certificate in a trusted publisher's name that does not chain to a trusted root, which is how a forged signature presents. A modified genuine file fails differently and is not reported here.", target.StartTime);
				}
				else
				{
					AddEngineFinding(findings, findingKeys, "acs-signature-unverifiable", "Publisher signature could not be validated", "WARNING", "integrity", "module",
						$"{text3} claims '{text4}' ({signatureStatus}) — {text2}",
						"The module names a trusted publisher, but Windows could not validate the signature (expired, revoked, or unreadable). This is not proof of forgery; review the file's hash.",
						target.StartTime);
				}
			}
			else if (flag3 && text3.Equals("opengl32.dll", StringComparison.OrdinalIgnoreCase))
			{
				AddEngineFinding(findings, findingKeys, "acp-local-opengl-hook", "Local OpenGL wrapper loaded into hl.exe", "WARNING", "injected", "module", text2, "A local OpenGL wrapper is loaded. Compatibility renderers can also do this; review its hash and code modifications.", target.StartTime);
			}
			else if (LooksCheatNamed(text3))
			{
				AddEngineFinding(findings, findingKeys, "acp-cheat-named-module", "Suspiciously named module loaded into hl.exe", "WARNING", "injected", "module", text2, "A suspicious filename is not proof of cheat code. Review the computed hash and module integrity evidence.", target.StartTime);
			}
			else if (!flag2)
			{
				bool flag5 = !string.IsNullOrWhiteSpace(text) && IsUnderDirectory(text2, text);
				if (!flag4 && !flag5 && !flag3)
				{
					bool flag6 = string.IsNullOrWhiteSpace(text4);
					AddEngineFinding(findings, findingKeys, "acp-foreign-module", "Foreign module loaded into hl.exe", "WARNING", "injected", "module", flag6 ? (text3 + " — " + text2 + " (unsigned)") : (text3 + " — " + text2), "A DLL mapped into the live game from outside the game, Steam and Windows folders. This is a real injection/loader indicator — review the module source and signer.", target.StartTime);
				}
			}
		}
		foreach (Dictionary<string, object> hlFile in hlFiles)
		{
			string text5 = Convert.ToString(hlFile.GetValueOrDefault("relativePath")) ?? "";
			string subject = Convert.ToString(hlFile.GetValueOrDefault("path")) ?? text5;
			string extension = Path.GetExtension(text5);
			if ((extension.Equals(".dll", StringComparison.OrdinalIgnoreCase) || extension.Equals(".exe", StringComparison.OrdinalIgnoreCase) || extension.Equals(".asi", StringComparison.OrdinalIgnoreCase)) && LooksCheatNamed(text5))
			{
				AddEngineFinding(findings, findingKeys, "acp-cheat-named-game-file", "Cheat-named file in live game folder", "WARNING", "review", "hl-file", subject, "File name is suspicious, but it is not called detected unless loaded into hl.exe or matched by a high-confidence signature.", "");
			}
			if (Path.GetFileName(text5).Contains("muzzIe", StringComparison.Ordinal))
			{
				AddEngineFinding(findings, findingKeys, "acp-fake-sprite", "Look-alike altered sprite in game folder", "WARNING", "review", "hl-file", subject, "Sprite name uses a capital 'I' (muzzIeflash) instead of 'l' — a known no-muzzle-flash / altered-sprite cheat trick.", "");
			}
		}
	}

	private static void AddEngineFinding(List<Dictionary<string, object?>> findings, HashSet<string> findingKeys, string ruleId, string ruleName, string severity, string category, string source, string subject, string reason, string time)
	{
		if (findings.Count < 500)
		{
			string item = $"{ruleId}|{source}|{subject}";
			if (findingKeys.Add(item))
			{
				findings.Add(new Dictionary<string, object>
				{
					["ruleId"] = ruleId,
					["ruleName"] = ruleName,
					["severity"] = severity,
					["confidence"] = ((severity == "DETECTED") ? "high" : "medium"),
					["category"] = category,
					["source"] = source,
					["subject"] = subject,
					["reason"] = reason,
					["time"] = time
				});
			}
		}
	}

	private static void ScanExecutionTraces(JsonElement database, List<Dictionary<string, object?>> findings, HashSet<string> findingKeys, List<string> notes)
	{
		string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
		if (!Directory.Exists(path))
		{
			return;
		}
		try
		{
			foreach (string file in Directory.GetFiles(path, "*.pf").OrderByDescending(File.GetLastWriteTimeUtc).Take(1500))
			{
				string fileName = Path.GetFileName(file);
				MatchRules(database, "execution-trace", fileName, fileName, findings, findingKeys, Safe(() => File.GetLastWriteTimeUtc(file).ToString("O")) ?? "");
			}
		}
		catch (Exception ex)
		{
			notes.Add("Unable to scan launch traces: " + ex.Message);
		}
	}

	private static void ScanCheatArtifacts(List<Dictionary<string, object?>> findings, HashSet<string> findingKeys, List<string> notes)
	{
		(string, string)[] cheatMutexes = CheatMutexes;
		for (int i = 0; i < cheatMutexes.Length; i++)
		{
			var (text, text2) = cheatMutexes[i];
			try
			{
				nint num = OpenMutex(1048576u, bInheritHandle: false, text);
				if (num != IntPtr.Zero)
				{
					CloseHandle(num);
					AddEngineFinding(findings, findingKeys, "acp-cheat-mutex", "Cheat launcher mutex present (" + text2 + ")", "DETECTED", "injected", "process", text, $"High-confidence: the named mutex '{text}' exists, which the {text2} cheat launcher creates while running.", "");
				}
			}
			catch (Exception ex)
			{
				notes.Add("Mutex check failed for " + text + ": " + ex.Message);
			}
		}
		string folderPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
		(string, string)[] cheatConfigFolders = CheatConfigFolders;
		for (int j = 0; j < cheatConfigFolders.Length; j++)
		{
			(string, string) tuple2 = cheatConfigFolders[j];
			string item = tuple2.Item1;
			string item2 = tuple2.Item2;
			string text3 = Path.Combine(folderPath, item);
			if (Directory.Exists(text3))
			{
				AddEngineFinding(findings, findingKeys, "acp-cheat-config-folder", "Cheat config folder present (" + item2 + ")", "WARNING", "installedInOs", "hl-file", text3, "A " + item2 + " configuration folder exists in %APPDATA% — the cheat has been installed or run on this machine.", "");
			}
		}
		(string, string)[] cheatRegistryKeys = CheatRegistryKeys;
		for (int k = 0; k < cheatRegistryKeys.Length; k++)
		{
			var (text4, text5) = cheatRegistryKeys[k];
			try
			{
				using RegistryKey registryKey = Registry.CurrentUser.OpenSubKey(text4);
				if (registryKey != null)
				{
					AddEngineFinding(findings, findingKeys, "acp-cheat-registry", "Cheat registry key present (" + text5 + ")", "WARNING", "installedInOs", "driver", "HKCU\\" + text4, "A " + text5 + " registry key exists — the cheat has been installed or run on this machine.", "");
				}
			}
			catch (Exception ex2)
			{
				notes.Add("Registry check failed for " + text4 + ": " + ex2.Message);
			}
		}
	}

	private static void ScanRunningTools(List<Dictionary<string, object?>> findings, HashSet<string> findingKeys, List<string> notes)
	{
		try
		{
			Process[] processes = Process.GetProcesses();
			foreach (Process process in processes)
			{
				string name = process.ProcessName.Replace(" ", "").ToLowerInvariant();
				string text = SuspiciousTools.FirstOrDefault((string tool) => name.Contains(tool, StringComparison.Ordinal));
				if (text != null)
				{
					AddEngineFinding(findings, findingKeys, "acp-suspicious-tool", "Cheat/debug tool running during scan", "WARNING", "review", "process", $"{process.ProcessName} (PID {Safe(() => process.Id)})", "A known cheat/injection/memory-editing tool is running ('" + text + "'). Review whether it was used against Counter-Strike.", "");
				}
			}
		}
		catch (Exception ex)
		{
			notes.Add("Unable to scan running tools: " + ex.Message);
		}
	}

	private static void ScanRegistryExecutionHistory(JsonElement database, List<Dictionary<string, object?>> findings, HashSet<string> findingKeys, List<string> notes)
	{
		string[] array = new string[2] { "SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings", "SYSTEM\\CurrentControlSet\\Services\\bam\\UserSettings" };
		string[] array2 = array;
		foreach (string name in array2)
		{
			try
			{
				using RegistryKey registryKey = Registry.LocalMachine.OpenSubKey(name);
				if (registryKey == null)
				{
					continue;
				}
				string[] subKeyNames = registryKey.GetSubKeyNames();
				foreach (string name2 in subKeyNames)
				{
					using RegistryKey registryKey2 = registryKey.OpenSubKey(name2);
					string[] array3 = registryKey2?.GetValueNames() ?? Array.Empty<string>();
					foreach (string entry in array3)
					{
						EvaluateExecutionEntry(database, findings, findingKeys, entry, "BAM");
					}
				}
			}
			catch (Exception ex)
			{
				notes.Add("Unable to scan BAM history: " + ex.Message);
			}
		}
		try
		{
			using RegistryKey registryKey3 = Registry.ClassesRoot.OpenSubKey("Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache");
			string[] array4 = registryKey3?.GetValueNames() ?? Array.Empty<string>();
			foreach (string entry2 in array4)
			{
				EvaluateExecutionEntry(database, findings, findingKeys, entry2, "MuiCache");
			}
		}
		catch (Exception ex2)
		{
			notes.Add("Unable to scan MuiCache: " + ex2.Message);
		}
		try
		{
			using RegistryKey registryKey4 = Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store");
			string[] array5 = registryKey4?.GetValueNames() ?? Array.Empty<string>();
			foreach (string entry3 in array5)
			{
				EvaluateExecutionEntry(database, findings, findingKeys, entry3, "AppCompatFlags");
			}
		}
		catch (Exception ex3)
		{
			notes.Add("Unable to scan AppCompatFlags: " + ex3.Message);
		}
		try
		{
			using RegistryKey userAssist = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist");
			if (userAssist != null)
			{
				foreach (string guid in userAssist.GetSubKeyNames())
				{
					using RegistryKey countKey = userAssist.OpenSubKey(guid + @"\Count");
					if (countKey == null) continue;
					foreach (string valName in countKey.GetValueNames())
					{
						string decoded = DecodeRot13(valName);
						EvaluateExecutionEntry(database, findings, findingKeys, decoded, "UserAssist");
					}
				}
			}
		}
		catch (Exception ex4)
		{
			notes.Add("Unable to scan UserAssist: " + ex4.Message);
		}
		try
		{
			string prefetchDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
			if (Directory.Exists(prefetchDir))
			{
				foreach (string pf in Directory.EnumerateFiles(prefetchDir, "*.pf").Take(1500))
				{
					string pfName = Path.GetFileName(pf);
					int hyphen = pfName.LastIndexOf('-');
					string exeName = hyphen > 0 ? pfName.Substring(0, hyphen) : pfName;
					if (!exeName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
					{
						exeName += ".exe";
					}
					EvaluateExecutionEntry(database, findings, findingKeys, exeName, "Prefetch");
				}
			}
		}
		catch (Exception ex5)
		{
			notes.Add("Unable to scan Prefetch: " + ex5.Message);
		}
	}

	private static string DecodeRot13(string input)
	{
		if (string.IsNullOrEmpty(input)) return input;
		char[] buffer = input.ToCharArray();
		for (int i = 0; i < buffer.Length; i++)
		{
			char c = buffer[i];
			if (c >= 'a' && c <= 'z')
			{
				buffer[i] = (char)('a' + (c - 'a' + 13) % 26);
			}
			else if (c >= 'A' && c <= 'Z')
			{
				buffer[i] = (char)('A' + (c - 'A' + 13) % 26);
			}
		}
		return new string(buffer);
	}


	private static void EvaluateExecutionEntry(JsonElement database, List<Dictionary<string, object?>> findings, HashSet<string> findingKeys, string entry, string sourceName)
	{
		if (!string.IsNullOrWhiteSpace(entry) && entry.IndexOf(".exe", StringComparison.OrdinalIgnoreCase) >= 0)
		{
			string fileName = Path.GetFileName(entry.Replace('/', '\\'));
			MatchRules(database, "execution-trace", fileName + " " + entry, fileName, findings, findingKeys);
			if (LooksCheatNamed(fileName))
			{
				AddEngineFinding(findings, findingKeys, "acp-executed-cheat-name", "Cheat-named program executed on this PC", "WARNING", "previouslyLaunched", "execution-trace", $"{fileName} — {entry} [{sourceName}]", sourceName + " shows a cheat-named executable was run on this machine. This record persists even if the file was later deleted — review.", "");
			}
		}
	}

	private static void ScanDownloadedTraces(JsonElement database, List<Dictionary<string, object?>> findings, HashSet<string> findingKeys, List<string> notes)
	{
		foreach (string item in DownloadFolders().Where(Directory.Exists).Distinct<string>(StringComparer.OrdinalIgnoreCase))
		{
			try
			{
				foreach (string file in Directory.GetFiles(item, "*", SearchOption.TopDirectoryOnly).OrderByDescending(File.GetLastWriteTimeUtc).Take(800))
				{
					string fileName = Path.GetFileName(file);
					MatchRules(database, "download-trace", fileName, file, findings, findingKeys, Safe(() => File.GetLastWriteTimeUtc(file).ToString("O")) ?? "");
				}
			}
			catch (Exception ex)
			{
				notes.Add("Unable to scan downloaded traces in " + item + ": " + ex.Message);
			}
		}
	}

	private static void ScanRecycleBin(JsonElement database, List<Dictionary<string, object?>> findings, HashSet<string> findingKeys, List<string> notes)
	{
		try
		{
			foreach (DriveInfo drive in DriveInfo.GetDrives())
			{
				if (drive.DriveType != DriveType.Fixed || !drive.IsReady)
				{
					continue;
				}
				string recycleRoot = Path.Combine(drive.RootDirectory.FullName, "$Recycle.Bin");
				if (!Directory.Exists(recycleRoot))
				{
					continue;
				}
				string[] userDirs;
				try
				{
					userDirs = Directory.GetDirectories(recycleRoot);
				}
				catch
				{
					continue;
				}
				foreach (string userDir in userDirs)
				{
					string[] metaFiles;
					try
					{
						metaFiles = Directory.GetFiles(userDir, "$I*");
					}
					catch
					{
						continue;
					}
					foreach (string metaFile in metaFiles)
					{
						try
						{
							byte[] bytes = File.ReadAllBytes(metaFile);
							if (bytes.Length < 28)
							{
								continue;
							}
							ulong version = BitConverter.ToUInt64(bytes, 0);
							long fileTime = BitConverter.ToInt64(bytes, 16);
							DateTime deletedAt = DateTime.FromFileTimeUtc(fileTime);
							string origPath = "";
							if (version >= 2 && bytes.Length >= 28)
							{
								int charCount = BitConverter.ToInt32(bytes, 24);
								int byteCount = Math.Min(charCount * 2, bytes.Length - 28);
								origPath = Encoding.Unicode.GetString(bytes, 28, byteCount).TrimEnd('\0');
							}
							else if (version == 1 && bytes.Length >= 24)
							{
								origPath = Encoding.Unicode.GetString(bytes, 24, bytes.Length - 24).TrimEnd('\0');
							}
							if (string.IsNullOrWhiteSpace(origPath))
							{
								continue;
							}
							string fileName = Path.GetFileName(origPath);
							string timeStr = deletedAt.ToString("O");
							string surface = $"{fileName} {origPath}";
							MatchRules(database, "download-trace", surface, $"{fileName} — {origPath} (in trash)", findings, findingKeys, timeStr);
							if (LooksCheatNamed(fileName) || fileName.Contains("unknowncheats", StringComparison.OrdinalIgnoreCase) || fileName.Contains("alternative", StringComparison.OrdinalIgnoreCase))
							{
								AddEngineFinding(findings, findingKeys, "acp-trash-cheat-file", "Cheat file in Recycle Bin (" + fileName + ")", "WARNING", "installedInOs", "download-trace", $"{fileName} — {origPath} (in trash)", "A cheat file or cheat download archive was found in the Windows Recycle Bin (deleted " + deletedAt.ToLocalTime().ToString("yyyy-MM-dd HH:mm") + ").", timeStr);
							}
						}
						catch
						{
						}
					}
				}
			}
		}
		catch (Exception ex)
		{
			notes.Add("Unable to scan Recycle Bin: " + ex.Message);
		}
	}

	private static void MatchRules(JsonElement database, string source, string surface, string subject, List<Dictionary<string, object?>> findings, HashSet<string> findingKeys, string time = "", string hashSurface = "")
	{
		_scanToken.ThrowIfCancellationRequested();
		if (findings.Count >= 500)
		{
			return;
		}
		RuleSet ruleSet = _activeRules ?? RuleSet.Build(database);
		List<CompiledRule> list = ruleSet.RulesFor(source);
		if (list.Count == 0)
		{
			return;
		}
		string lowSurface = surface.ToLowerInvariant();
		foreach (CompiledRule item2 in list)
		{
			if (findings.Count >= 500)
			{
				break;
			}
			if (!item2.Enabled)
			{
				continue;
			}
			string item = $"{item2.Id}|{source}|{subject}";
			if (!findingKeys.Contains(item) && RuleConditionsMatch(item2, source, surface, lowSurface, hashSurface, out int matchedHashLength))
			{
				string text = ((item2.Severity == "DETECTED" && !IsStrongEvidence(item2.Severity, item2.Confidence, matchedHashLength)) ? "WARNING" : item2.Severity);
				findingKeys.Add(item);
				string text2;
				if (text == "DETECTED")
				{
					bool flag = ((source == "demo-file" || source == "live-behavior") ? true : false);
					text2 = (flag ? "High-confidence integrated behavior evidence." : "High-confidence live client evidence.");
				}
				else
				{
					bool flag = ((source == "demo-file" || source == "live-behavior") ? true : false);
					text2 = (flag ? "Integrated live behavior review evidence." : "Review evidence only. ACS does not call this a cheat without live module/driver evidence.");
				}
				string value = text2;
				findings.Add(new Dictionary<string, object>
				{
					["ruleId"] = item2.Id,
					["ruleName"] = item2.Name,
					["severity"] = text,
					["confidence"] = item2.Confidence,
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
		bool matched = rule.Valid && RuleConditionsMatch(rule, source, surface, surface.ToLowerInvariant(), hashSurface, out hashLength);
		string severity = matched && rule.Severity == "DETECTED" && !IsStrongEvidence(rule.Severity, rule.Confidence, hashLength)
			? "WARNING" : rule.Severity;
		return (matched, hashLength, severity, rule.Valid);
	}

	private static bool RuleConditionsMatch(CompiledRule rule, string source, string surface, string lowSurface, string hashSurface, out int matchedHashLength)
	{
		matchedHashLength = 0;
		int applicable = 0;
		foreach (MatchCondition condition in rule.Conditions)
		{
			if (!MatchKeyAppliesToSource(condition.Key, source))
			{
				continue;
			}
			applicable++;
			bool flag;
			switch (condition.Key)
			{
			case "sha256":
			case "hash_sha256":
			case "sha1":
			case "hash_sha1":
			case "md5":
			case "hash_md5":
			case "file_md5hash":
			case "file_hash":
				flag = true;
				break;
			default:
				flag = false;
				break;
			}
			if (flag)
			{
				string[] actual = hashSurface.Split(' ', StringSplitOptions.RemoveEmptyEntries);
				if (!HashValueMatches(condition.Values, actual, out int conditionHashLength))
				{
					return false;
				}
				matchedHashLength = Math.Max(matchedHashLength, conditionHashLength);
				continue;
			}
			if (condition.IsRegex)
			{
				bool conditionMatched = false;
				foreach (Regex regex in condition.Regexes)
				{
					try
					{
						if (regex.IsMatch(surface))
						{
							conditionMatched = true;
							break;
						}
					}
					catch (RegexMatchTimeoutException)
					{
					}
				}
				if (!conditionMatched)
				{
					return false;
				}
				continue;
			}
			bool valueMatched = false;
			foreach (string value in condition.Values)
			{
				if (value.Length > 0 && lowSurface.IndexOf(value, StringComparison.Ordinal) >= 0)
				{
					valueMatched = true;
					break;
				}
			}
			if (!valueMatched)
			{
				return false;
			}
		}
		return applicable > 0;
	}

	/// <summary>
	/// Match a rule's hash values against the hashes of the current artifact.
	/// A full digest matches exactly; a truncated digest matches as a prefix. Server-side
	/// cheat databases (ReChecker and its forks) publish 4-byte MD5s, so prefix matching turns
	/// a filename-only signature into real file evidence and removes its false positives.
	/// Values shorter than the 8 hex characters (4 bytes) those databases use are ignored so a
	/// stray short string cannot match by accident.
	/// </summary>
	private static bool HashValueMatches(List<string> values, string[] actual, out int matchedLength)
	{
		matchedLength = 0;
		foreach (string value in values)
		{
			if (value.Length < 8 || value.Length > 64 || !IsHex(value))
			{
				continue;
			}
			foreach (string candidate in actual)
			{
				if (candidate.Length >= value.Length
					&& candidate.AsSpan(0, value.Length).Equals(value.AsSpan(), StringComparison.OrdinalIgnoreCase))
				{
					matchedLength = Math.Max(matchedLength, value.Length);
				}
			}
		}
		return matchedLength > 0;
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

	private static string CategoryForSource(string source, string subject = "")
	{
		if (source == "hl-file")
		{
			if (subject.EndsWith(".mdl", StringComparison.OrdinalIgnoreCase) ||
			    subject.EndsWith(".spr", StringComparison.OrdinalIgnoreCase) ||
			    subject.Contains("models/", StringComparison.OrdinalIgnoreCase) ||
			    subject.Contains("models\\", StringComparison.OrdinalIgnoreCase) ||
			    subject.Contains("sprites/", StringComparison.OrdinalIgnoreCase) ||
			    subject.Contains("sprites\\", StringComparison.OrdinalIgnoreCase))
			{
				return "resources";
			}
			return "loaded";
		}
		if (source == "hl-config")
		{
			return "loaded";
		}
		if (source == "process")
		{
			return "injected";
		}
		return source switch
		{
			"module" => "injected", 
			"memory" => "injected", 
			"process" => "injected",
			"hl-file" => "loaded",
			"live-behavior" => "behavioral", 
			"demo-file" => "behavioral", 
			"execution-trace" => "previouslyLaunched", 
			"driver" => "installedInOs", 
			"download-trace" => "downloaded", 
			"hl-config" => "loaded", 
			"environment" => "review",
			_ => "review", 
		};
	}

	private static Dictionary<string, object?> BuildDetectedCheats(List<Dictionary<string, object?>> findings)
	{
		Dictionary<string, object> dictionary = new Dictionary<string, object>
		{
			["injected"] = new List<Dictionary<string, object>>(),
			["loaded"] = new List<Dictionary<string, object>>(),
			["resources"] = new List<Dictionary<string, object>>(),
			["behavioral"] = new List<Dictionary<string, object>>(),
			["previouslyLaunched"] = new List<Dictionary<string, object>>(),
			["installedInOs"] = new List<Dictionary<string, object>>(),
			["downloaded"] = new List<Dictionary<string, object>>()
		};
		foreach (Dictionary<string, object> item in findings.Where((Dictionary<string, object> f) => SeverityOf(f) == "DETECTED" || SeverityOf(f) == "WARNING"))
		{
			string text = Convert.ToString(item.GetValueOrDefault("category")) ?? "review";
			if (dictionary.TryGetValue(text, out var value) && value is List<Dictionary<string, object>> list)
			{
				list.Add(new Dictionary<string, object>
				{
					["type"] = TypeLabel(text),
					["severity"] = SeverityOf(item),
					["cheat"] = Convert.ToString(item.GetValueOrDefault("ruleName")) ?? "",
					["evidence"] = Convert.ToString(item.GetValueOrDefault("subject")) ?? "",
					["reason"] = Convert.ToString(item.GetValueOrDefault("reason")) ?? Convert.ToString(item.GetValueOrDefault("source")) ?? "",
					["time"] = Convert.ToString(item.GetValueOrDefault("time")) ?? ""
				});
			}
		}
		return dictionary;
	}

	private static List<Dictionary<string, object?>> BuildEngineChecks(HlTarget target, List<Dictionary<string, object?>> modules, List<Dictionary<string, object?>> hlFiles, List<Dictionary<string, object?>> memoryArtifacts, GameWindowInfo windowInfo, string renderMode, DateTimeOffset scanStartedAt)
	{
		HashSet<string> hashSet = (from m in modules
			select Convert.ToString(m.GetValueOrDefault("name")) ?? "" into s
			where s.Length > 0
			select s).ToHashSet<string>(StringComparer.OrdinalIgnoreCase);
		DateTime? dateTime = null;
		try
		{
			dateTime = target.Process.StartTime.ToUniversalTime();
		}
		catch
		{
			dateTime = null;
		}
		TimeSpan timeSpan = ((!dateTime.HasValue) ? TimeSpan.Zero : (scanStartedAt.UtcDateTime - dateTime.Value));
		bool passed = dateTime.HasValue && dateTime.Value <= scanStartedAt.UtcDateTime;
		int num = memoryArtifacts.Count((Dictionary<string, object> m) => string.Equals(Convert.ToString(m.GetValueOrDefault("type")), "MEM_PRIVATE", StringComparison.OrdinalIgnoreCase));
		return new List<Dictionary<string, object>>
		{
			Check("hl.exe running", passed: true, target.Path),
			Check("Game directory resolved from process", Directory.Exists(target.Root), target.Root),
			Check("CS was running before scan", passed, (!dateTime.HasValue) ? "unknown" : $"{Math.Max(0, (int)timeSpan.TotalSeconds)} seconds before scan"),
			Check("Render mode", renderMode != "Unknown", renderMode),
			Check("Game window mode", passed: true, windowInfo.Mode + ": " + windowInfo.Bounds),
			Check("Executable private memory", num == 0, (num == 0) ? "none found" : $"{num} region(s) need review"),
			Check("Single game process", target.TotalGameProcesses == 1, $"{target.TotalGameProcesses} hl.exe process(es)"),
			Check("Game build", passed: true, hashSet.Contains("steamclient.dll") ? "Steam build (steamclient.dll loaded)" : "No-Steam build"),
			Check("hw.dll module loaded", hashSet.Contains("hw.dll"), hashSet.Contains("hw.dll") ? "hw.dll found" : "hw.dll not found"),
			Check("client.dll module loaded", hashSet.Contains("client.dll"), hashSet.Contains("client.dll") ? "client.dll found" : "client.dll not found")
		};
	}

	private static Dictionary<string, object?> Check(string name, bool passed, string detail)
	{
		return new Dictionary<string, object>
		{
			["name"] = name,
			["status"] = (passed ? "OK" : "REVIEW"),
			["detail"] = detail
		};
	}

	private static string TypeLabel(string category)
	{
		return category switch
		{
			"injected" => "Injected into current game", 
			"loaded" => "Installed in game folder",
			"resources" => "Game resources (models/sprites)",
			"behavioral" => "Live behavior evidence", 
			"previouslyLaunched" => "Previously executed", 
			"installedInOs" => "Installed in system", 
			"downloaded" => "Downloaded", 
			"environment" => "Environment / Integrity",
			_ => "Review", 
		};
	}


	private static bool MatchKeyAppliesToSource(string key, string source)
	{
		if (key.StartsWith("output_", StringComparison.OrdinalIgnoreCase))
		{
			return (source == "demo-file" || source == "live-behavior") ? true : false;
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
			case "demo-file":
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
			case "demo-file":
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
			case "demo-file":
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

	private static string? TrySha256(string path)
	{
		FileHashes fileHashes = TryFileHashes(path);
		return string.IsNullOrWhiteSpace(fileHashes.Sha256) ? null : fileHashes.Sha256;
	}

	private static FileHashes TryFileHashes(string path)
	{
		_scanToken.ThrowIfCancellationRequested();
		try
		{
			FileInfo fileInfo = new FileInfo(ModuleIntegrity.NativeFilePath(path));
			if (!fileInfo.Exists || fileInfo.Length <= 0 || fileInfo.Length > 67108864)
			{
				return FileHashes.Empty;
			}
			string key = $"{fileInfo.FullName}|{fileInfo.Length}|{fileInfo.LastWriteTimeUtc.Ticks}";
			if (HashCache.TryGetValue(key, out FileHashes value))
			{
				return value;
			}
			// Hash the file actually opened above (the native path under WOW64), not the
			// original path, which a 32-bit process would silently read from SysWOW64.
			FileHashes fileHashes = HashFileStreaming(fileInfo.FullName);
			SetHashCache(key, fileHashes);
			return fileHashes;
		}
		catch
		{
			return FileHashes.Empty;
		}
	}

	private static uint[] GenerateCrc32Table()
	{
		uint[] array = new uint[256];
		for (uint num = 0u; num < 256; num++)
		{
			uint num2 = num;
			for (int i = 0; i < 8; i++)
			{
				num2 = (((num2 & 1) != 1) ? (num2 >> 1) : ((num2 >> 1) ^ 0xEDB88320u));
			}
			array[num] = num2;
		}
		return array;
	}

	private static FileHashes HashFileStreaming(string path)
	{
		using SHA256 sHA = SHA256.Create();
		using SHA1 sHA2 = SHA1.Create();
		using MD5 mD = MD5.Create();
		using FileStream fileStream = File.OpenRead(path);
		byte[] array = new byte[1048576];
		uint num = uint.MaxValue;
		int num2;
		while ((num2 = fileStream.Read(array, 0, array.Length)) > 0)
		{
			_scanToken.ThrowIfCancellationRequested();
			sHA.TransformBlock(array, 0, num2, null, 0);
			sHA2.TransformBlock(array, 0, num2, null, 0);
			mD.TransformBlock(array, 0, num2, null, 0);
			for (int i = 0; i < num2; i++)
			{
				byte b = (byte)(num ^ array[i]);
				num = (num >> 8) ^ Crc32Table[b];
			}
		}
		sHA.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
		sHA2.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
		mD.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
		num ^= 0xFFFFFFFFu;
		return new FileHashes(CryptoUtils.ToHex(sHA.Hash), CryptoUtils.ToHex(sHA2.Hash), CryptoUtils.ToHex(mD.Hash), num.ToString("x8"));
	}

	private static void SetHashCache(string key, FileHashes hashes)
	{
		lock (HashCacheLock)
		{
			if (HashCache.Count >= 40000)
			{
				List<KeyValuePair<string, FileHashes>> list = HashCache.OrderBy<KeyValuePair<string, FileHashes>, string>((KeyValuePair<string, FileHashes> kvp) => kvp.Key, StringComparer.Ordinal).Take(2000).ToList();
				foreach (KeyValuePair<string, FileHashes> item in list)
				{
					HashCache.TryRemove(item.Key, out FileHashes _);
				}
			}
			HashCache[key] = hashes;
		}
	}

	private static FileHashes HashBytes(byte[] bytes)
	{
		uint num = uint.MaxValue;
		for (int i = 0; i < bytes.Length; i++)
		{
			byte b = (byte)(num ^ bytes[i]);
			num = (num >> 8) ^ Crc32Table[b];
		}
		return new FileHashes(CryptoUtils.Sha256Hex(bytes), CryptoUtils.Sha1Hex(bytes), CryptoUtils.Md5Hex(bytes), (num ^ 0xFFFFFFFFu).ToString("x8"));
	}

	private static IEnumerable<string> ExtractAsciiStrings(byte[] bytes, int minLength, int limit)
	{
		List<string> list = new List<string>();
		StringBuilder stringBuilder = new StringBuilder();
		foreach (byte b in bytes)
		{
			if (b >= 32 && b <= 126)
			{
				stringBuilder.Append((char)b);
				continue;
			}
			FlushAsciiString(stringBuilder, list, minLength, limit);
			if (list.Count >= limit)
			{
				return list;
			}
		}
		FlushAsciiString(stringBuilder, list, minLength, limit);
		return list;
	}

	private static void FlushAsciiString(StringBuilder builder, List<string> results, int minLength, int limit)
	{
		if (builder.Length >= minLength && results.Count < limit)
		{
			string text = builder.ToString();
			if (!results.Contains<string>(text, StringComparer.OrdinalIgnoreCase))
			{
				results.Add(text);
			}
		}
		builder.Clear();
	}

	private static FileMetadata ReadFileMetadata(string path)
	{
		path = ModuleIntegrity.NativeFilePath(path);
		if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
		{
			return FileMetadata.Empty;
		}
		string fileVersion = "";
		string company = "";
		string product = "";
		string signer = "";
		try
		{
			FileVersionInfo versionInfo = FileVersionInfo.GetVersionInfo(path);
			fileVersion = versionInfo.FileVersion ?? "";
			company = versionInfo.CompanyName ?? "";
			product = versionInfo.ProductName ?? "";
		}
		catch
		{
		}
		// The Authenticode signer of a PE file.
		//
		// This used to call X509CertificateLoader.LoadCertificateFromFile, which reads a
		// standalone certificate file (.cer/.pem) - pointed at a signed .exe or .dll it throws
		// "Cannot find the requested object" every time. So the signer was empty for every
		// module and driver ever scanned: verified on a genuine Steam hl.exe, which Windows
		// reports as validly signed by Valve Corp. while the old call threw. The "trusted
		// vendor" branch of IsTrustedModule could therefore never pass, and nothing could tell
		// a Valve-signed engine from a repacked one.
		//
		// CreateFromSignedFile is the call that extracts the embedded signing certificate. It
		// is marked obsolete in favour of the loader API, but the loader has no equivalent for
		// PE signatures. It does NOT verify anything - it only names the certificate - which is
		// why every consumer pairs this name with IsAuthenticodeValid before believing it.
		try
		{
#pragma warning disable SYSLIB0057
			using X509Certificate2 x509Certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
			signer = x509Certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
		}
		catch
		{
			signer = "";   // unsigned, or a signature that does not parse
		}
		return new FileMetadata(fileVersion, company, product, signer);
	}

	private static bool ShouldHashHlFile(string path)
	{
		string extension = Path.GetExtension(path);
		if (extension.Equals(".exe", StringComparison.OrdinalIgnoreCase) || extension.Equals(".dll", StringComparison.OrdinalIgnoreCase) || extension.Equals(".asi", StringComparison.OrdinalIgnoreCase) || extension.Equals(".sys", StringComparison.OrdinalIgnoreCase) || extension.Equals(".cfg", StringComparison.OrdinalIgnoreCase) || extension.Equals(".ini", StringComparison.OrdinalIgnoreCase) || extension.Equals(".bat", StringComparison.OrdinalIgnoreCase) || extension.Equals(".cmd", StringComparison.OrdinalIgnoreCase))
		{
			return true;
		}
		if (extension.Equals(".mdl", StringComparison.OrdinalIgnoreCase) || extension.Equals(".spr", StringComparison.OrdinalIgnoreCase))
		{
			string norm = path.Replace('/', '\\').ToLowerInvariant();
			if (norm.Contains(@"\models\player\") || norm.Contains(@"\sprites\"))
			{
				return true;
			}
		}
		return false;
	}

	private static bool IsHlCriticalAsset(string path)
	{
		string extension = Path.GetExtension(path);
		if (extension.Equals(".mdl", StringComparison.OrdinalIgnoreCase) || extension.Equals(".spr", StringComparison.OrdinalIgnoreCase))
		{
			string norm = path.Replace('/', '\\').ToLowerInvariant();
			return norm.Contains(@"\models\player\") || norm.Contains(@"\sprites\");
		}
		return false;
	}

	private static bool ShouldReadMetadata(string path)
	{
		string extension = Path.GetExtension(path);
		return extension.Equals(".exe", StringComparison.OrdinalIgnoreCase) || extension.Equals(".dll", StringComparison.OrdinalIgnoreCase) || extension.Equals(".asi", StringComparison.OrdinalIgnoreCase) || extension.Equals(".sys", StringComparison.OrdinalIgnoreCase);
	}

	// Extensions that can carry code or steer the engine. A cheat has to live in one of
	// these, so they are never dropped: the file budget now applies only to assets
	// (sprites, models, sounds, maps), which cannot execute.
	//
	// The previous behaviour took the first 2500 files in directory-walk order and stopped.
	// On a real install the scanner logged that it had hit that limit, which means every
	// file past it - including any DLL - went unexamined purely because of where it sorted.
	private static readonly string[] HlCodeExtensions = new string[13]
	{
		".exe", ".dll", ".asi", ".sys", ".so", ".ocx", ".drv", ".cfg", ".rc", ".ini", ".bat", ".cmd", ".vdf"
	};

	private static bool IsHlCodeFile(string path)
	{
		string extension = Path.GetExtension(path);
		for (int i = 0; i < HlCodeExtensions.Length; i++)
		{
			if (extension.Equals(HlCodeExtensions[i], StringComparison.OrdinalIgnoreCase))
			{
				return true;
			}
		}
		return false;
	}

	// Every executable and config, then assets until the budget runs out.
	private static string[] SelectHlCandidates(string root, List<string> notes)
	{
		List<string> code = new List<string>();
		List<string> assets = new List<string>();
		int assetsSeen = 0;

		foreach (string file in EnumerateFilesSafe(root, notes))
		{
			if (IsHlCodeFile(file) || IsHlCriticalAsset(file))
			{
				if (code.Count < MaxHlCodeFiles)
				{
					code.Add(file);
				}
				continue;
			}
			assetsSeen++;
			if (assets.Count < MaxHlFiles)
			{
				assets.Add(file);
			}
		}


		if (code.Count >= MaxHlCodeFiles)
		{
			notes.Add($"Code/config scan reached the {MaxHlCodeFiles}-file ceiling for {root}.");
		}
		if (assetsSeen > assets.Count)
		{
			notes.Add($"Asset scan covered {assets.Count} of {assetsSeen} non-code files for {root}. Every executable and config in this folder was scanned.");
		}

		List<string> selected = new List<string>(code.Count + assets.Count);
		selected.AddRange(code);
		selected.AddRange(assets);
		return selected.ToArray();
	}

	private static IEnumerable<string> EnumerateFilesSafe(string root, List<string> notes)
	{
		Stack<string> pending = new Stack<string>();
		pending.Push(root);
		while (pending.Count > 0)
		{
			string dir = pending.Pop();
			string[] subdirs;
			try
			{
				subdirs = Directory.GetDirectories(dir);
			}
			catch (Exception ex)
			{
				notes.Add("Unable to read folder " + dir + ": " + ex.Message);
				continue;
			}
			string[] files;
			try
			{
				files = Directory.GetFiles(dir);
			}
			catch (Exception ex2)
			{
				notes.Add("Unable to read files in " + dir + ": " + ex2.Message);
				files = Array.Empty<string>();
			}
			string[] array = files;
			for (int i = 0; i < array.Length; i++)
			{
				yield return array[i];
			}
			string[] array2 = subdirs;
			foreach (string subdir in array2)
			{
				pending.Push(subdir);
			}
		}
	}

	private static IEnumerable<string> CommonHlPaths()
	{
		string[] roots = new string[4]
		{
			Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
			Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
			"C:\\Games",
			"D:\\Games"
		};
		foreach (string root in roots.Where((string r) => !string.IsNullOrWhiteSpace(r)))
		{
			yield return Path.Combine(root, "Steam", "steamapps", "common", "Half-Life", "hl.exe");
			yield return Path.Combine(root, "Half-Life", "hl.exe");
			yield return Path.Combine(root, "Counter-Strike 1.6", "hl.exe");
		}
	}

	private static bool IsUnderDirectory(string path, string root)
	{
		try
		{
			string text = Path.GetFullPath(path).TrimEnd(new char[2]
			{
				Path.DirectorySeparatorChar,
				Path.AltDirectorySeparatorChar
			}) + Path.DirectorySeparatorChar;
			string value = Path.GetFullPath(root).TrimEnd(new char[2]
			{
				Path.DirectorySeparatorChar,
				Path.AltDirectorySeparatorChar
			}) + Path.DirectorySeparatorChar;
			return text.StartsWith(value, StringComparison.OrdinalIgnoreCase);
		}
		catch
		{
			return false;
		}
	}

	private static string SafeRelative(string root, string path)
	{
		try
		{
			return PathUtils.GetRelativePath(root, path);
		}
		catch
		{
			return path;
		}
	}

	private static bool LooksCheatNamed(string value)
	{
		string fileNameWithoutExtension = Path.GetFileNameWithoutExtension(value);
		return Regex.IsMatch(fileNameWithoutExtension, "(?i)(^|[^a-z0-9])(aimbot|wallhack|triggerbot|speedhack|esp|oxware|evol|alternative|unknowncheats|r-?aimbot|leis|organner|cdhack|badboy|cheatengine|vehdebug|dbvm|dbk32|dbk64|injector)([^a-z0-9]|$)", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100L));
	}

	private static IEnumerable<string> DownloadFolders()
	{
		string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
		if (!string.IsNullOrWhiteSpace(profile))
		{
			yield return Path.Combine(profile, "Downloads");
			yield return Path.Combine(profile, "Desktop");
		}
	}

	private static string DetectGameBuild(List<Dictionary<string, object?>> modules, string gameRoot, string windowTitle)
	{
		List<string> list = (from m in modules
			select Convert.ToString(m.GetValueOrDefault("name")) ?? "" into s
			where s.Length > 0
			select s).ToList();
		string surface = string.Join(" ", list) + " " + gameRoot + " " + windowTitle;
		if (ContainsAny(surface, "nextclient", "nitro_api", "next_engine", "next_lib", "filesystem_proxy"))
		{
			return "Counter-Strike: 1.6 (NextClient / Non-Steam)";
		}
		if (ContainsAny(surface, "gsclient"))
		{
			return "Counter-Strike: 1.6 (GSClient / Non-Steam)";
		}
		if (ContainsAny(surface, "goldclient", "goldsrc.dll"))
		{
			return "Counter-Strike: 1.6 (GoldClient / Non-Steam)";
		}
		if (ContainsAny(surface, "revemu", "rev_emu", "revloader", "revcrew", "rev.ini"))
		{
			return "Counter-Strike: 1.6 (RevEmu / RevCrew / Non-Steam)";
		}
		if (ContainsAny(surface, "smartsteamemu", "sselauncher", "smartsteamloader", "sse.ini"))
		{
			return "Counter-Strike: 1.6 (SmartSteamEmu / Non-Steam)";
		}
		if (ContainsAny(surface, "goldberg", "steam_settings", "libsteam_api"))
		{
			return "Counter-Strike: 1.6 (Goldberg emulator / Non-Steam)";
		}
		if (ContainsAny(surface, "cream_api", "creamapi"))
		{
			return "Counter-Strike: 1.6 (CreamAPI / Non-Steam)";
		}
		if (ContainsAny(surface, "greenluma", "dllinjector"))
		{
			return "Counter-Strike: 1.6 (GreenLuma / Non-Steam)";
		}
		if (ContainsAny(surface, "platinum.ini", "platinum_emu", "platinumemu"))
		{
			return "Counter-Strike: 1.6 (Platinum emulator / Non-Steam)";
		}
		if (ContainsAny(surface, "crackedsteam"))
		{
			return "Counter-Strike: 1.6 (CrackedSteam / Non-Steam)";
		}
		if (ContainsAny(surface, "steamless", "steam_emu", "steamemu"))
		{
			return "Counter-Strike: 1.6 (Steam emulator / Non-Steam)";
		}
		if (ContainsAny(surface, "multiemulator", "multiemu", "avsmp", "avs.dll"))
		{
			return "Counter-Strike: 1.6 (MultiEmulator / Non-Steam)";
		}
		if (ContainsAny(surface, "reunion_mm", "dproto", "dproto_mm", "reapi_amxx", "amxmodx_mm", "regamedll", "swds.dll"))
		{
			return "Counter-Strike: 1.6 (ReHLDS / DProto server platform)";
		}
		return (list.Any((string n) => string.Equals(n, "steamclient.dll", StringComparison.OrdinalIgnoreCase)) || !string.IsNullOrWhiteSpace(ReadSteamPath())) ? "Counter-Strike: 1.6 (Steam)" : "Counter-Strike: 1.6 (No Steam)";
	}

	private static bool ContainsAny(string surface, params string[] needles)
	{
		return needles.Any((string n) => surface.Contains(n, StringComparison.OrdinalIgnoreCase));
	}

	/// <summary>
	/// The server the game is joined to right now, from its live UDP traffic (see GameTraffic),
	/// plus the engine's live version string. Replaces a search of game memory for any
	/// "ip:port" text, which found server-browser entries and servers left long ago.
	/// </summary>
	private static ConnectedServer DetectConnectedServer(HlTarget target, List<string> notes, CancellationToken cancellationToken)
	{
		string gameDirectory = "";
		try
		{
			foreach (ProcessModule module in target.Process.Modules)
			{
				if (string.Equals(module.ModuleName, "client.dll", StringComparison.OrdinalIgnoreCase))
				{
					gameDirectory = EngineIdentity.GameDirectoryOf(module.FileName ?? "", target.Root);
					if (gameDirectory != "")
					{
						break;
					}
				}
			}
		}
		catch
		{
			// the version string is then simply not located; the connection read does not need it
		}

		var (patchVersion, _, _) = EngineIdentity.ReadVersionFile(target.Root, gameDirectory);
		string liveVersion = LiveEngineState.ReadVersion(target.Process, patchVersion);

		GameTraffic.Result traffic = GameTraffic.Capture(target.Process.Id, cancellationToken);
		if (traffic.Status != "connected")
		{
			if (traffic.Status == "unverified")
			{
				notes.Add("Server connection could not be verified: " + traffic.Reason);
			}
			return new ConnectedServer(traffic.Status, "", "", "", "", traffic, liveVersion);
		}

		ValveA2S.ServerInfo a2s = traffic.A2S ?? ValveA2S.Query(traffic.Endpoint);
		string name = a2s.Success ? a2s.Name : "";
		string map = a2s.Success ? a2s.Map : "";
		string nameSource = a2s.Success ? "server reply (A2S_INFO)" : "the server did not answer the info query";
		if (!a2s.Success && !string.IsNullOrEmpty(a2s.Error))
		{
			notes.Add($"A2S query note for {traffic.Endpoint}: {a2s.Error}");
		}
		return new ConnectedServer("connected", traffic.Endpoint, name, map, nameSource, traffic, liveVersion, a2s);
	}

	/// <summary>The one-line server description shown in the app's evidence log.</summary>
	private static string DescribeServer(ConnectedServer server)
	{
		if (server.Status == "connected")
		{
			var desc = $"Joined {Or(server.Name, "(name not reported)")} — {server.Address}";
			if (!string.IsNullOrWhiteSpace(server.Map)) desc += $" — {server.Map}";
			if (server.A2S is { Success: true } a2s)
			{
				desc += $" ({a2s.Players}/{a2s.MaxPlayers} players";
				if (!string.IsNullOrWhiteSpace(a2s.Environment) && a2s.Environment != "Unknown") desc += $", {a2s.Environment}";
				if (a2s.VacSecured) desc += ", VAC";
				desc += ")";
			}
			return desc;
		}
		if (server.Status == "not-connected") return "No Server Detected";
		return "Game connection not verified: " + server.Traffic.Reason;
	}

	private static string Or(string value, string fallback)
	{
		return string.IsNullOrWhiteSpace(value) ? fallback : value;
	}

	private static string DetectRenderMode(List<Dictionary<string, object?>> modules)
	{
		HashSet<string> hashSet = (from m in modules
			select Convert.ToString(m.GetValueOrDefault("name")) ?? "" into s
			where s.Length > 0
			select s).ToHashSet<string>(StringComparer.OrdinalIgnoreCase);
		if (hashSet.Contains("opengl32.dll"))
		{
			return "OpenGL";
		}
		if (hashSet.Contains("d3d9.dll") || hashSet.Contains("d3dim.dll") || hashSet.Contains("ddraw.dll"))
		{
			return "Direct3D";
		}
		if (hashSet.Contains("sw.dll"))
		{
			return "Software";
		}
		return "Unknown";
	}

	private static GameWindowInfo ReadGameWindowInfo(Process process)
	{
		try
		{
			nint mainWindowHandle = process.MainWindowHandle;
			if (mainWindowHandle == IntPtr.Zero)
			{
				return new GameWindowInfo("", "Unknown", IsFullscreen: false, "");
			}
			StringBuilder stringBuilder = new StringBuilder(256);
			GetWindowText(mainWindowHandle, stringBuilder, stringBuilder.Capacity);
			if (!GetWindowRect(mainWindowHandle, out var lpRect))
			{
				return new GameWindowInfo(stringBuilder.ToString(), "Unknown", IsFullscreen: false, "");
			}
			Rectangle rectangle = new Rectangle(lpRect.Left, lpRect.Top, lpRect.Right - lpRect.Left, lpRect.Bottom - lpRect.Top);
			Rectangle bounds = Screen.FromHandle(mainWindowHandle).Bounds;
			bool flag = rectangle.Width >= bounds.Width - 8 && rectangle.Height >= bounds.Height - 8 && rectangle.Left <= bounds.Left + 8 && rectangle.Top <= bounds.Top + 8;
			return new GameWindowInfo(stringBuilder.ToString(), flag ? "Fullscreen" : "Windowed", flag, $"{rectangle.X},{rectangle.Y} {rectangle.Width}x{rectangle.Height}");
		}
		catch
		{
			return new GameWindowInfo("", "Unknown", IsFullscreen: false, "");
		}
	}

	private static bool IsTrustedGoldSrcModule(string moduleName)
	{
		return TrustedGoldSrcModules.Contains(moduleName);
	}

	private static bool IsWindowsSystemModule(string path)
	{
		return !string.IsNullOrWhiteSpace(WindowsDirectory) && !string.IsNullOrWhiteSpace(path) && IsUnderDirectory(path, WindowsDirectory);
	}

	private static bool IsTrustedSigner(string? signer)
	{
		if (string.IsNullOrWhiteSpace(signer))
		{
			return false;
		}
		string[] trustedSigners = TrustedSigners;
		foreach (string value in trustedSigners)
		{
			if (signer.Contains(value, StringComparison.OrdinalIgnoreCase))
			{
				return true;
			}
		}
		return false;
	}

	/// <summary>
	/// Whether a loaded module can be taken at face value.
	///
	/// Trust is not cosmetic: a trusted module is matched against the signature database by
	/// hash alone, while an untrusted one is matched across its name, path, company, product
	/// and signer as well. So anything that gets trust wrongly also gets a much smaller
	/// surface to be caught on.
	///
	/// The GoldSrc whitelist used to grant that on the module NAME alone, which is the one
	/// thing an attacker picks. A cheat DLL called client.dll - injected from anywhere on the
	/// disk - was trusted, and only an exact hash match could then catch it. The name now
	/// only counts for a file that is actually part of the game install, which is where the
	/// real engine modules live and where an injected one generally is not.
	/// </summary>
	private static bool IsTrustedModule(string name, string path, string? signer, bool signatureValid)
	{
		return (IsTrustedGoldSrcModule(name) && IsInsideGameInstall(path))
			|| IsWindowsSystemModule(path)
			|| (IsTrustedSigner(signer) && signatureValid);
	}

	/// <summary>
	/// The install directory of the game being scanned, published for the module trust check.
	/// Set once the target is resolved; empty outside a scan, which makes the name whitelist
	/// grant nothing rather than everything.
	/// </summary>
	private static string _gameInstallRoot = "";

	private static bool IsInsideGameInstall(string path)
	{
		return !string.IsNullOrWhiteSpace(_gameInstallRoot)
			&& !string.IsNullOrWhiteSpace(path)
			&& IsUnderDirectory(path, _gameInstallRoot);
	}

	private static string? ReadPlayerName(string root)
	{
		string text = FindConfigPath(root);
		if (text == null)
		{
			return null;
		}
		try
		{
			foreach (string item in File.ReadLines(text).Take(500))
			{
				Match match = Regex.Match(item, "^\\s*name\\s+\"(?<name>[^\"]+)\"", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
				if (match.Success)
				{
					return match.Groups["name"].Value.Trim();
				}
			}
		}
		catch
		{
			return null;
		}
		return null;
	}

	private static string? FindConfigPath(string root)
	{
		string[] source = new string[4]
		{
			Path.Combine(root, "cstrike", "config.cfg"),
			Path.Combine(root, "cstrike", "cfg", "config.cfg"),
			Path.Combine(root, "valve", "config.cfg"),
			Path.Combine(root, "valve", "cfg", "config.cfg")
		};
		return source.FirstOrDefault(File.Exists);
	}

	private static string? ReadSteamPath()
	{
		try
		{
			using RegistryKey registryKey = Registry.CurrentUser.OpenSubKey("Software\\Valve\\Steam");
			string text = Convert.ToString(registryKey?.GetValue("SteamPath") ?? "");
			if (!string.IsNullOrWhiteSpace(text))
			{
				return text.Replace('/', Path.DirectorySeparatorChar);
			}
			string text2 = Convert.ToString(registryKey?.GetValue("SteamExe") ?? "");
			if (!string.IsNullOrWhiteSpace(text2))
			{
				return Path.GetDirectoryName(text2.Replace('/', Path.DirectorySeparatorChar));
			}
		}
		catch
		{
		}
		return null;
	}

	private static SteamIdentity ReadSteamId()
	{
		List<SteamIdentityCandidate> source = ReadSteamIdentityCandidates();
		SteamIdentityCandidate steamIdentityCandidate = source.FirstOrDefault((SteamIdentityCandidate c) => c.IsPrimary) ?? source.FirstOrDefault();
		if ((object)steamIdentityCandidate == null)
		{
			return SteamIdentity.Empty;
		}
		return new SteamIdentity(steamIdentityCandidate.SteamId64, steamIdentityCandidate.AccountId, steamIdentityCandidate.Steam2, steamIdentityCandidate.Steam3, steamIdentityCandidate.Source, source.Select((SteamIdentityCandidate c) => c.ToDictionary()).ToList());
	}

	private static List<SteamIdentityCandidate> ReadSteamIdentityCandidates()
	{
		List<SteamIdentityCandidate> list = new List<SteamIdentityCandidate>();
		AddSteamCandidate(list, ReadActiveSteamAccountId(), "HKCU Steam ActiveProcess ActiveUser", primary: true);
		string text = ReadSteamPath();
		if (!string.IsNullOrWhiteSpace(text))
		{
			foreach (ulong item in ReadLoginUsers(text))
			{
				AddSteamCandidate(list, item, "Steam loginusers.vdf", primary: false);
			}
			foreach (ulong item2 in ReadUserDataAccounts(text))
			{
				AddSteamCandidate(list, item2, "Steam userdata folder", primary: false);
			}
		}
		return (from g in list.GroupBy<SteamIdentityCandidate, string>((SteamIdentityCandidate c) => c.AccountId, StringComparer.OrdinalIgnoreCase)
			select g.OrderByDescending((SteamIdentityCandidate c) => c.IsPrimary).First() into c
			orderby c.IsPrimary descending
			select c).ThenBy<SteamIdentityCandidate, string>((SteamIdentityCandidate c) => c.Source, StringComparer.OrdinalIgnoreCase).ToList();
	}

	private static ulong? ReadActiveSteamAccountId()
	{
		try
		{
			using RegistryKey registryKey = Registry.CurrentUser.OpenSubKey("Software\\Valve\\Steam\\ActiveProcess");
			object obj = registryKey?.GetValue("ActiveUser");
			if (obj == null)
			{
				return null;
			}
			ulong num = Convert.ToUInt64(obj);
			if (num == 0)
			{
				return null;
			}
			return num;
		}
		catch
		{
			return null;
		}
	}

	private static IEnumerable<ulong> ReadLoginUsers(string steamRoot)
	{
		string path = Path.Combine(steamRoot, "config", "loginusers.vdf");
		if (!File.Exists(path))
		{
			yield break;
		}
		string text;
		try
		{
			text = File.ReadAllText(path);
		}
		catch
		{
			yield break;
		}
		foreach (Match match in Regex.Matches(text, "\"(?<id>7656119\\d{10})\"\\s*\\{", RegexOptions.CultureInvariant))
		{
			if (ulong.TryParse(match.Groups["id"].Value, out var steamId64) && steamId64 >= 76561197960265728L)
			{
				yield return steamId64 - 76561197960265728L;
			}
		}
	}

	private static IEnumerable<ulong> ReadUserDataAccounts(string steamRoot)
	{
		string path = Path.Combine(steamRoot, "userdata");
		if (!Directory.Exists(path))
		{
			yield break;
		}
		IEnumerable<string> dirs;
		try
		{
			dirs = Directory.EnumerateDirectories(path).Take(32).ToArray();
		}
		catch
		{
			yield break;
		}
		foreach (string dir in dirs)
		{
			string name = Path.GetFileName(dir);
			if (ulong.TryParse(name, out var accountId) && accountId != 0)
			{
				yield return accountId;
			}
		}
	}

	private static void AddSteamCandidate(List<SteamIdentityCandidate> candidates, ulong? accountId, string source, bool primary)
	{
		if (accountId.HasValue && accountId.Value != 0)
		{
			candidates.Add(SteamIdentityCandidate.FromAccountId(accountId.Value, source, primary));
		}
	}

	private static VolumeIdentity ReadVolumeSerial(string root)
	{
		try
		{
			string pathRoot = Path.GetPathRoot(Path.GetFullPath(root));
			if (string.IsNullOrWhiteSpace(pathRoot))
			{
				pathRoot = Path.GetPathRoot(Environment.SystemDirectory);
			}
			if (string.IsNullOrWhiteSpace(pathRoot))
			{
				return new VolumeIdentity("", "");
			}
			if (!GetVolumeInformation(pathRoot, null, 0, out var lpVolumeSerialNumber, out var _, out var _, null, 0))
			{
				return new VolumeIdentity(pathRoot, "");
			}
			return new VolumeIdentity(pathRoot, lpVolumeSerialNumber.ToString("X8"));
		}
		catch
		{
			return new VolumeIdentity("", "");
		}
	}

	private static string StableDeviceFingerprint(string steamId, string hddSerial)
	{
		string s = $"{steamId}|{hddSerial}|{Environment.MachineName}";
		return CryptoUtils.Sha256Hex(Encoding.UTF8.GetBytes(s)).Substring(0, 16);
	}

	private static string StablePlayerId()
	{
		string s = $"{Environment.UserName}|{Environment.MachineName}|{Environment.OSVersion.VersionString}";
		return CryptoUtils.Sha256Hex(Encoding.UTF8.GetBytes(s)).Substring(0, 12);
	}

	private static string NormalizeDriverPath(string path)
	{
		if (string.IsNullOrWhiteSpace(path))
		{
			return "";
		}
		string name = path.Trim().Trim('"');
		name = Environment.ExpandEnvironmentVariables(name);
		name = name.Replace("\\\\??\\\\", "", StringComparison.Ordinal);
		name = name.Replace("\\??\\", "", StringComparison.Ordinal);
		name = name.Replace("System32\\", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32") + "\\", StringComparison.OrdinalIgnoreCase);
		name = name.Replace("\\SystemRoot\\", Environment.GetFolderPath(Environment.SpecialFolder.Windows) + "\\", StringComparison.OrdinalIgnoreCase);
		if (name.StartsWith("\\", StringComparison.Ordinal) && !name.StartsWith("\\\\", StringComparison.Ordinal))
		{
			name = Environment.GetFolderPath(Environment.SpecialFolder.System).Substring(0, 2) + name;
		}
		return name;
	}

	private static int ToInt(object? value)
	{
		try
		{
			return Convert.ToInt32(value);
		}
		catch
		{
			return 0;
		}
	}

	private static T? Safe<T>(Func<T> read)
	{
		try
		{
			return read();
		}
		catch
		{
			return default(T);
		}
	}

	private static Dictionary<string, object?> ReadCounts(JsonElement database)
	{
		Dictionary<string, object> dictionary = new Dictionary<string, object>();
		if (database.TryGetProperty("counts", out var value) && value.ValueKind == JsonValueKind.Object)
		{
			foreach (JsonProperty item in value.EnumerateObject())
			{
				dictionary[item.Name] = ((item.Value.ValueKind == JsonValueKind.Number && item.Value.TryGetInt32(out var value2)) ? ((object)value2) : item.Value.ToString());
			}
		}
		return dictionary;
	}

	private static string ReadString(JsonElement element, string property, string fallback)
	{
		JsonElement value;
		return (element.TryGetProperty(property, out value) && value.ValueKind == JsonValueKind.String) ? (value.GetString() ?? fallback) : fallback;
	}

	private static string SeverityOf(Dictionary<string, object?> finding)
	{
		return Convert.ToString(finding.GetValueOrDefault("severity"))?.ToUpperInvariant() ?? "INFO";
	}

	private static bool IsExecutableProtection(uint protect)
	{
		switch (protect & 0xFFFFFEFFu)
		{
		case 16u:
		case 32u:
		case 64u:
		case 128u:
			return true;
		default:
			return false;
		}
	}

	private static string ProtectionName(uint protect)
	{
		uint num = protect & 0xFFFFFEFFu;
		if (1 == 0)
		{
		}
		string text = num switch
		{
			16u => "PAGE_EXECUTE", 
			32u => "PAGE_EXECUTE_READ", 
			64u => "PAGE_EXECUTE_READWRITE", 
			128u => "PAGE_EXECUTE_WRITECOPY", 
			1u => "PAGE_NOACCESS", 
			_ => $"0x{protect:X}", 
		};
		if (1 == 0)
		{
		}
		string text2 = text;
		return ((protect & 0x100) != 0) ? (text2 + "|PAGE_GUARD") : text2;
	}

	private static string MemoryTypeName(uint type)
	{
		if (1 == 0)
		{
		}
		string result = type switch
		{
			16777216u => "MEM_IMAGE", 
			262144u => "MEM_MAPPED", 
			131072u => "MEM_PRIVATE", 
			_ => $"0x{type:X}", 
		};
		if (1 == 0)
		{
		}
		return result;
	}

	private static long ToLong(object? value)
	{
		try
		{
			return Convert.ToInt64(value);
		}
		catch
		{
			return 0L;
		}
	}

	private static bool KeyDown(int virtualKey)
	{
		return (GetAsyncKeyState(virtualKey) & 0x8000) != 0;
	}

	private static int ForegroundProcessId()
	{
		nint foregroundWindow = GetForegroundWindow();
		if (foregroundWindow == IntPtr.Zero)
		{
			return 0;
		}
		GetWindowThreadProcessId(foregroundWindow, out var lpdwProcessId);
		return (int)lpdwProcessId;
	}

	private static string BuildUrl(string apiUrl, string action)
	{
		char value = (apiUrl.Contains('?') ? '&' : '?');
		return $"{apiUrl}{value}action={Uri.EscapeDataString(action)}";
	}

	private static string? MakeAbsoluteReportUrl(string apiUrl, string? relativeUrl)
	{
		if (string.IsNullOrWhiteSpace(relativeUrl))
		{
			return null;
		}
		if (Uri.TryCreate(relativeUrl, UriKind.Absolute, out Uri result))
		{
			return result.ToString();
		}
		Uri baseUri = new Uri(apiUrl);
		return new Uri(baseUri, relativeUrl).ToString();
	}

	private static JsonSerializerOptions JsonOptions()
	{
		return new JsonSerializerOptions
		{
			WriteIndented = true
		};
	}

	[DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
	private static extern bool GetVolumeInformation(string lpRootPathName, StringBuilder? lpVolumeNameBuffer, int nVolumeNameSize, out uint lpVolumeSerialNumber, out uint lpMaximumComponentLength, out uint lpFileSystemFlags, StringBuilder? lpFileSystemNameBuffer, int nFileSystemNameSize);

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern nint OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern bool CloseHandle(nint hObject);

	[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
	private static extern nint OpenMutex(uint dwDesiredAccess, bool bInheritHandle, string lpName);

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern nuint VirtualQueryEx(nint hProcess, nint lpAddress, out MemoryBasicInformation lpBuffer, nuint dwLength);

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern bool ReadProcessMemory(nint hProcess, nint lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

	[DllImport("user32.dll", SetLastError = true)]
	private static extern bool GetWindowRect(nint hWnd, out NativeRect lpRect);

	[DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
	private static extern int GetWindowText(nint hWnd, StringBuilder lpString, int nMaxCount);

	[DllImport("user32.dll")]
	private static extern short GetAsyncKeyState(int vKey);

	[DllImport("user32.dll")]
	private static extern bool GetCursorPos(out NativePoint lpPoint);

	[DllImport("user32.dll")]
	private static extern nint GetForegroundWindow();

	[DllImport("user32.dll")]
	private static extern uint GetWindowThreadProcessId(nint hWnd, out uint lpdwProcessId);

	[DllImport("user32.dll")]
	private static extern bool SetForegroundWindow(nint hWnd);

	/// <summary>
	/// The version from the project file - one source, instead of a string literal in the
	/// report that had to be edited by hand and was not.
	/// </summary>
	private static readonly string ScannerVersion =
		(typeof(ScannerEngine).Assembly
			.GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false)
			.OfType<System.Reflection.AssemblyInformationalVersionAttribute>()
			.FirstOrDefault()?.InformationalVersion ?? "0.0.0")
		.Split('+')[0];

	/// <summary>
	/// Fingerprint of the exact executable that ran the scan: the first 12 hex digits of its
	/// SHA-256.
	///
	/// A version number names a release, not a binary. Two different builds of this app both
	/// reported "1.0.0" and scanned the same client to different verdicts, and nothing in
	/// either report could tell them apart. The fingerprint can: identical builds always
	/// match, and any rebuild changes it.
	/// </summary>
	private static readonly Lazy<string> ScannerBuild = new(() =>
	{
		try
		{
			string? exe = Process.GetCurrentProcess().MainModule?.FileName;
			if (string.IsNullOrWhiteSpace(exe) || !File.Exists(exe))
			{
				return "unknown";
			}
			using FileStream stream = File.OpenRead(exe);
			return CryptoUtils.Sha256Hex(stream).Substring(0, 12);
		}
		catch
		{
			return "unknown";
		}
	});

	private static bool IsAuthenticodeValid(string path)
	{
		return AuthenticodeResult(path) == 0;
	}

	/// <summary>
	/// Why a file's signature does or does not validate, as one word.
	///
	/// "Not valid" used to be a single answer, and it was treated as forgery. But the two
	/// common failures mean opposite things. A certificate that claims a publisher and does
	/// not chain to a trusted root is a forgery - someone made a certificate that says Valve.
	/// A certificate that does chain, over contents that no longer match it, is a real
	/// signed file that was modified afterwards. The ESK client's hw.dll is the second kind
	/// (Windows: HashMismatch, signed "CN=Valve" in 2009): Valve's own engine, patched the
	/// way every non-Steam edition patches it. Calling that a forged signature put a
	/// DETECTED on a player for running an ordinary non-Steam client.
	/// </summary>
	private static string SignatureStatus(uint result)
	{
		return result switch
		{
			0u => "valid",
			0x800B0100u => "not-signed",   // TRUST_E_NOSIGNATURE
			0x80096010u => "modified",     // TRUST_E_BAD_DIGEST - signed, then changed
			0x800B0109u or                  // CERT_E_UNTRUSTEDROOT
			0x800B010Au or                  // CERT_E_CHAINING
			0x800B010Du or                  // CERT_E_UNTRUSTEDTESTROOT
			0x800B0111u or                  // TRUST_E_EXPLICIT_DISTRUST
			0x80096004u => "untrusted",    // TRUST_E_CERT_SIGNATURE - the certificate itself is not genuine
			0x800B0101u => "expired",      // CERT_E_EXPIRED
			0x800B010Cu => "revoked",      // CERT_E_REVOKED
			_ => "unverifiable"
		};
	}

	/// <summary>The raw WinVerifyTrust result for a file: 0 when the signature is valid.</summary>
	private static uint AuthenticodeResult(string path)
	{
		path = ModuleIntegrity.NativeFilePath(path);
		if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
		{
			return 0x800B0100u;
		}
		Guid pgActionID = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
		WintrustFileInfo structure = new WintrustFileInfo
		{
			cbStruct = (uint)Marshal.SizeOf<WintrustFileInfo>(),
			pcwszFilePath = path,
			hFile = IntPtr.Zero,
			pgKnownSubject = IntPtr.Zero
		};
		nint num = Marshal.AllocHGlobal(Marshal.SizeOf<WintrustFileInfo>());
		nint num2 = Marshal.AllocHGlobal(Marshal.SizeOf<WintrustData>());
		try
		{
			Marshal.StructureToPtr(structure, num, fDeleteOld: false);
			WintrustData structure2 = new WintrustData
			{
				cbStruct = (uint)Marshal.SizeOf<WintrustData>(),
				dwUIChoice = 2u,
				fdwRevocationChecks = 0u,
				dwUnionChoice = 1u,
				pFile = num,
				dwStateAction = 1u,
				dwProvFlags = 4096u
			};
			Marshal.StructureToPtr(structure2, num2, fDeleteOld: false);
			uint num3 = WinVerifyTrust(IntPtr.Zero, pgActionID, num2);
			WintrustData structure3 = Marshal.PtrToStructure<WintrustData>(num2);
			structure3.dwStateAction = 2u;
			Marshal.StructureToPtr(structure3, num2, fDeleteOld: false);
			WinVerifyTrust(IntPtr.Zero, pgActionID, num2);
			return num3;
		}
		catch
		{
			return 0xFFFFFFFFu;   // could not be checked at all; reported as unverifiable
		}
		finally
		{
			Marshal.FreeHGlobal(num2);
			Marshal.FreeHGlobal(num);
		}
	}

	[DllImport("wintrust.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
	private static extern uint WinVerifyTrust(nint hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, nint pWVTData);
}
