using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace ACPScanner;

/// <summary>
/// Continuous server connection monitor that runs throughout the entire scan.
/// Collects timestamped proof points to detect disconnection/reconnection cheats.
/// 
/// Anti-cheat design:
/// - Samples connection state at multiple points during scan (start, middle, end)
/// - Each sample includes UDP port state, memory evidence, and A2S response
/// - Cryptographic hash chain links all samples together
/// - Server-side verification can independently confirm the player was connected
/// </summary>
public sealed class ServerConnectionMonitor : IDisposable
{
    /// <summary>A single timestamped proof point of connection state.</summary>
    public sealed record ProofPoint(
        int SequenceNumber,
        DateTimeOffset Timestamp,
        string Status,              // "connected" | "not-connected" | "unverified"
        string Endpoint,            // "ip:port" when connected
        string ServerName,          // from A2S when available
        string ServerMap,           // from A2S when available
        int PlayersOnServer,        // from A2S when available
        IReadOnlyList<int> LocalUdpPorts,
        string MemoryEvidenceHash,  // SHA256 of memory evidence found
        string A2SResponseHash,     // SHA256 of raw A2S response (when available)
        string Reason);

    /// <summary>Complete evidence chain for the scan session.</summary>
    public sealed record EvidenceChain(
        string SessionId,           // Unique scan session identifier
        DateTimeOffset ScanStarted,
        DateTimeOffset ScanFinished,
        IReadOnlyList<ProofPoint> ProofPoints,
        string ChainHash,           // SHA256 of all proof points concatenated
        string FinalStatus,         // "connected" | "not-connected" | "disconnected-during-scan" | "unverified"
        string FinalEndpoint,
        string FinalServerName,
        string FinalServerMap,
        bool ConsistentConnection,  // True if same server throughout scan
        int DisconnectionEvents);   // Number of times connection was lost

    private readonly int _processId;
    private readonly CancellationToken _cancellationToken;
    private readonly List<ProofPoint> _proofPoints = new();
    private readonly string _sessionId;
    private readonly object _lock = new();
    private System.Threading.Timer? _monitorTimer;
    private bool _disposed;
    private int _sequenceNumber;
    private string? _initialEndpoint;
    private int _disconnectionEvents;

    public ServerConnectionMonitor(int processId, CancellationToken cancellationToken)
    {
        _processId = processId;
        _cancellationToken = cancellationToken;
        _sessionId = GenerateSessionId();
    }

    /// <summary>Generate a unique session ID for this scan.</summary>
    private static string GenerateSessionId()
    {
        var bytes = new byte[16];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);
        return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
    }

    /// <summary>Start continuous monitoring. Call at scan start.</summary>
    public void StartMonitoring()
    {
        // Take initial proof point immediately
        TakeProofPoint("scan-start");

        // Then sample every 2 seconds during scan
        _monitorTimer = new System.Threading.Timer(_ => TakeProofPoint("periodic"), null,
            TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(2));
    }

    /// <summary>Stop monitoring and finalize the evidence chain.</summary>
    public EvidenceChain StopAndFinalize()
    {
        _monitorTimer?.Dispose();
        _monitorTimer = null;

        // Take final proof point
        TakeProofPoint("scan-end");

        lock (_lock)
        {
            var scanStarted = _proofPoints.Count > 0 ? _proofPoints[0].Timestamp : DateTimeOffset.UtcNow;
            var scanFinished = DateTimeOffset.UtcNow;

            // Determine final status
            var finalStatus = DetermineFinalStatus();
            var lastConnected = _proofPoints.LastOrDefault(p => p.Status == "connected");

            // Check consistency
            var endpoints = _proofPoints
                .Where(p => p.Status == "connected" && !string.IsNullOrEmpty(p.Endpoint))
                .Select(p => p.Endpoint)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            var consistentConnection = endpoints.Count <= 1 && _disconnectionEvents == 0;

            // Build chain hash
            var chainHash = ComputeChainHash(_proofPoints);

            return new EvidenceChain(
                SessionId: _sessionId,
                ScanStarted: scanStarted,
                ScanFinished: scanFinished,
                ProofPoints: _proofPoints.ToList(),
                ChainHash: chainHash,
                FinalStatus: finalStatus,
                FinalEndpoint: lastConnected?.Endpoint ?? "",
                FinalServerName: lastConnected?.ServerName ?? "",
                FinalServerMap: lastConnected?.ServerMap ?? "",
                ConsistentConnection: consistentConnection,
                DisconnectionEvents: _disconnectionEvents);
        }
    }

    /// <summary>Take a single proof point sample.</summary>
    private void TakeProofPoint(string trigger)
    {
        if (_disposed || _cancellationToken.IsCancellationRequested) return;

        try
        {
            var timestamp = DateTimeOffset.UtcNow;
            var sequence = Interlocked.Increment(ref _sequenceNumber);

            // Get UDP ports
            var ports = GameTraffic.UdpPortsOf(_processId);

            // Scan for the live connection. The authoritative source is the operating
            // system's UDP endpoint table (the game's connected socket remote peer).
            string? endpoint = null;
            string? serverName = null;
            string? serverMap = null;
            int players = 0;
            string memoryHash = "";
            string a2sHash = "";
            string status = "not-connected";
            string reason = "no connection evidence found";

            var peers = GameTraffic.ConnectedUdpPeersOf(_processId);
            if (peers.Count > 0)
            {
                // Prefer the standard Counter-Strike port range when several sockets exist.
                var best = peers
                    .OrderByDescending(p => p.RemotePort is >= 27015 and <= 27030)
                    .ThenByDescending(p => p.RemotePort == 27015)
                    .First();

                endpoint = best.Endpoint;
                status = "connected";
                reason = $"live OS UDP endpoint ({trigger})";
                memoryHash = ComputeHash(string.Join(";", peers.Select(p => p.Endpoint).OrderBy(e => e)));

                var a2s = ValveA2S.Query(best.Endpoint, timeoutMs: 500);
                if (a2s.Success)
                {
                    serverName = a2s.Name;
                    serverMap = a2s.Map;
                    players = a2s.Players;
                    a2sHash = ComputeHash($"{a2s.Name}|{a2s.Map}|{a2s.Players}|{a2s.MaxPlayers}");
                }
            }
            else if (ports.Count > 0)
            {
                // Fallback: read the connection strings the engine prints to its console.
                var handle = OpenProcess(ProcessQueryInformation | ProcessVmRead, false, _processId);
                if (handle != IntPtr.Zero)
                {
                    try
                    {
                        var (accepted, candidates, hasDisconnected) = ScanMemoryForEndpoints(handle);

                        if (!string.IsNullOrEmpty(accepted) && !hasDisconnected)
                        {
                            endpoint = accepted;
                            status = "connected";
                            reason = $"active connection found ({trigger})";

                            // Try A2S query
                            var a2s = ValveA2S.Query(accepted, timeoutMs: 500);
                            if (a2s.Success)
                            {
                                serverName = a2s.Name;
                                serverMap = a2s.Map;
                                players = a2s.Players;
                                a2sHash = ComputeHash($"{a2s.Name}|{a2s.Map}|{a2s.Players}|{a2s.MaxPlayers}");
                            }
                        }
                        else if (hasDisconnected)
                        {
                            status = "not-connected";
                            reason = "disconnection detected in memory";
                            _disconnectionEvents++;
                        }
                        else if (candidates.Count > 0)
                        {
                            // Have candidates but no accepted connection
                            endpoint = candidates[0];
                            status = "unverified";
                            reason = "connection candidates found but not confirmed";
                        }

                        memoryHash = ComputeHash($"{accepted}|{string.Join(",", candidates)}|{hasDisconnected}");
                    }
                    finally
                    {
                        CloseHandle(handle);
                    }
                }
                else
                {
                    status = "unverified";
                    reason = "cannot open process for memory reading";
                }
            }
            else
            {
                status = "not-connected";
                reason = "no UDP ports open";
            }

            // Track initial endpoint for consistency checking
            if (sequence == 1 && !string.IsNullOrEmpty(endpoint))
            {
                _initialEndpoint = endpoint;
            }
            else if (_initialEndpoint != null && endpoint != null &&
                     !endpoint.Equals(_initialEndpoint, StringComparison.OrdinalIgnoreCase))
            {
                // Server changed during scan - this is suspicious
                _disconnectionEvents++;
            }

            var proofPoint = new ProofPoint(
                SequenceNumber: sequence,
                Timestamp: timestamp,
                Status: status,
                Endpoint: endpoint ?? "",
                ServerName: serverName ?? "",
                ServerMap: serverMap ?? "",
                PlayersOnServer: players,
                LocalUdpPorts: ports,
                MemoryEvidenceHash: memoryHash,
                A2SResponseHash: a2sHash,
                Reason: reason);

            lock (_lock)
            {
                _proofPoints.Add(proofPoint);
            }
        }
        catch (Exception ex)
        {
            // Log but don't fail - monitoring should be resilient
            Debug.WriteLine($"[ServerMonitor] Proof point error: {ex.Message}");
        }
    }

    /// <summary>Determine the final connection status based on all proof points.</summary>
    private string DetermineFinalStatus()
    {
        if (_proofPoints.Count == 0) return "unverified";

        var connectedCount = _proofPoints.Count(p => p.Status == "connected");
        var totalCount = _proofPoints.Count;

        // Check for disconnection during scan
        var hadConnection = _proofPoints.Any(p => p.Status == "connected");
        var lostConnection = _proofPoints.Any(p => p.Status == "not-connected" &&
            p.Reason.Contains("disconnect", StringComparison.OrdinalIgnoreCase));

        if (hadConnection && lostConnection)
        {
            return "disconnected-during-scan";
        }

        if (connectedCount == 0)
        {
            return "not-connected";
        }

        if (connectedCount == totalCount)
        {
            return "connected";
        }

        // Partial connection - suspicious
        return connectedCount >= totalCount / 2 ? "connected" : "unverified";
    }

    /// <summary>Compute SHA256 hash of all proof points for tamper evidence.</summary>
    private static string ComputeChainHash(IReadOnlyList<ProofPoint> points)
    {
        var sb = new StringBuilder();
        foreach (var p in points)
        {
            sb.Append(p.SequenceNumber).Append('|')
              .Append(p.Timestamp.ToString("O")).Append('|')
              .Append(p.Status).Append('|')
              .Append(p.Endpoint).Append('|')
              .Append(p.MemoryEvidenceHash).Append('|')
              .Append(p.A2SResponseHash).Append(';');
        }
        return ComputeHash(sb.ToString());
    }

    /// <summary>Compute SHA256 hash of a string.</summary>
    private static string ComputeHash(string input)
    {
        using var sha = SHA256.Create();
        var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(input));
        return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
    }

    // Memory scanning helpers (simplified from GameTraffic)
    private static readonly System.Text.RegularExpressions.Regex AcceptedRegex =
        new(@"Connection accepted by\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{1,5})",
            System.Text.RegularExpressions.RegexOptions.Compiled | System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    private static readonly string[] DisconnectPhrases =
    [
        "Server disconnected",
        "Disconnecting from server",
        "Server closed connection",
        "Connection to server lost",
        "Dropped from server"
    ];

    private static (string? Accepted, List<string> Candidates, bool HasDisconnected) ScanMemoryForEndpoints(IntPtr handle)
    {
        string? lastAccepted = null;
        var hasDisconnected = false;
        var candidates = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        long addr = 0x00010000;
        const uint readableMask = PageReadWrite | PageWriteCopy | PageExecuteReadWrite | PageExecuteWriteCopy | PageReadOnly | PageExecuteRead;
        var buffer = new byte[4 * 1024 * 1024];

        while (VirtualQueryEx(handle, (IntPtr)addr, out var mbi, (UIntPtr)Marshal.SizeOf<MemoryBasicInformation>()) != UIntPtr.Zero)
        {
            long baseAddr = mbi.BaseAddress.ToInt64();
            long size = (long)mbi.RegionSize.ToUInt64();
            if (baseAddr >= 0x7FFF0000 || size <= 0) break;

            bool isCommitted = mbi.State == MemCommit;
            bool isReadable = (mbi.Protect & readableMask) != 0 && (mbi.Protect & 0x100) == 0;

            if (isCommitted && isReadable && size <= 16 * 1024 * 1024)
            {
                int toRead = (int)Math.Min(size, buffer.Length);
                if (ReadProcessMemory(handle, (IntPtr)baseAddr, buffer, (UIntPtr)(uint)toRead, out var read) && read.ToUInt64() > 0)
                {
                    int bytesRead = (int)read.ToUInt64();
                    var text = Encoding.ASCII.GetString(buffer, 0, bytesRead);

                    var acceptedMatches = AcceptedRegex.Matches(text);
                    if (acceptedMatches.Count > 0)
                    {
                        var lastMatch = acceptedMatches[^1];
                        lastAccepted = lastMatch.Groups[1].Value;

                        var acceptedPos = lastMatch.Index;
                        foreach (var phrase in DisconnectPhrases)
                        {
                            var dcPos = text.IndexOf(phrase, acceptedPos, StringComparison.OrdinalIgnoreCase);
                            if (dcPos > acceptedPos)
                            {
                                hasDisconnected = true;
                                break;
                            }
                        }
                    }
                }
            }

            addr = baseAddr + size;
        }

        return (lastAccepted, candidates, hasDisconnected);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _monitorTimer?.Dispose();
    }

    // P/Invoke
    private const uint ProcessQueryInformation = 0x0400;
    private const uint ProcessVmRead = 0x0010;
    private const uint MemCommit = 0x1000;
    private const uint PageReadOnly = 0x02;
    private const uint PageReadWrite = 0x04;
    private const uint PageWriteCopy = 0x08;
    private const uint PageExecuteRead = 0x20;
    private const uint PageExecuteReadWrite = 0x40;
    private const uint PageExecuteWriteCopy = 0x80;

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryBasicInformation
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public UIntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern UIntPtr VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MemoryBasicInformation lpBuffer, UIntPtr dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr process, IntPtr address, byte[] buffer, UIntPtr size, out UIntPtr bytesRead);
}
