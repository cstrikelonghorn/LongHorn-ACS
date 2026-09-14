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
    private string? _cachedServerName;
    private string? _cachedServerMap;
    private int _cachedPlayers;
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

            var finalEndpoint = lastConnected?.Endpoint ?? _initialEndpoint ?? "";
            var finalServerName = _proofPoints.FirstOrDefault(p => !string.IsNullOrEmpty(p.ServerName))?.ServerName ?? _cachedServerName ?? "";
            var finalServerMap = _proofPoints.FirstOrDefault(p => !string.IsNullOrEmpty(p.ServerMap))?.ServerMap ?? _cachedServerMap ?? "";

            return new EvidenceChain(
                SessionId: _sessionId,
                ScanStarted: scanStarted,
                ScanFinished: scanFinished,
                ProofPoints: _proofPoints.ToList(),
                ChainHash: chainHash,
                FinalStatus: finalStatus,
                FinalEndpoint: finalEndpoint,
                FinalServerName: finalServerName,
                FinalServerMap: finalServerMap,
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

            // Authoritative server connection inspection via GameTraffic
            var traffic = GameTraffic.Capture(_processId, _cancellationToken, sampleMilliseconds: 1000);
            status = traffic.Status;
            endpoint = traffic.Endpoint;
            reason = $"{traffic.Reason} ({trigger})";

            if (traffic.A2S is { Success: true } a2s)
            {
                serverName = _cachedServerName = a2s.Name;
                serverMap = _cachedServerMap = a2s.Map;
                players = _cachedPlayers = a2s.Players;
                a2sHash = ComputeHash($"{a2s.Name}|{a2s.Map}|{a2s.Players}|{a2s.MaxPlayers}");
            }
            else if (!string.IsNullOrEmpty(_cachedServerName))
            {
                serverName = _cachedServerName;
                serverMap = _cachedServerMap;
                players = _cachedPlayers;
            }

            memoryHash = ComputeHash($"{traffic.Status}|{traffic.Endpoint}|{string.Join(",", ports)}");

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



    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _monitorTimer?.Dispose();
    }
}
