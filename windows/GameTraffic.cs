using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

namespace ACPScanner;

/// <summary>
/// Identifies the game server the player is currently joined to in standard user space.
///
/// Eliminates the need for raw promiscuous sockets (which previously required Windows
/// Administrator elevation). Instead, this module uses zero-privilege game process memory
/// inspection and official Valve A2S Server Queries (A2S_INFO) to identify the live server accurately.
/// </summary>
public static class GameTraffic
{
    public const int MinPacketsInOneDirection = 12;

    public sealed record Result(
        string Status,          // "connected" | "not-connected" | "unverified"
        string Endpoint,        // "ip:port" of the server when connected
        int Sent,               // query packets sent
        int Received,           // query packets received
        int SampleMilliseconds,
        IReadOnlyList<int> LocalPorts,
        string Reason,
        DateTimeOffset CapturedAt,
        ValveA2S.ServerInfo? A2S = null);

    /// <summary>
    /// Checks whether the current process token has Administrator membership.
    /// Note: Elevation is NO LONGER required for game connection detection or scanning.
    /// </summary>
    public static bool IsElevated()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Resolves the connected server for the given game process in user space without requiring administrator rights.
    /// </summary>
    public static Result Capture(int processId, CancellationToken cancellationToken, int sampleMilliseconds = 2500)
    {
        var capturedAt = DateTimeOffset.UtcNow;
        var sw = Stopwatch.StartNew();
        var ports = UdpPortsOf(processId);

        if (ports.Count == 0)
        {
            return new Result("not-connected", "", 0, 0, (int)sw.ElapsedMilliseconds, ports,
                "the game has no UDP socket open", capturedAt);
        }

        IntPtr handle = OpenProcess(ProcessQueryInformation | ProcessVmRead, false, processId);
        if (handle == IntPtr.Zero)
        {
            return new Result("unverified", "", 0, 0, (int)sw.ElapsedMilliseconds, ports,
                "unable to inspect game memory (access denied or process closed)", capturedAt);
        }

        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            Process process;
            try
            {
                process = Process.GetProcessById(processId);
            }
            catch
            {
                return new Result("not-connected", "", 0, 0, (int)sw.ElapsedMilliseconds, ports,
                    "game process exited", capturedAt);
            }

            var (acceptedEndpoint, candidateEndpoints, hasDisconnected) = ScanMemoryForEndpoints(handle, process);

            cancellationToken.ThrowIfCancellationRequested();

            var queryCandidates = new List<string>();
            if (!string.IsNullOrEmpty(acceptedEndpoint) && !hasDisconnected)
            {
                queryCandidates.Add(acceptedEndpoint);
            }

            // Prioritize standard CS server port :27015 and common range 27015-27030
            var prioritized = candidateEndpoints
                .OrderByDescending(ep => ep.EndsWith(":27015", StringComparison.OrdinalIgnoreCase))
                .ThenByDescending(ep =>
                {
                    if (ValveA2S.TryParseEndpoint(ep, out var parsed) && parsed is not null)
                    {
                        return parsed.Port is >= 27015 and <= 27030;
                    }
                    return false;
                })
                .ToList();

            foreach (var ep in prioritized)
            {
                if (!queryCandidates.Contains(ep, StringComparer.OrdinalIgnoreCase))
                {
                    queryCandidates.Add(ep);
                }
            }

            var packetsSent = 0;
            var packetsReceived = 0;

            // Query candidates via Valve A2S_INFO
            foreach (var candidate in queryCandidates)
            {
                if (sw.ElapsedMilliseconds >= sampleMilliseconds) break;
                cancellationToken.ThrowIfCancellationRequested();

                packetsSent++;
                var a2s = ValveA2S.Query(candidate, timeoutMs: 600);
                if (a2s.Success)
                {
                    packetsReceived++;
                    return new Result("connected", candidate, packetsSent, packetsReceived,
                        (int)sw.ElapsedMilliseconds, ports, "verified via Valve A2S_INFO query", capturedAt, a2s);
                }
            }

            // If the server did not answer A2S (e.g. firewalled UDP queries), but was accepted in game memory
            if (!string.IsNullOrEmpty(acceptedEndpoint) && !hasDisconnected)
            {
                return new Result("connected", acceptedEndpoint, packetsSent, packetsReceived,
                    (int)sw.ElapsedMilliseconds, ports,
                    "identified from active game connection (server did not answer A2S query)", capturedAt);
            }

            return new Result("not-connected", "", packetsSent, packetsReceived,
                (int)sw.ElapsedMilliseconds, ports, "no active game server connection detected", capturedAt);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return new Result("unverified", "", 0, 0, (int)sw.ElapsedMilliseconds, ports,
                "connection detection error: " + ex.Message, capturedAt);
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    private static readonly Regex AcceptedRegex = new(@"Connection accepted by\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{1,5})", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex ConnectingRegex = new(@"Connecting to\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{1,5})", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex ConnectCmdRegex = new(@"connect\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{1,5})", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex GeneralIpPortRegex = new(@"\b([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):([0-9]{2,5})\b", RegexOptions.Compiled);

    private static readonly string[] DisconnectPhrases =
    [
        "Server disconnected",
        "Disconnecting from server",
        "Server closed connection",
        "Connection to server lost",
        "Dropped from server"
    ];

    private static (string? Accepted, List<string> Candidates, bool HasDisconnected) ScanMemoryForEndpoints(IntPtr handle, Process process)
    {
        string? lastAccepted = null;
        var hasDisconnected = false;
        var candidates = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        long addr = 0x00010000;
        const uint readableMask = PageReadWrite | PageWriteCopy | PageExecuteReadWrite | PageExecuteWriteCopy | PageReadOnly | PageExecuteRead;

        // Reusable buffer to avoid memory allocations
        var buffer = new byte[4 * 1024 * 1024];

        while (VirtualQueryEx(handle, (IntPtr)addr, out var mbi, (UIntPtr)Marshal.SizeOf<MemoryBasicInformation>()) != UIntPtr.Zero)
        {
            long baseAddr = mbi.BaseAddress.ToInt64();
            long size = (long)mbi.RegionSize.ToUInt64();
            if (baseAddr >= 0x7FFF0000 || size <= 0) break;

            bool isCommitted = mbi.State == MemCommit;
            bool isReadable = (mbi.Protect & readableMask) != 0 && (mbi.Protect & 0x100 /* PAGE_GUARD */) == 0;

            if (isCommitted && isReadable && size <= 16 * 1024 * 1024)
            {
                int toRead = (int)Math.Min(size, buffer.Length);
                if (ReadProcessMemory(handle, (IntPtr)baseAddr, buffer, (UIntPtr)(uint)toRead, out var read) && read.ToUInt64() > 0)
                {
                    int bytesRead = (int)read.ToUInt64();
                    var text = Encoding.ASCII.GetString(buffer, 0, bytesRead);

                    // Search for accepted connections
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

                    // Search for connecting
                    foreach (Match m in ConnectingRegex.Matches(text))
                    {
                        var ep = m.Groups[1].Value;
                        if (IsValidEndpoint(ep) && seen.Add(ep))
                        {
                            candidates.Add(ep);
                        }
                    }

                    // Search for connect commands
                    foreach (Match m in ConnectCmdRegex.Matches(text))
                    {
                        var ep = m.Groups[1].Value;
                        if (IsValidEndpoint(ep) && seen.Add(ep))
                        {
                            candidates.Add(ep);
                        }
                    }

                    // General IP:port patterns in game memory
                    foreach (Match m in GeneralIpPortRegex.Matches(text))
                    {
                        var ep = m.Value;
                        if (IsValidEndpoint(ep) && seen.Add(ep))
                        {
                            candidates.Add(ep);
                        }
                    }
                }
            }

            addr = baseAddr + size;
        }

        return (lastAccepted, candidates, hasDisconnected);
    }

    private static bool IsValidEndpoint(string endpoint)
    {
        if (!ValveA2S.TryParseEndpoint(endpoint, out var ep) || ep is null) return false;
        if (IPAddress.IsLoopback(ep.Address) || ep.Address.Equals(IPAddress.Any) || ep.Address.Equals(IPAddress.Broadcast)) return false;
        if (ep.Port is < 1024 or > 65535) return false;

        // Filter out non-game ports like HTTPS (443), STUN (3478), etc.
        if (ep.Port is 80 or 443 or 3478) return false;

        return true;
    }

    /// <summary>
    /// Legacy compatibility helper for unit tests or external callers.
    /// </summary>
    public static Result Decide(IReadOnlyDictionary<string, (int Sent, int Received)> flows, int sampleMilliseconds,
                                IReadOnlyList<int> localPorts, DateTimeOffset capturedAt)
    {
        var best = flows
            .OrderByDescending(f => Math.Max(f.Value.Sent, f.Value.Received))
            .ThenByDescending(f => f.Value.Sent + f.Value.Received)
            .FirstOrDefault();

        if (best.Key is not null && Math.Max(best.Value.Sent, best.Value.Received) >= MinPacketsInOneDirection)
        {
            return new Result("connected", best.Key, best.Value.Sent, best.Value.Received, sampleMilliseconds, localPorts,
                "sustained UDP traffic between the game and this server", capturedAt);
        }

        var total = flows.Values.Sum(f => f.Sent + f.Received);
        var reason = flows.Count == 0
            ? "no UDP traffic between the game and any server"
            : $"no sustained traffic: {total} packet(s) to {flows.Count} address(es)";
        return new Result("not-connected", "", 0, 0, sampleMilliseconds, localPorts, reason, capturedAt);
    }

    /// <summary>
    /// Legacy compatibility helper for parsing UDP packets.
    /// </summary>
    public static bool TryParseUdp(ReadOnlySpan<byte> packet, out IPAddress source, out int sourcePort,
                                   out IPAddress destination, out int destinationPort)
    {
        source = destination = IPAddress.None;
        sourcePort = destinationPort = 0;

        if (packet.Length < 28 || packet[0] >> 4 != 4) return false;
        var headerLength = (packet[0] & 0x0F) * 4;
        if (headerLength < 20 || packet.Length < headerLength + 8 || packet[9] != 17) return false;
        var fragmentOffset = ((packet[6] & 0x1F) << 8) | packet[7];
        if (fragmentOffset != 0) return false;

        source = new IPAddress(packet.Slice(12, 4).ToArray());
        destination = new IPAddress(packet.Slice(16, 4).ToArray());
        sourcePort = (packet[headerLength] << 8) | packet[headerLength + 1];
        destinationPort = (packet[headerLength + 2] << 8) | packet[headerLength + 3];
        return true;
    }

    // ── The game's UDP ports ─────────────────────────────────────────────────

    /// <summary>
    /// Every local UDP port owned by a process, from GetExtendedUdpTable with UDP_TABLE_OWNER_PID.
    /// Runs with standard user privileges (no administrator rights needed).
    /// </summary>
    public static List<int> UdpPortsOf(int processId)
    {
        var ports = new List<int>();
        var size = 0;
        GetExtendedUdpTable(IntPtr.Zero, ref size, false, AfInet, UdpTableOwnerPid, 0);
        if (size <= 0) return ports;

        for (var attempt = 0; attempt < 3; attempt++)
        {
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                var status = GetExtendedUdpTable(buffer, ref size, false, AfInet, UdpTableOwnerPid, 0);
                if (status == ErrorInsufficientBuffer) continue;
                if (status != 0) return ports;

                var rows = Marshal.ReadInt32(buffer);
                for (var i = 0; i < rows; i++)
                {
                    var row = buffer + 4 + i * 12;
                    var owner = Marshal.ReadInt32(row, 8);
                    if (owner != processId) continue;
                    var raw = Marshal.ReadInt32(row, 4);
                    var port = ((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF);
                    if (port > 0 && !ports.Contains(port))
                    {
                        ports.Add(port);
                    }
                }
                return ports;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        return ports;
    }

    private const int AfInet = 2;
    private const int UdpTableOwnerPid = 1;
    private const uint ErrorInsufficientBuffer = 122;

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

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(IntPtr table, ref int size, bool sort, int addressFamily, int tableClass, int reserved);
}
