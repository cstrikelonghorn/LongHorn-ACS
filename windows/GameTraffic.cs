using System.Diagnostics;
using System.Linq;
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
    /// A live UDP peer of the game process, read from the operating system's UDP endpoint
    /// table. RemotePort is the server's port; it is only non-zero for a connected socket.
    /// </summary>
    public sealed record UdpPeer(int LocalPort, IPAddress RemoteAddress, int RemotePort)
    {
        public string Endpoint => $"{RemoteAddress}:{RemotePort}";
    }

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
	///
	/// Primary method: the Windows UDP endpoint table (the same data netstat prints), which exposes the
	/// remote peer of the game's connected UDP socket. That is authoritative - it is the address the client
	/// is actually talking to, not a value the engine happens to have in memory.
	/// Fallback: scan the engine's memory for the connection strings it prints to the console, for engines
	/// whose socket is not in the connected state.
	/// </summary>
	public static Result Capture(int processId, CancellationToken cancellationToken, int sampleMilliseconds = 2500)
	{
		var capturedAt = DateTimeOffset.UtcNow;
		var sw = Stopwatch.StartNew();
		var ports = UdpPortsOf(processId);

		// Authoritative OS view of the game's connected UDP socket(s). No elevation required.
		var peers = ConnectedUdpPeersOf(processId);

		if (ports.Count == 0 && peers.Count == 0)
		{
			return new Result("not-connected", "", 0, 0, (int)sw.ElapsedMilliseconds, ports,
				"the game has no UDP socket open", capturedAt);
		}

		// Prefer servers listening on the standard Counter-Strike port range.
		var orderedPeers = peers
			.OrderByDescending(p => p.RemotePort is >= 27015 and <= 27030)
			.ThenByDescending(p => p.RemotePort == 27015)
			.ToList();

		var packetsSent = 0;
		var packetsReceived = 0;

		// Ask each live endpoint what server it is; the one that answers A2S_INFO as a game
		// server is the server the client is joined to.
		foreach (var peer in orderedPeers)
		{
			if (sw.ElapsedMilliseconds >= sampleMilliseconds) break;
			cancellationToken.ThrowIfCancellationRequested();

			packetsSent++;
			var a2s = ValveA2S.Query(peer.Endpoint, timeoutMs: 600);
			if (a2s.Success)
			{
				packetsReceived++;
				return new Result("connected", peer.Endpoint, packetsSent, packetsReceived,
					(int)sw.ElapsedMilliseconds, ports,
					"verified via live OS UDP endpoint and Valve A2S_INFO query", capturedAt, a2s);
			}
		}

		// The OS reports a live peer even when the server refuses A2S queries (common on
		// protected 1.6 servers). The endpoint is still authoritative, so report it.
		if (orderedPeers.Count > 0)
		{
			var best = orderedPeers[0];
			return new Result("connected", best.Endpoint, packetsSent, packetsReceived,
				(int)sw.ElapsedMilliseconds, ports,
				"identified from live OS UDP endpoint (server did not answer A2S query)", capturedAt);
		}

		// Fallback or authoritative engine scan: query the game engine's internal network state
		// (netadr_t structs in hw.dll/sw.dll/hl.exe) and connection commands.
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

			var candidateList = DetectCandidates(handle, process, orderedPeers);
			cancellationToken.ThrowIfCancellationRequested();

			// Query candidates via Valve A2S_INFO in order of confidence/score
			foreach (var candidate in candidateList)
			{
				if (sw.ElapsedMilliseconds >= sampleMilliseconds) break;
				cancellationToken.ThrowIfCancellationRequested();

				packetsSent++;
				var a2s = ValveA2S.Query(candidate.Endpoint, timeoutMs: 600);
				if (a2s.Success)
				{
					packetsReceived++;
					return new Result("connected", candidate.Endpoint, packetsSent, packetsReceived,
						(int)sw.ElapsedMilliseconds, ports, $"verified via Valve A2S_INFO query ({candidate.Source})", capturedAt, a2s);
				}
			}

			// If the server did not answer A2S (e.g. firewalled UDP queries or flood protection),
			// but was verified from an active engine netadr_t struct or OS peer
			var activeEngineCandidate = candidateList.FirstOrDefault(c => c.Score >= 700);
			if (activeEngineCandidate != null)
			{
				return new Result("connected", activeEngineCandidate.Endpoint, packetsSent, packetsReceived,
					(int)sw.ElapsedMilliseconds, ports,
					$"identified from active game connection ({activeEngineCandidate.Source}, server did not answer A2S query)", capturedAt);
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

	public sealed record EndpointCandidate(string Endpoint, int Score, string Source);

	private static readonly Regex ConnectCmdRegex = new(@"connect\s+([a-zA-Z0-9_.-]+(?::[0-9]{1,5})?)", RegexOptions.Compiled | RegexOptions.IgnoreCase);
	private static readonly Regex ConnectingRegex = new(@"Connecting to\s+([a-zA-Z0-9_.-]+(?::[0-9]{1,5})?)", RegexOptions.Compiled | RegexOptions.IgnoreCase);
	private static readonly Regex GeneralIpPortRegex = new(@"\b([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):([0-9]{2,5})\b", RegexOptions.Compiled);

	private static List<EndpointCandidate> DetectCandidates(IntPtr handle, Process process, List<UdpPeer> osPeers)
	{
		var candidates = new Dictionary<string, EndpointCandidate>(StringComparer.OrdinalIgnoreCase);

		// 1. OS connected UDP peers (highest authoritative rank)
		foreach (var peer in osPeers)
		{
			int score = 2000;
			if (peer.RemotePort == 27015) score += 200;
			candidates[peer.Endpoint] = new EndpointCandidate(peer.Endpoint, score, "OS UDP socket table");
		}

		// 2. Scan engine modules for GoldSrc netadr_t structs (NA_IP = 3)
		try
		{
			foreach (ProcessModule mod in process.Modules)
			{
				string name = (mod.ModuleName ?? "").ToLowerInvariant();
				if (name == "hw.dll" || name == "sw.dll" || name == "hl.exe" || name == "client.dll")
				{
					ScanModuleForNetAdr(handle, mod, candidates);
				}
			}
		}
		catch { }

		// 3. Scan committed game memory for heap netadr_t structs, connect commands, and IP:port patterns
		ScanMemoryForGameTraffic(handle, candidates);

		return candidates.Values
			.OrderByDescending(c => c.Score)
			.ToList();
	}

	private static void ScanModuleForNetAdr(IntPtr handle, ProcessModule mod, Dictionary<string, EndpointCandidate> candidates)
	{
		long baseAddr = mod.BaseAddress.ToInt64();
		int size = mod.ModuleMemorySize;
		if (size <= 0 || size > 64 * 1024 * 1024) return;

		byte[] buf = new byte[size];
		if (!ReadProcessMemory(handle, (IntPtr)baseAddr, buf, (UIntPtr)(uint)size, out var read) || read.ToUInt64() == 0) return;
		int bytesRead = (int)read.ToUInt64();

		for (int i = 0; i <= bytesRead - 20; i++)
		{
			// type == 3 (NA_IP)
			if (buf[i] == 3 && buf[i + 1] == 0 && buf[i + 2] == 0 && buf[i + 3] == 0)
			{
				byte b0 = buf[i + 4], b1 = buf[i + 5], b2 = buf[i + 6], b3 = buf[i + 7];
				if (b0 == 0 || b0 == 127 || b0 == 255) continue;

				// IPX bytes (must be 10 consecutive zeros in netadr_t)
				bool allZeros = true;
				for (int k = 0; k < 10; k++)
				{
					if (buf[i + 8 + k] != 0) { allZeros = false; break; }
				}
				if (!allZeros) continue;

				// Port (big-endian network byte order)
				int port = (buf[i + 18] << 8) | buf[i + 19];
				if (port < 1024 || port > 65535) continue;

				var ip = new IPAddress(new byte[] { b0, b1, b2, b3 });
				string ep = $"{ip}:{port}";

				int score = 800;
				if (port == 27015) score += 300;
				else if (port is >= 27015 and <= 27030) score += 200;

				if (!IsPrivateIp(ip)) score += 150;

				if (!candidates.TryGetValue(ep, out var existing) || existing.Score < score)
				{
					candidates[ep] = new EndpointCandidate(ep, score, $"{mod.ModuleName} netadr_t struct");
				}
			}
		}
	}

	private static void ScanMemoryForGameTraffic(IntPtr handle, Dictionary<string, EndpointCandidate> candidates)
	{
		long addr = 0x00010000;
		const uint readableMask = PageReadWrite | PageWriteCopy | PageExecuteReadWrite | PageExecuteWriteCopy | PageReadOnly | PageExecuteRead;
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

					// Check for heap netadr_t structs
					for (int i = 0; i <= bytesRead - 20; i++)
					{
						if (buffer[i] == 3 && buffer[i + 1] == 0 && buffer[i + 2] == 0 && buffer[i + 3] == 0)
						{
							byte b0 = buffer[i + 4], b1 = buffer[i + 5], b2 = buffer[i + 6], b3 = buffer[i + 7];
							if (b0 == 0 || b0 == 127 || b0 == 255) continue;

							bool allZeros = true;
							for (int k = 0; k < 10; k++)
							{
								if (buffer[i + 8 + k] != 0) { allZeros = false; break; }
							}
							if (!allZeros) continue;

							int port = (buffer[i + 18] << 8) | buffer[i + 19];
							if (port < 1024 || port > 65535) continue;

							var ip = new IPAddress(new byte[] { b0, b1, b2, b3 });
							string ep = $"{ip}:{port}";

							int score = 700;
							if (port == 27015) score += 250;
							else if (port is >= 27015 and <= 27030) score += 150;
							if (!IsPrivateIp(ip)) score += 100;

							if (!candidates.TryGetValue(ep, out var existing) || existing.Score < score)
							{
								candidates[ep] = new EndpointCandidate(ep, score, "heap netadr_t struct");
							}
						}
					}

					string text = Encoding.ASCII.GetString(buffer, 0, bytesRead);

					void AddConnectMatch(Match m, string source, int baseScore)
					{
						string hostPort = m.Groups[1].Value.Trim();
						if (string.IsNullOrEmpty(hostPort) || hostPort.StartsWith("%") || hostPort.StartsWith("<")) return;

						string host = hostPort;
						int port = 27015;
						int colon = hostPort.IndexOf(':');
						if (colon > 0)
						{
							host = hostPort.Substring(0, colon);
							int.TryParse(hostPort.Substring(colon + 1), out port);
						}
						if (port < 1024 || port > 65535) port = 27015;

						if (IPAddress.TryParse(host, out var ip))
						{
							if (!IPAddress.IsLoopback(ip) && !ip.Equals(IPAddress.Any) && !ip.Equals(IPAddress.Broadcast))
							{
								string ep = $"{ip}:{port}";
								int score = baseScore;
								if (port == 27015) score += 50;
								if (!IsPrivateIp(ip)) score += 50;
								if (!candidates.TryGetValue(ep, out var existing) || existing.Score < score)
									candidates[ep] = new EndpointCandidate(ep, score, source);
							}
						}
						else if (LooksLikeDomain(host))
						{
							try
							{
								var addrs = Dns.GetHostAddresses(host);
								foreach (var addr in addrs.Where(a => a.AddressFamily == AddressFamily.InterNetwork))
								{
									string ep = $"{addr}:{port}";
									int score = baseScore + 20;
									if (port == 27015) score += 50;
									if (!IsPrivateIp(addr)) score += 50;
									if (!candidates.TryGetValue(ep, out var existing) || existing.Score < score)
										candidates[ep] = new EndpointCandidate(ep, score, $"{source} (resolved {host})");
								}
							}
							catch { }
						}
					}

					foreach (Match m in ConnectingRegex.Matches(text))
						AddConnectMatch(m, "console 'Connecting to' log", 550);

					foreach (Match m in ConnectCmdRegex.Matches(text))
						AddConnectMatch(m, "console 'connect' command", 500);

					// General IP:port patterns in memory (e.g. server history/favorites) - lower score
					foreach (Match m in GeneralIpPortRegex.Matches(text))
					{
						string ep = m.Value;
						if (ValveA2S.TryParseEndpoint(ep, out var parsed) && parsed is not null)
						{
							if (parsed.Port is >= 27015 and <= 27030 && !IPAddress.IsLoopback(parsed.Address) && !parsed.Address.Equals(IPAddress.Any))
							{
								int score = 50;
								if (!IsPrivateIp(parsed.Address)) score += 30;
								if (!candidates.TryGetValue(ep, out var existing) || existing.Score < score)
									candidates[ep] = new EndpointCandidate(ep, score, "memory ip:port string");
							}
						}
					}
				}
			}

			addr = baseAddr + size;
		}
	}

	private static bool LooksLikeDomain(string host)
	{
		if (string.IsNullOrWhiteSpace(host)) return false;
		if (!host.Contains('.')) return false;
		if (host.StartsWith(".") || host.EndsWith(".")) return false;
		int lastDot = host.LastIndexOf('.');
		string tld = host.Substring(lastDot + 1);
		return tld.Length >= 2 && tld.All(char.IsLetter);
	}

	private static bool IsPrivateIp(IPAddress ip)
	{
		var bytes = ip.GetAddressBytes();
		if (bytes.Length != 4) return false;
		if (bytes[0] == 10) return true;
		if (bytes[0] == 172 && bytes[1] is >= 16 and <= 31) return true;
		if (bytes[0] == 192 && bytes[1] == 168) return true;
		if (bytes[0] == 127) return true;
		if (bytes[0] == 169 && bytes[1] == 254) return true;
		return false;
	}

	private static bool IsValidEndpoint(string endpoint)
	{
		if (!ValveA2S.TryParseEndpoint(endpoint, out var ep) || ep is null) return false;
		if (IPAddress.IsLoopback(ep.Address) || ep.Address.Equals(IPAddress.Any) || ep.Address.Equals(IPAddress.Broadcast)) return false;
		if (ep.Port is < 1024 or > 65535) return false;
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

    // ── The game's connected UDP peer (the server) ───────────────────────────

    /// <summary>
    /// Every connected UDP socket owned by a process, with its remote address and port, read from the
    /// operating system's endpoint table. This is the same source netstat uses and it is authoritative:
    /// the operating system knows exactly which server the client's socket is talking to, no matter what
    /// the game stores in memory. It does not require administrator rights.
    ///
    /// Uses the internal table function that exposes the remote endpoint (netstat's own source). If it
    /// is unavailable on this build of Windows, an empty list is returned and callers fall back to the
    /// memory scan in Capture().
    /// </summary>
    public static List<UdpPeer> ConnectedUdpPeersOf(int processId)
    {
        var peers = new List<UdpPeer>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        IntPtr heap = GetProcessHeap();
        IntPtr table = IntPtr.Zero;

        try
        {
            var status = InternalGetUdpTable2(out table, heap, false);
            if (status != 0 || table == IntPtr.Zero) return peers;

            var count = Marshal.ReadInt32(table);
            if (count < 0 || count > 1_000_000) return peers;

            // MIB_UDPROW2 (see Windows SDK udpmib.h): the table header is 8 bytes and each
            // 168-byte row carries dwLocalAddr(+0), dwLocalPort(+4), dwOwningPid(+8),
            // dwRemoteAddr(+160) and dwRemotePort(+164). Verified against both 32- and
            // 64-bit processes.
            const int RowBase = 8;
            const int RowSize = 168;
            const int OwningPidOffset = 8;
            const int LocalPortOffset = 4;
            const int RemoteAddrOffset = 160;
            const int RemotePortOffset = 164;

            for (var i = 0; i < count; i++)
            {
                var row = table + RowBase + i * RowSize;

                if (Marshal.ReadInt32(row, OwningPidOffset) != processId) continue;

                var remotePortRaw = Marshal.ReadInt32(row, RemotePortOffset);
                var remotePort = ((remotePortRaw & 0xFF) << 8) | ((remotePortRaw >> 8) & 0xFF);
                if (remotePort <= 0 || remotePort > 65535) continue; // not a connected socket

                var remoteAddrRaw = Marshal.ReadInt32(row, RemoteAddrOffset);
                var address = new IPAddress(BitConverter.GetBytes(remoteAddrRaw));
                var bytes = address.GetAddressBytes();
                if (bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 0) continue;
                if (address.Equals(IPAddress.Broadcast)) continue;

                var localPortRaw = Marshal.ReadInt32(row, LocalPortOffset);
                var localPort = ((localPortRaw & 0xFF) << 8) | ((localPortRaw >> 8) & 0xFF);

                var endpoint = $"{address}:{remotePort}";
                if (seen.Add(endpoint))
                {
                    peers.Add(new UdpPeer(localPort, address, remotePort));
                }
            }
        }
        catch
        {
            // Internal export is missing or blocked on this build; Capture() falls back.
        }
        finally
        {
            if (table != IntPtr.Zero)
            {
                try { HeapFree(heap, 0, table); } catch { }
            }
        }

        return peers;
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

    // Internal export used by netstat to read the UDP endpoint table including remote peers.
    // The function allocates the table on the heap passed in; free it with HeapFree.
    [DllImport("iphlpapi.dll", EntryPoint = "InternalGetUdpTable2", SetLastError = true)]
    private static extern uint InternalGetUdpTable2(out IntPtr table, IntPtr heap, bool order);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetProcessHeap();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr HeapFree(IntPtr hHeap, uint dwFlags, IntPtr lpMem);
}
