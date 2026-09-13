using System.Net;
using System.Net.Sockets;
using System.Text;

namespace ACPScanner;

/// <summary>
/// Valve Server Queries protocol implementation (A2S_INFO) according to the official specification:
/// https://developer.valvesoftware.com/wiki/Server_queries
///
/// Runs entirely in standard user space using standard UDP sockets. Zero elevation required.
/// Supports both modern Source/ReHLDS ('I' / 0x49) and legacy GoldSrc ('m' / 0x6D) responses,
/// as well as challenge negotiation ('A' / 0x41).
/// </summary>
public static class ValveA2S
{
    public sealed record ServerInfo(
        bool Success,
        string Address,
        string Name,
        string Map,
        string Folder,
        string Game,
        short Id,
        int Players,
        int MaxPlayers,
        int Bots,
        string ServerType,
        string Environment,
        bool Visibility,
        bool VacSecured,
        int Protocol,
        string Version,
        string Error = "")
    {
        public static ServerInfo Failed(string address, string error) =>
            new(false, address, "", "", "", "", 0, 0, 0, 0, "", "", false, false, 0, "", error);
    }

    private static readonly byte[] RequestHeader = [0xFF, 0xFF, 0xFF, 0xFF, 0x54]; // -1 + 'T'
    private static readonly byte[] QueryString = Encoding.ASCII.GetBytes("Source Engine Query\0");

    /// <summary>
    /// Builds an A2S_INFO query packet, optionally appending a 4-byte challenge.
    /// </summary>
    private static byte[] BuildPacket(ReadOnlySpan<byte> challenge)
    {
        var packet = new byte[RequestHeader.Length + QueryString.Length + challenge.Length];
        RequestHeader.CopyTo(packet, 0);
        QueryString.CopyTo(packet, RequestHeader.Length);
        if (!challenge.IsEmpty)
        {
            challenge.CopyTo(packet.AsSpan(RequestHeader.Length + QueryString.Length));
        }
        return packet;
    }

    /// <summary>
    /// Parses an IP:Port string or hostname:port string into an IPEndPoint.
    /// </summary>
    public static bool TryParseEndpoint(string address, out IPEndPoint? endPoint)
    {
        endPoint = null;
        if (string.IsNullOrWhiteSpace(address)) return false;

        var lastColon = address.LastIndexOf(':');
        if (lastColon <= 0 || lastColon >= address.Length - 1) return false;

        var host = address[..lastColon].Trim();
        var portStr = address[(lastColon + 1)..].Trim();
        if (!int.TryParse(portStr, out var port) || port < 1 || port > 65535) return false;

        if (IPAddress.TryParse(host, out var ip))
        {
            endPoint = new IPEndPoint(ip, port);
            return true;
        }

        try
        {
            var addresses = Dns.GetHostAddresses(host);
            var v4 = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
            if (v4 is not null)
            {
                endPoint = new IPEndPoint(v4, port);
                return true;
            }
        }
        catch
        {
            // DNS resolution failure
        }

        return false;
    }

    /// <summary>
    /// Sends an A2S_INFO query to the specified address and parses the response.
    /// </summary>
    public static ServerInfo Query(string address, int timeoutMs = 1500)
    {
        if (!TryParseEndpoint(address, out var endPoint) || endPoint is null)
        {
            return ServerInfo.Failed(address, "Invalid server address format or hostname could not be resolved");
        }

        try
        {
            using var client = new UdpClient(AddressFamily.InterNetwork);
            client.Client.ReceiveTimeout = timeoutMs;
            client.Client.SendTimeout = timeoutMs;

            var packet = BuildPacket(ReadOnlySpan<byte>.Empty);

            // Up to 2 attempts: attempt 0 may receive a challenge response ('A'), which is answered in attempt 1.
            for (var attempt = 0; attempt < 2; attempt++)
            {
                client.Send(packet, packet.Length, endPoint);

                IPEndPoint? remote = null;
                byte[] response;
                try
                {
                    response = client.Receive(ref remote);
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut)
                {
                    return ServerInfo.Failed(address, "Server query timed out (no response)");
                }
                catch (Exception ex)
                {
                    return ServerInfo.Failed(address, $"Socket error: {ex.Message}");
                }

                // Minimum valid header is 5 bytes: 4 bytes 0xFF and 1 byte header
                if (response.Length < 5 || response[0] != 0xFF || response[1] != 0xFF || response[2] != 0xFF || response[3] != 0xFF)
                {
                    return ServerInfo.Failed(address, "Invalid response header from server");
                }

                var header = response[4];

                // Challenge response 'A' (0x41)
                if (header == 0x41 && response.Length >= 9)
                {
                    packet = BuildPacket(response.AsSpan(5, 4));
                    continue;
                }

                // Modern Source / ReHLDS response 'I' (0x49)
                if (header == 0x49)
                {
                    return ParseSourceInfo(address, response);
                }

                // Legacy GoldSrc response 'm' (0x6D)
                if (header == 0x6D)
                {
                    return ParseGoldSrcInfo(address, response);
                }

                return ServerInfo.Failed(address, $"Unsupported response type 0x{header:X2}");
            }

            return ServerInfo.Failed(address, "Challenge negotiation failed");
        }
        catch (Exception ex)
        {
            return ServerInfo.Failed(address, $"Query error: {ex.Message}");
        }
    }

    private static ServerInfo ParseSourceInfo(string address, byte[] data)
    {
        try
        {
            var offset = 5;
            if (offset >= data.Length) return ServerInfo.Failed(address, "Truncated A2S_INFO payload");

            var protocol = (int)data[offset++];
            var name = ReadNullTerminatedString(data, ref offset);
            var map = ReadNullTerminatedString(data, ref offset);
            var folder = ReadNullTerminatedString(data, ref offset);
            var game = ReadNullTerminatedString(data, ref offset);

            var id = ReadInt16(data, ref offset);
            var players = offset < data.Length ? (int)data[offset++] : 0;
            var maxPlayers = offset < data.Length ? (int)data[offset++] : 0;
            var bots = offset < data.Length ? (int)data[offset++] : 0;

            var serverTypeChar = offset < data.Length ? (char)data[offset++] : 'd';
            var serverType = serverTypeChar switch
            {
                'd' or 'D' => "Dedicated",
                'l' or 'L' => "Listen",
                'p' or 'P' => "Proxy",
                _ => "Dedicated"
            };

            var envChar = offset < data.Length ? (char)data[offset++] : 'l';
            var environment = envChar switch
            {
                'l' or 'L' => "Linux",
                'w' or 'W' => "Windows",
                'm' or 'M' or 'o' or 'O' => "Mac",
                _ => "Unknown"
            };

            var visibility = offset < data.Length && data[offset++] != 0;
            var vac = offset < data.Length && data[offset++] != 0;

            var version = "";
            if (offset < data.Length)
            {
                version = ReadNullTerminatedString(data, ref offset);
            }

            return new ServerInfo(
                Success: true,
                Address: address,
                Name: name,
                Map: map,
                Folder: folder,
                Game: game,
                Id: id,
                Players: players,
                MaxPlayers: maxPlayers,
                Bots: bots,
                ServerType: serverType,
                Environment: environment,
                Visibility: visibility,
                VacSecured: vac,
                Protocol: protocol,
                Version: version);
        }
        catch (Exception ex)
        {
            return ServerInfo.Failed(address, $"Failed to parse A2S_INFO response: {ex.Message}");
        }
    }

    private static ServerInfo ParseGoldSrcInfo(string address, byte[] data)
    {
        try
        {
            var offset = 5;
            if (offset >= data.Length) return ServerInfo.Failed(address, "Truncated GoldSrc info payload");

            var serverAddr = ReadNullTerminatedString(data, ref offset);
            var name = ReadNullTerminatedString(data, ref offset);
            var map = ReadNullTerminatedString(data, ref offset);
            var folder = ReadNullTerminatedString(data, ref offset);
            var game = ReadNullTerminatedString(data, ref offset);

            var players = offset < data.Length ? (int)data[offset++] : 0;
            var maxPlayers = offset < data.Length ? (int)data[offset++] : 0;
            var protocol = offset < data.Length ? (int)data[offset++] : 0;

            var serverTypeChar = offset < data.Length ? (char)data[offset++] : 'd';
            var serverType = serverTypeChar switch
            {
                'd' or 'D' => "Dedicated",
                'l' or 'L' => "Listen",
                'p' or 'P' => "Proxy",
                _ => "Dedicated"
            };

            var envChar = offset < data.Length ? (char)data[offset++] : 'l';
            var environment = envChar switch
            {
                'l' or 'L' => "Linux",
                'w' or 'W' => "Windows",
                'm' or 'M' or 'o' or 'O' => "Mac",
                _ => "Unknown"
            };

            var visibility = offset < data.Length && data[offset++] != 0;
            var isMod = offset < data.Length && data[offset++] != 0;

            if (isMod)
            {
                // Mod info fields
                ReadNullTerminatedString(data, ref offset); // mod url info
                ReadNullTerminatedString(data, ref offset); // mod url dl
                if (offset < data.Length) offset++;         // null byte
                if (offset + 4 <= data.Length) offset += 4; // mod version
                if (offset + 4 <= data.Length) offset += 4; // mod size
                if (offset < data.Length) offset++;         // svonly
                if (offset < data.Length) offset++;         // cldll
            }

            var vac = offset < data.Length && data[offset++] != 0;
            var bots = offset < data.Length ? (int)data[offset++] : 0;

            return new ServerInfo(
                Success: true,
                Address: !string.IsNullOrWhiteSpace(serverAddr) ? serverAddr : address,
                Name: name,
                Map: map,
                Folder: folder,
                Game: game,
                Id: 10,
                Players: players,
                MaxPlayers: maxPlayers,
                Bots: bots,
                ServerType: serverType,
                Environment: environment,
                Visibility: visibility,
                VacSecured: vac,
                Protocol: protocol,
                Version: "");
        }
        catch (Exception ex)
        {
            return ServerInfo.Failed(address, $"Failed to parse GoldSrc info response: {ex.Message}");
        }
    }

    private static string ReadNullTerminatedString(byte[] data, ref int offset)
    {
        var start = offset;
        while (offset < data.Length && data[offset] != 0)
        {
            offset++;
        }
        var length = Math.Min(offset, data.Length) - start;
        var text = Encoding.UTF8.GetString(data, start, length);
        if (offset < data.Length)
        {
            offset++; // Skip null terminator
        }
        return text;
    }

    private static short ReadInt16(byte[] data, ref int offset)
    {
        if (offset + 2 > data.Length) return 0;
        var val = (short)(data[offset] | (data[offset + 1] << 8));
        offset += 2;
        return val;
    }
}

