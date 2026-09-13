using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace ACPScanner;

/// <summary>
/// The engine's exact version string, read from the running game's memory.
///
/// The engine copies PatchVersion out of steam.inf into memory and, when launched by Steam,
/// appends the file-system interface name ("1.1.2.7/Stdio"). Reading the live string gives
/// the exact value the engine itself reports. Confirmed in real scans of the ESK client,
/// where it was read as "1.1.2.6".
///
/// This class once also located the engine's server connection record, using a structure
/// layout from ReHLDS. ReHLDS is a dedicated server and its client-side structures do not
/// match the real engine: real scans found no record while a player was joined. The game
/// server is now established from live UDP traffic instead (GameTraffic).
///
/// Read-only: the process is opened with query and VM-read access and nothing is written.
/// </summary>
public static class LiveEngineState
{
    /// <summary>
    /// The engine's version string, or "" when it could not be read. <paramref name="patchVersion"/>
    /// is the PatchVersion from the game's steam.inf, used to find the string.
    /// </summary>
    public static string ReadVersion(Process process, string patchVersion)
    {
        if (string.IsNullOrWhiteSpace(patchVersion))
        {
            return "";
        }

        ProcessModule? engine = null;
        try
        {
            foreach (ProcessModule module in process.Modules)
            {
                var name = module.ModuleName ?? "";
                if (name.Equals("hw.dll", StringComparison.OrdinalIgnoreCase) || name.Equals("sw.dll", StringComparison.OrdinalIgnoreCase))
                {
                    engine = module;
                    break;
                }
            }
        }
        catch
        {
            return "";
        }

        if (engine is null)
        {
            return "";
        }

        var handle = OpenProcess(ProcessQueryInformation | ProcessVmRead, false, process.Id);
        if (handle == IntPtr.Zero)
        {
            return "";
        }

        try
        {
            var start = ((IntPtr)engine.BaseAddress).ToInt64();
            return FindVersionString(ReadWritableRegions(handle, start, start + engine.ModuleMemorySize), patchVersion);
        }
        catch
        {
            return "";
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    /// <summary>
    /// Finds the version string in memory: PatchVersion as a whole NUL-terminated string,
    /// optionally followed by "/Name". A longer string merely containing the value is ignored.
    /// </summary>
    public static string FindVersionString(IReadOnlyList<(long Address, byte[] Bytes)> regions, string patchVersion)
    {
        if (string.IsNullOrWhiteSpace(patchVersion))
        {
            return "";
        }

        var needle = Encoding.ASCII.GetBytes(patchVersion);
        var plain = "";
        foreach (var (_, bytes) in regions)
        {
            var span = bytes.AsSpan();
            var from = 0;
            while (from < span.Length)
            {
                var hit = span[from..].IndexOf(needle);
                if (hit < 0)
                {
                    break;
                }
                var at = from + hit;
                from = at + 1;
                if (at > 0 && span[at - 1] != 0)
                {
                    continue;
                }

                var end = at + needle.Length;
                if (end < span.Length && span[end] == 0)
                {
                    plain = patchVersion;
                    continue;
                }
                if (end < span.Length && span[end] == (byte)'/')
                {
                    var tail = end + 1;
                    while (tail < span.Length && tail - end <= 16 && IsSuffixChar(span[tail]))
                    {
                        tail++;
                    }
                    if (tail < span.Length && span[tail] == 0 && tail > end + 1)
                    {
                        return Encoding.ASCII.GetString(span[at..tail]);
                    }
                }
            }
        }
        return plain;
    }

    private static bool IsSuffixChar(byte b) => b is >= (byte)'A' and <= (byte)'Z' or >= (byte)'a' and <= (byte)'z' or >= (byte)'0' and <= (byte)'9';

    // ── Memory access ─────────────────────────────────────────────────────────

    private static List<(long Address, byte[] Bytes)> ReadWritableRegions(IntPtr handle, long start, long end)
    {
        var regions = new List<(long, byte[])>();
        var address = start;
        var infoSize = (UIntPtr)Marshal.SizeOf<MemoryBasicInformation>();
        while (address < end && VirtualQueryEx(handle, (IntPtr)address, out var info, infoSize) != UIntPtr.Zero)
        {
            var regionBase = info.BaseAddress.ToInt64();
            var regionSize = (long)info.RegionSize.ToUInt64();
            if (regionSize <= 0)
            {
                break;
            }

            var writable = (info.Protect & (PageReadWrite | PageWriteCopy | PageExecuteReadWrite | PageExecuteWriteCopy)) != 0;
            if (info.State == MemCommit && writable && (info.Protect & PageGuard) == 0 && regionSize <= 64L * 1024 * 1024)
            {
                var from = Math.Max(regionBase, start);
                var to = Math.Min(regionBase + regionSize, end);
                var bytes = ReadBytes(handle, from, (int)(to - from));
                if (bytes is not null)
                {
                    regions.Add((from, bytes));
                }
                else
                {
                    for (var piece = from; piece < to; piece += 0x10000)
                    {
                        var chunk = ReadBytes(handle, piece, (int)Math.Min(0x10000, to - piece));
                        if (chunk is not null)
                        {
                            regions.Add((piece, chunk));
                        }
                    }
                }
            }

            address = regionBase + regionSize;
        }
        return regions;
    }

    private static byte[]? ReadBytes(IntPtr handle, long address, int count)
    {
        if (count <= 0)
        {
            return null;
        }
        var buffer = new byte[count];
        return ReadProcessMemory(handle, (IntPtr)address, buffer, (UIntPtr)(uint)count, out var read) && read.ToUInt64() == (ulong)count ? buffer : null;
    }

    private const uint ProcessQueryInformation = 0x0400;
    private const uint ProcessVmRead = 0x0010;
    private const uint MemCommit = 0x1000;
    private const uint PageReadWrite = 0x04;
    private const uint PageWriteCopy = 0x08;
    private const uint PageExecuteReadWrite = 0x40;
    private const uint PageExecuteWriteCopy = 0x80;
    private const uint PageGuard = 0x100;

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryBasicInformation
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public ushort PartitionId;
        public UIntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern UIntPtr VirtualQueryEx(IntPtr process, IntPtr address, out MemoryBasicInformation info, UIntPtr length);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr process, IntPtr address, byte[] buffer, UIntPtr size, out UIntPtr bytesRead);
}
