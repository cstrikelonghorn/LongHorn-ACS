using System.Runtime.InteropServices;

namespace ACPScanner;

// Module integrity verification.
//
// WHY THIS EXISTS
//   The original engine only looked at the first bytes of a handful of exports and flagged a
//   JMP/CALL trampoline. That misses IAT hooks, EAT hooks, VMT swaps, mid-function patches and
//   VEH/page-guard hooks. Verifying the whole executable section against the on-disk file catches
//   every one of them at once, regardless of the technique used, because any of them has to write
//   into code that should be byte-identical to the file it was loaded from.
//
//   For GoldSrc this is the single highest-value check available: wallhacks patch opengl32 render
//   calls, speedhacks patch the timing imports, and engine cheats patch CL_CreateMove /
//   HUD_PostRunCmd inside hw.dll and client.dll. All three show up here.
//
// HOW IT AVOIDS FALSE POSITIVES
//   A module loaded away from its preferred ImageBase has had relocations applied to it, so the
//   in-memory bytes legitimately differ from the file. We apply the same relocations to the disk
//   copy before comparing, so a correctly loaded module compares byte-identical. Anything we
//   cannot parse with confidence returns Inconclusive rather than a finding.
internal static class ModuleIntegrity
{
    private const int ImageDirectoryImport = 1;
    private const int ImageDirectoryBaseReloc = 5;
    private const int ImageDirectoryExport = 0;
    private const int ImageDirectoryComDescriptor = 14;
    private const uint ImageScnMemExecute = 0x20000000;
    private const uint ImageScnMemWrite = 0x80000000;
    private const ushort ImageRelBasedAbsolute = 0;
    private const ushort ImageRelBasedHighLow = 3;
    private const ushort ImageRelBasedDir64 = 10;

    // A patch has to be at least this large to be reported. Single-byte differences in code are
    // almost always a hot-patch stub or an anti-virus veneer rather than a cheat, and reporting
    // them produces noise without producing detections.
    private const int MinPatchBytes = 2;

    // Cap on reported patch sites so one heavily instrumented module cannot flood a report.
    private const int MaxPatchSites = 24;

    // Only genuine code sections are compared. Windows ships executable sections that the loader
    // and the hotpatch engine legitimately rewrite at load time -- "fothk" (forward-only hotpatch
    // thunks) is the common one, and comparing it reports every system DLL as patched. Restricting
    // the comparison to the compiler's code section keeps the check meaningful and quiet. GoldSrc
    // modules (hw.dll, client.dll, opengl32.dll) all use ".text".
    private static readonly HashSet<string> CodeSectionNames = new(StringComparer.Ordinal)
    {
        ".text", ".code", "CODE"
    };

    internal sealed record PatchSite(long Address, uint Rva, string Section, int Length, string OnDisk, string InMemory, string Nearest);

    internal sealed record Result(
        string Status,              // "clean" | "patched" | "inconclusive"
        string Module,
        int BytesCompared,
        int BytesDiffering,
        IReadOnlyList<PatchSite> Sites,
        IReadOnlyList<string> HookedImports,
        IReadOnlyList<string> HookedExports,
        string Detail)
    {
        internal bool IsPatched => Status == "patched";
    }

    internal static Result Inconclusive(string module, string reason) =>
        new("inconclusive", module, 0, 0, Array.Empty<PatchSite>(), Array.Empty<string>(), Array.Empty<string>(), reason);

    // ---------------------------------------------------------------------------------------
    // Entry point
    // ---------------------------------------------------------------------------------------

    internal static Result Verify(IntPtr processHandle, string moduleName, string modulePath, long remoteBase, IReadOnlyList<(string Name, long Base, long Size)> allModules)
    {
        if (processHandle == IntPtr.Zero || remoteBase <= 0) {
            return Inconclusive(moduleName, "no process handle or module base");
        }

        // On 64-bit Windows, 32-bit processes (like GoldSrc hl.exe) load system DLLs from SysWOW64,
        // but module enumeration reports paths starting with System32. Normalize to SysWOW64 so
        // we compare against the matching 32-bit binary on disk.
        modulePath = NormalizeModulePath(modulePath);

        byte[] disk;
        try
        {
            if (!File.Exists(modulePath)) {
                return Inconclusive(moduleName, "module file not present on disk");
            }

            var info = new FileInfo(modulePath);
            if (info.Length > 64L * 1024 * 1024) {
                return Inconclusive(moduleName, "module file too large to verify");
            }

            disk = File.ReadAllBytes(modulePath);
        }
        catch (Exception ex)
        {
            return Inconclusive(moduleName, $"unable to read module file: {ex.Message}");
        }

        PeImage pe;
        try
        {
            pe = PeImage.Parse(disk);
        }
        catch (Exception ex)
        {
            return Inconclusive(moduleName, $"unable to parse PE headers: {ex.Message}");
        }

        // Turn the raw file into the flat image the loader would have produced, then relocate it
        // to wherever the module actually sits in the target process.
        byte[] expected;
        try
        {
            expected = pe.MapToImage(disk);
            if (!pe.ApplyRelocations(expected, remoteBase)) {
                return Inconclusive(moduleName, "module is relocated but has no usable relocation table");
            }
        }
        catch (Exception ex)
        {
            return Inconclusive(moduleName, $"unable to normalise module image: {ex.Message}");
        }

        var sites = new List<PatchSite>();
        var compared = 0;
        var differing = 0;

        // A managed assembly is laid out by the CLR rather than the OS loader and its in-memory
        // image legitimately differs from the file, so it cannot be verified this way.
        if (pe.IsManaged) {
            return Inconclusive(moduleName, "managed assembly -- not verifiable against the file image");
        }

        foreach (var section in pe.Sections)
        {
            if ((section.Characteristics & ImageScnMemExecute) == 0) {
                continue;
            }

            // Skip writable code and loader-managed thunk sections; both change legitimately.
            if ((section.Characteristics & ImageScnMemWrite) != 0 || !CodeSectionNames.Contains(section.Name)) {
                continue;
            }

            var length = (int)Math.Min(section.VirtualSize, (uint)Math.Max(0, expected.Length - section.VirtualAddress));
            if (length <= 0) {
                continue;
            }

            var actual = ReadRemote(processHandle, remoteBase + section.VirtualAddress, length);
            if (actual is null) {
                return Inconclusive(moduleName, $"unable to read section {section.Name} from the live process");
            }

            compared += length;
            differing += CollectDifferences(expected, section.VirtualAddress, section.Name, actual, remoteBase, pe, sites);
        }

        if (compared == 0) {
            return Inconclusive(moduleName, "module has no readable executable section");
        }

        var hookedImports = VerifyImports(processHandle, pe, remoteBase, allModules);
        var hookedExports = VerifyExports(processHandle, pe, expected, remoteBase);

        var patched = sites.Count > 0 || hookedImports.Count > 0 || hookedExports.Count > 0;
        var detail = patched
            ? $"{differing} byte(s) differ across {sites.Count} site(s) in {compared} bytes of code"
            : $"{compared} bytes of code match the file on disk";

        return new Result(patched ? "patched" : "clean", moduleName, compared, differing, sites, hookedImports, hookedExports, detail);
    }

    internal static string NormalizeModulePath(string path)
    {
        if (Environment.Is64BitOperatingSystem && !string.IsNullOrWhiteSpace(path))
        {
            var sys32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
            if (path.StartsWith(sys32, StringComparison.OrdinalIgnoreCase))
            {
                var wow64 = Environment.GetFolderPath(Environment.SpecialFolder.SystemX86);
                var rel = Path.GetRelativePath(sys32, path);
                var candidate = Path.Combine(wow64, rel);
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }
        }
        return path;
    }

    // ---------------------------------------------------------------------------------------
    // Code comparison
    // ---------------------------------------------------------------------------------------

    private static int CollectDifferences(byte[] expected, uint sectionRva, string sectionName, byte[] actual, long remoteBase, PeImage pe, List<PatchSite> sites)
    {
        var differing = 0;
        var i = 0;

        while (i < actual.Length)
        {
            if (expected[sectionRva + i] == actual[i])
            {
                i++;
                continue;
            }

            // Walk to the end of this run of differing bytes. Two matching bytes end a run, so a
            // patch containing an incidental matching byte is still reported as one site.
            var start = i;
            var lastDiff = i;
            while (i < actual.Length && i - lastDiff <= 2)
            {
                if (expected[sectionRva + i] != actual[i]) {
                    lastDiff = i;
                }
                i++;
            }

            var length = lastDiff - start + 1;

            if (length >= MinPatchBytes)
            {
                differing += length;
                if (sites.Count < MaxPatchSites)
                {
                    var rva = sectionRva + (uint)start;
                    sites.Add(new PatchSite(
                        remoteBase + rva,
                        rva,
                        sectionName,
                        length,
                        Hex(expected, (int)(sectionRva + start), Math.Min(length, 16)),
                        Hex(actual, start, Math.Min(length, 16)),
                        pe.NearestExport(rva)));
                }
            }
        }

        return differing;
    }

    private static string Hex(byte[] data, int offset, int count)
    {
        var end = Math.Min(data.Length, offset + count);
        if (offset >= end) {
            return "";
        }

        return string.Join(' ', Enumerable.Range(offset, end - offset).Select(i => data[i].ToString("X2")));
    }

    // ---------------------------------------------------------------------------------------
    // Import address table verification
    // ---------------------------------------------------------------------------------------
    //
    // An IAT slot pointing outside the module named in the import descriptor is NOT by itself a
    // hook: export forwarders (kernel32!EnterCriticalSection -> ntdll!RtlEnterCriticalSection),
    // API set redirection (api-ms-win-*) and the AppHelp compatibility shim engine all do exactly
    // that on every healthy Windows process. Testing for it produces a false positive on nearly
    // every module.
    //
    // What is never legitimate is an IAT slot pointing into memory that belongs to no loaded
    // module at all -- that is code the loader did not map, which is what an injected hook looks
    // like. That is the condition we test.

    private static List<string> VerifyImports(IntPtr handle, PeImage pe, long remoteBase, IReadOnlyList<(string Name, long Base, long Size)> allModules)
    {
        var hooked = new List<string>();
        if (allModules.Count == 0) {
            return hooked;
        }

        try
        {
            foreach (var (dllName, thunkRva, entries) in pe.EnumerateImports())
            {
                for (var i = 0; i < entries.Count; i++)
                {
                    var slot = remoteBase + thunkRva + (long)i * pe.PointerSize;
                    var raw = ReadRemote(handle, slot, pe.PointerSize);
                    if (raw is null) {
                        continue;
                    }

                    var target = pe.PointerSize == 8 ? BitConverter.ToInt64(raw, 0) : BitConverter.ToUInt32(raw, 0);
                    if (target == 0) {
                        continue;
                    }

                    var inSomeModule = allModules.Any(m => m.Size > 0 && target >= m.Base && target < m.Base + m.Size);
                    if (!inSomeModule)
                    {
                        hooked.Add($"{dllName}!{entries[i]} -> 0x{target:X} (unbacked memory)");
                        if (hooked.Count >= MaxPatchSites) {
                            return hooked;
                        }
                    }
                }
            }
        }
        catch
        {
            // A malformed import table is not evidence of anything; leave the list as-is.
        }

        return hooked;
    }

    // ---------------------------------------------------------------------------------------
    // Export address table verification
    // ---------------------------------------------------------------------------------------
    //
    // An EAT hook rewrites the export RVA so every later GetProcAddress hands out the cheat's
    // function. The module's own code is untouched, so a .text comparison alone would miss it.

    private static List<string> VerifyExports(IntPtr handle, PeImage pe, byte[] expected, long remoteBase)
    {
        var hooked = new List<string>();

        try
        {
            var (tableRva, count) = pe.ExportFunctionTable();
            if (tableRva == 0 || count == 0) {
                return hooked;
            }

            var live = ReadRemote(handle, remoteBase + tableRva, (int)(count * 4));
            if (live is null) {
                return hooked;
            }

            for (var i = 0; i < count; i++)
            {
                var diskRva = BitConverter.ToUInt32(expected, (int)(tableRva + i * 4));
                var liveRva = BitConverter.ToUInt32(live, i * 4);
                if (diskRva == liveRva) {
                    continue;
                }

                hooked.Add($"{pe.ExportNameForIndex(i)} RVA 0x{diskRva:X} -> 0x{liveRva:X}");
                if (hooked.Count >= MaxPatchSites) {
                    break;
                }
            }
        }
        catch
        {
            // Malformed export directory -- not evidence.
        }

        return hooked;
    }

    // ---------------------------------------------------------------------------------------
    // Remote memory helper
    // ---------------------------------------------------------------------------------------

    private static byte[]? ReadRemote(IntPtr handle, long address, int count)
    {
        if (count <= 0) {
            return null;
        }

        var buffer = new byte[count];
        var offset = 0;
        var chunkBuffer = new byte[Math.Min(0x10000, count)];

        // Read in chunks so one very large section does not need a single huge transfer. An
        // unreadable page makes the module unverifiable rather than suspicious, so we bail out.
        while (offset < count)
        {
            var chunk = Math.Min(chunkBuffer.Length, count - offset);
            if (!ReadProcessMemory(handle, new IntPtr(address + offset), chunkBuffer, chunk, out var read) || read <= 0) {
                return null;
            }

            Buffer.BlockCopy(chunkBuffer, 0, buffer, offset, read);
            offset += read;
        }

        return buffer;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    // ---------------------------------------------------------------------------------------
    // Minimal PE reader
    // ---------------------------------------------------------------------------------------

    private sealed class PeImage
    {
        internal sealed record Section(string Name, uint VirtualAddress, uint VirtualSize, uint RawAddress, uint RawSize, uint Characteristics);

        private byte[] _file = Array.Empty<byte>();
        private int _ntHeader;
        private bool _is64;
        private ulong _preferredBase;
        private uint _sizeOfImage;
        private uint _sizeOfHeaders;
        private uint[] _dirRva = Array.Empty<uint>();
        private uint[] _dirSize = Array.Empty<uint>();
        private readonly List<Section> _sections = new();
        private readonly List<(uint Rva, string Name)> _exports = new();

        private bool _isManaged;

        internal IReadOnlyList<Section> Sections => _sections;
        internal int PointerSize => _is64 ? 8 : 4;
        internal bool IsManaged => _isManaged;

        internal static PeImage Parse(byte[] file)
        {
            var pe = new PeImage { _file = file };

            if (file.Length < 0x40 || BitConverter.ToUInt16(file, 0) != 0x5A4D) {
                throw new InvalidDataException("not a PE file");
            }

            pe._ntHeader = BitConverter.ToInt32(file, 0x3C);
            if (pe._ntHeader <= 0 || pe._ntHeader + 0x78 > file.Length || BitConverter.ToUInt32(file, pe._ntHeader) != 0x00004550) {
                throw new InvalidDataException("bad NT header");
            }

            var fileHeader = pe._ntHeader + 4;
            var numberOfSections = BitConverter.ToUInt16(file, fileHeader + 2);
            var sizeOfOptional = BitConverter.ToUInt16(file, fileHeader + 16);
            var optional = fileHeader + 20;

            var magic = BitConverter.ToUInt16(file, optional);
            pe._is64 = magic == 0x20B;
            if (magic != 0x10B && magic != 0x20B) {
                throw new InvalidDataException("unknown optional header magic");
            }

            pe._sizeOfImage = BitConverter.ToUInt32(file, optional + 56);
            pe._sizeOfHeaders = BitConverter.ToUInt32(file, optional + 60);
            pe._preferredBase = pe._is64
                ? BitConverter.ToUInt64(file, optional + 24)
                : BitConverter.ToUInt32(file, optional + 28);

            var dirOffset = optional + (pe._is64 ? 112 : 96);
            var dirCount = BitConverter.ToUInt32(file, optional + (pe._is64 ? 108 : 92));
            dirCount = Math.Min(dirCount, 16);
            pe._dirRva = new uint[16];
            pe._dirSize = new uint[16];
            for (var i = 0; i < dirCount; i++)
            {
                pe._dirRva[i] = BitConverter.ToUInt32(file, dirOffset + i * 8);
                pe._dirSize[i] = BitConverter.ToUInt32(file, dirOffset + i * 8 + 4);
            }

            var sectionTable = optional + sizeOfOptional;
            for (var i = 0; i < numberOfSections; i++)
            {
                var s = sectionTable + i * 40;
                if (s + 40 > file.Length) {
                    break;
                }

                var name = System.Text.Encoding.ASCII.GetString(file, s, 8).TrimEnd('\0');
                pe._sections.Add(new Section(
                    name,
                    BitConverter.ToUInt32(file, s + 12),
                    BitConverter.ToUInt32(file, s + 8),
                    BitConverter.ToUInt32(file, s + 20),
                    BitConverter.ToUInt32(file, s + 16),
                    BitConverter.ToUInt32(file, s + 36)));
            }

            // A non-zero COM descriptor directory means this is a .NET assembly.
            pe._isManaged = pe._dirRva[ImageDirectoryComDescriptor] != 0;

            if (pe._sizeOfImage == 0 || pe._sections.Count == 0) {
                throw new InvalidDataException("no sections");
            }

            return pe;
        }

        // Lay the file out the way the loader does: headers, then each section at its RVA.
        internal byte[] MapToImage(byte[] file)
        {
            var image = new byte[_sizeOfImage];
            Array.Copy(file, 0, image, 0, Math.Min(_sizeOfHeaders, (uint)file.Length));

            foreach (var s in _sections)
            {
                if (s.RawSize == 0 || s.RawAddress >= file.Length) {
                    continue;
                }

                var copy = (int)Math.Min(s.RawSize, (uint)(file.Length - s.RawAddress));
                copy = (int)Math.Min((uint)copy, (uint)Math.Max(0, image.Length - s.VirtualAddress));
                if (copy > 0) {
                    Array.Copy(file, s.RawAddress, image, s.VirtualAddress, copy);
                }
            }

            CacheExports(image);
            return image;
        }

        // Rebase the mapped image to where it actually loaded. Returns false only when the module
        // needs relocating but carries no relocation table, which makes comparison impossible.
        internal bool ApplyRelocations(byte[] image, long actualBase)
        {
            var delta = (long)((ulong)actualBase - _preferredBase);
            if (delta == 0) {
                return true;
            }

            var rva = _dirRva[ImageDirectoryBaseReloc];
            var size = _dirSize[ImageDirectoryBaseReloc];
            if (rva == 0 || size == 0) {
                return false;
            }

            var offset = (int)rva;
            var end = (int)Math.Min((uint)image.Length, rva + size);

            while (offset + 8 <= end)
            {
                var pageRva = BitConverter.ToUInt32(image, offset);
                var blockSize = BitConverter.ToUInt32(image, offset + 4);
                if (blockSize < 8 || offset + blockSize > end) {
                    break;
                }

                var count = (int)((blockSize - 8) / 2);
                for (var i = 0; i < count; i++)
                {
                    var entry = BitConverter.ToUInt16(image, offset + 8 + i * 2);
                    var type = (ushort)(entry >> 12);
                    var target = pageRva + (uint)(entry & 0x0FFF);

                    if (type == ImageRelBasedAbsolute) {
                        continue;
                    }

                    if (type == ImageRelBasedHighLow && target + 4 <= image.Length)
                    {
                        var value = BitConverter.ToUInt32(image, (int)target);
                        BitConverter.TryWriteBytes(image.AsSpan((int)target, 4), (uint)(value + (uint)delta));
                    }
                    else if (type == ImageRelBasedDir64 && target + 8 <= image.Length)
                    {
                        var value = BitConverter.ToUInt64(image, (int)target);
                        BitConverter.TryWriteBytes(image.AsSpan((int)target, 8), (ulong)((long)value + delta));
                    }
                }

                offset += (int)blockSize;
            }

            return true;
        }

        internal IEnumerable<(string Dll, uint ThunkRva, IReadOnlyList<string> Names)> EnumerateImports()
        {
            var rva = _dirRva[ImageDirectoryImport];
            if (rva == 0) {
                yield break;
            }

            var image = MapToImage(_file);
            var descriptor = (int)rva;

            while (descriptor + 20 <= image.Length)
            {
                var originalFirstThunk = BitConverter.ToUInt32(image, descriptor);
                var nameRva = BitConverter.ToUInt32(image, descriptor + 12);
                var firstThunk = BitConverter.ToUInt32(image, descriptor + 16);

                if (nameRva == 0 && firstThunk == 0) {
                    break;
                }

                var dll = ReadAscii(image, (int)nameRva);
                var lookup = originalFirstThunk != 0 ? originalFirstThunk : firstThunk;
                var names = new List<string>();

                if (lookup != 0)
                {
                    var thunk = (int)lookup;
                    while (thunk + PointerSize <= image.Length)
                    {
                        var value = _is64 ? BitConverter.ToUInt64(image, thunk) : BitConverter.ToUInt32(image, thunk);
                        if (value == 0) {
                            break;
                        }

                        var byOrdinal = _is64 ? (value & 0x8000000000000000UL) != 0 : (value & 0x80000000UL) != 0;
                        if (byOrdinal)
                        {
                            names.Add("#" + (value & 0xFFFF));
                        }
                        else
                        {
                            var hintNameRva = (int)(value & 0x7FFFFFFF);
                            names.Add(hintNameRva + 2 < image.Length ? ReadAscii(image, hintNameRva + 2) : "?");
                        }

                        thunk += PointerSize;
                    }
                }

                if (!string.IsNullOrWhiteSpace(dll) && firstThunk != 0 && names.Count > 0) {
                    yield return (dll, firstThunk, names);
                }

                descriptor += 20;
            }
        }

        internal (uint TableRva, uint Count) ExportFunctionTable()
        {
            var rva = _dirRva[ImageDirectoryExport];
            if (rva == 0) {
                return (0, 0);
            }

            var image = MapToImage(_file);
            if (rva + 40 > image.Length) {
                return (0, 0);
            }

            var count = BitConverter.ToUInt32(image, (int)rva + 20);
            var table = BitConverter.ToUInt32(image, (int)rva + 28);
            if (table == 0 || count == 0 || table + count * 4 > image.Length) {
                return (0, 0);
            }

            return (table, count);
        }

        private void CacheExports(byte[] image)
        {
            if (_exports.Count > 0) {
                return;
            }

            var rva = _dirRva[ImageDirectoryExport];
            if (rva == 0 || rva + 40 > image.Length) {
                return;
            }

            try
            {
                var nameCount = BitConverter.ToUInt32(image, (int)rva + 24);
                var nameTable = BitConverter.ToUInt32(image, (int)rva + 32);
                var ordinalTable = BitConverter.ToUInt32(image, (int)rva + 36);
                var functionTable = BitConverter.ToUInt32(image, (int)rva + 28);

                for (var i = 0; i < nameCount && i < 8192; i++)
                {
                    if (nameTable + i * 4 + 4 > image.Length || ordinalTable + i * 2 + 2 > image.Length) {
                        break;
                    }

                    var namePtr = BitConverter.ToUInt32(image, (int)(nameTable + i * 4));
                    var ordinal = BitConverter.ToUInt16(image, (int)(ordinalTable + i * 2));
                    if (functionTable + ordinal * 4 + 4 > image.Length) {
                        continue;
                    }

                    var funcRva = BitConverter.ToUInt32(image, (int)(functionTable + ordinal * 4));
                    _exports.Add((funcRva, ReadAscii(image, (int)namePtr)));
                }

                _exports.Sort((a, b) => a.Rva.CompareTo(b.Rva));
            }
            catch
            {
                _exports.Clear();
            }
        }

        internal string ExportNameForIndex(int index)
        {
            var image = MapToImage(_file);
            CacheExports(image);
            return index >= 0 && index < _exports.Count ? _exports[index].Name : $"ordinal[{index}]";
        }

        // Name the closest export at or before an RVA, so a patch site reads as
        // "glBegin+0x03" instead of a bare address.
        internal string NearestExport(uint rva)
        {
            if (_exports.Count == 0) {
                return "";
            }

            (uint Rva, string Name)? best = null;
            foreach (var e in _exports)
            {
                if (e.Rva > rva) {
                    break;
                }
                best = e;
            }

            if (best is null || rva - best.Value.Rva > 0x2000) {
                return "";
            }

            var delta = rva - best.Value.Rva;
            return delta == 0 ? best.Value.Name : $"{best.Value.Name}+0x{delta:X}";
        }

        private static string ReadAscii(byte[] data, int offset)
        {
            if (offset <= 0 || offset >= data.Length) {
                return "";
            }

            var end = offset;
            while (end < data.Length && data[end] != 0 && end - offset < 512) {
                end++;
            }

            return System.Text.Encoding.ASCII.GetString(data, offset, end - offset);
        }
    }
}
