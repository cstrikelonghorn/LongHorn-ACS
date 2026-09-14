using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace ACPScanner;

// Probes for cheats that never inject anything into the game.
//
// WHY THIS EXISTS
//   Everything the original engine looked at -- loaded modules, files in the game folder, inline
//   hooks -- assumes the cheat put something inside hl.exe. An external cheat does not. It opens
//   a handle, reads memory from outside, and draws its ESP in its own click-through window. It
//   loads no module, patches no code and drops no file in the game directory, so the entire
//   original surface saw nothing.
//
//   The three probes here cover that class:
//     - who holds a read/write handle to the game process
//     - threads running from addresses that belong to no module (manual-map payloads)
//     - click-through topmost windows sitting over the game (overlay ESP)
internal static class SystemProbe
{
    internal sealed record HandleHolder(int ProcessId, string ProcessName, string ProcessPath, string Access);
    internal sealed record ForeignThread(int ThreadId, long StartAddress, string Region);
    internal sealed record OverlayWindow(int ProcessId, string ProcessName, string Title, string Bounds, string Styles);

    // ---------------------------------------------------------------------------------------
    // 1. Who else holds a handle to the game?
    // ---------------------------------------------------------------------------------------
    //
    // Enumerate every handle on the system, find the ones whose kernel object is the same object
    // our own handle to the game points at, and report the processes holding read or write access.
    // A process holding PROCESS_VM_READ on hl.exe that is not Steam, the OS or the game itself is
    // reading the game's memory from outside -- the defining behaviour of an external cheat.

    internal static List<HandleHolder> FindHandleHolders(int targetPid, IntPtr ownHandleToTarget, out string? note)
    {
        note = null;
        var holders = new List<HandleHolder>();

        try
        {
            var queried = QuerySystemHandles(out var error);
            if (queried is null)
            {
                note = $"Handle enumeration unavailable: {error}. Run ACS as administrator for external-cheat coverage.";
                return holders;
            }

            var buffer = queried.Value;
            var selfPid = Process.GetCurrentProcess().Id;
            var entrySize = IntPtr.Size == 8 ? 40 : 28;
            var count = (long)Marshal.ReadIntPtr(buffer, 0);
            var start = IntPtr.Size == 8 ? 16 : 8;

            // Windows redacts the kernel Object pointer in this table for callers that are not
            // elevated, so matching on the object address only works with administrator rights.
            // Instead, learn the object TYPE index of a process handle from our own handle to the
            // game -- that index varies between OS builds, so it has to be discovered, not assumed
            // -- then identify candidates by duplicating them and asking which process they name.
            ushort processTypeIndex = 0;
            IntPtr targetObject = IntPtr.Zero;
            var objectPointersVisible = false;

            for (long i = 0; i < count; i++)
            {
                var p = IntPtr.Add(buffer, (int)(start + i * entrySize));
                var pid = (int)(long)Marshal.ReadIntPtr(p, IntPtr.Size);
                var handle = Marshal.ReadIntPtr(p, IntPtr.Size * 2);

                if (pid == selfPid && handle == ownHandleToTarget)
                {
                    targetObject = Marshal.ReadIntPtr(p, 0);
                    processTypeIndex = (ushort)Marshal.ReadInt16(p, IntPtr.Size * 3 + 6);
                    objectPointersVisible = targetObject != IntPtr.Zero;
                    break;
                }
            }

            if (processTypeIndex == 0)
            {
                note = "Handle enumeration could not locate this scan's own handle; external-handle check skipped.";
                Marshal.FreeHGlobal(buffer);
                return holders;
            }

            var seen = new HashSet<int>();
            var holderHandles = new Dictionary<int, IntPtr>();

            try
            {
                for (long i = 0; i < count; i++)
                {
                    var p = IntPtr.Add(buffer, (int)(start + i * entrySize));

                    if (objectPointersVisible)
                    {
                        if (Marshal.ReadIntPtr(p, 0) != targetObject) {
                            continue;
                        }
                    }
                    else if ((ushort)Marshal.ReadInt16(p, IntPtr.Size * 3 + 6) != processTypeIndex)
                    {
                        continue;
                    }

                    var pid = (int)(long)Marshal.ReadIntPtr(p, IntPtr.Size);
                    var access = (uint)Marshal.ReadInt32(p, IntPtr.Size * 3);

                    // Only interesting if the holder can actually read or modify the game.
                    var rights = DescribeAccess(access);
                    if (rights.Length == 0 || pid == selfPid || pid == targetPid || pid <= 4) {
                        continue;
                    }

                    if (seen.Contains(pid)) {
                        continue;
                    }

                    if (!objectPointersVisible)
                    {
                        // Confirm this handle really names the game before reporting the holder.
                        if (!holderHandles.TryGetValue(pid, out var holder))
                        {
                            holder = OpenProcess(ProcessDupHandle, false, pid);
                            holderHandles[pid] = holder;
                        }

                        if (holder == IntPtr.Zero) {
                            continue;   // Protected or higher-integrity process; nothing we can do.
                        }

                        var raw = Marshal.ReadIntPtr(p, IntPtr.Size * 2);
                        // Ask for query rights on the copy. External memory readers open the game
                        // with VM_READ alone, and a copy with only that access cannot answer
                        // GetProcessId - so those holders, the ones this check exists for, used to
                        // be skipped. Fall back to the handle's own access if query is refused.
                        if (!DuplicateHandle(holder, raw, GetCurrentProcess(), out var dup, ProcessQueryLimitedInformation, false, 0)
                            && !DuplicateHandle(holder, raw, GetCurrentProcess(), out dup, 0, false, DuplicateSameAccess)) {
                            continue;
                        }

                        var named = GetProcessId(dup);
                        CloseHandle(dup);

                        if (named != targetPid) {
                            continue;
                        }
                    }

                    if (!seen.Add(pid)) {
                        continue;
                    }

                    var (name, path) = DescribeProcess(pid);
                    holders.Add(new HandleHolder(pid, name, path, rights));
                }
            }
            finally
            {
                foreach (var h in holderHandles.Values)
                {
                    if (h != IntPtr.Zero) { CloseHandle(h); }
                }

                Marshal.FreeHGlobal(buffer);
            }
        }
        catch (Exception ex)
        {
            note = $"Handle enumeration failed: {ex.Message}";
        }

        return holders;
    }

    private static string DescribeAccess(uint access)
    {
        const uint VmRead = 0x0010, VmWrite = 0x0020, VmOperation = 0x0008, AllAccess = 0x1F0FFF;

        var parts = new List<string>();
        if ((access & AllAccess) == AllAccess) { return "PROCESS_ALL_ACCESS"; }
        if ((access & VmRead) != 0) { parts.Add("VM_READ"); }
        if ((access & VmWrite) != 0) { parts.Add("VM_WRITE"); }
        if ((access & VmOperation) != 0) { parts.Add("VM_OPERATION"); }

        return string.Join("|", parts);
    }

    private static IntPtr? QuerySystemHandles(out string error)
    {
        const int SystemExtendedHandleInformation = 64;
        const int StatusInfoLengthMismatch = unchecked((int)0xC0000004);

        error = "";
        var size = 1 << 20;

        for (var attempt = 0; attempt < 12; attempt++)
        {
            var buffer = Marshal.AllocHGlobal(size);
            var status = NtQuerySystemInformation(SystemExtendedHandleInformation, buffer, size, out var needed);

            if (status == 0) {
                return buffer;
            }

            Marshal.FreeHGlobal(buffer);

            if (status != StatusInfoLengthMismatch)
            {
                error = $"NTSTATUS 0x{status:X8}";
                return null;
            }

            size = Math.Max(size * 2, needed + 0x10000);
        }

        error = "handle table kept growing between queries";
        return null;
    }

    private static (string Name, string Path) DescribeProcess(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            // QueryFullProcessImageName also works for 64-bit processes from 32-bit ACS.
            var path = ModuleIntegrity.ProcessImagePath(pid);
            if (path == "")
            {
                try { path = p.MainModule?.FileName ?? ""; }
                catch { path = ""; }
            }
            return (p.ProcessName, path);
        }
        catch
        {
            return ($"pid {pid}", "");
        }
    }

    // ---------------------------------------------------------------------------------------
    // 2. Threads running from nowhere
    // ---------------------------------------------------------------------------------------
    //
    // A thread whose Win32 start address belongs to no module may be manually mapped code, but
    // runtime-generated code and instrumentation can also produce this shape. The caller treats
    // it as review evidence until another detector corroborates it.

    internal static List<ForeignThread> FindForeignThreads(Process target, IReadOnlyList<(string Name, long Base, long Size)> modules, out string? note)
    {
        note = null;
        var found = new List<ForeignThread>();

        try
        {
            foreach (ProcessThread thread in target.Threads)
            {
                var handle = OpenThread(0x0040, false, thread.Id);   // THREAD_QUERY_INFORMATION
                if (handle == IntPtr.Zero) {
                    continue;
                }

                try
                {
                    var start = IntPtr.Zero;
                    var status = NtQueryInformationThread(handle, 9 /* ThreadQuerySetWin32StartAddress */,
                        ref start, IntPtr.Size, IntPtr.Zero);

                    if (status != 0 || start == IntPtr.Zero) {
                        continue;
                    }

                    var address = start.ToInt64();
                    var owner = modules.FirstOrDefault(m => m.Size > 0 && address >= m.Base && address < m.Base + m.Size);
                    if (owner.Name is not null) {
                        continue;
                    }

                    found.Add(new ForeignThread(thread.Id, address, "outside every mapped module"));
                }
                finally
                {
                    CloseHandle(handle);
                }
            }
        }
        catch (Exception ex)
        {
            note = $"Thread start-address scan failed: {ex.Message}";
        }

        return found;
    }

    // ---------------------------------------------------------------------------------------
    // 3. Overlay windows
    // ---------------------------------------------------------------------------------------
    //
    // An external ESP draws into a layered, click-through, always-on-top window positioned over
    // the game. Legitimate overlays exist too (Steam, Discord, RTSS), so this is review evidence
    // that names the owning process rather than a verdict on its own.

    internal static List<OverlayWindow> FindOverlayWindows(int gamePid, Rect gameRect)
    {
        var results = new List<OverlayWindow>();

        EnumWindows((hwnd, _) =>
        {
            try
            {
                if (!IsWindowVisible(hwnd)) {
                    return true;
                }

                var exStyle = (long)GetWindowLongPtr(hwnd, -20);   // GWL_EXSTYLE
                const long Layered = 0x00080000, Transparent = 0x00000020, TopMost = 0x00000008;

                // Click-through + layered is the overlay signature; a normal window is neither.
                if ((exStyle & Layered) == 0 || (exStyle & Transparent) == 0) {
                    return true;
                }

                if (!GetWindowRect(hwnd, out var rect)) {
                    return true;
                }

                if (rect.Right <= rect.Left || rect.Bottom <= rect.Top) {
                    return true;
                }

                var intersects = rect.Left < gameRect.Right && rect.Right > gameRect.Left
                    && rect.Top < gameRect.Bottom && rect.Bottom > gameRect.Top;
                if (!intersects) {
                    return true;
                }

                GetWindowThreadProcessId(hwnd, out var pid);
                if (pid == gamePid || pid == 0) {
                    return true;
                }

                var title = new StringBuilder(256);
                GetWindowText(hwnd, title, title.Capacity);

                var styles = "layered|transparent" + ((exStyle & TopMost) != 0 ? "|topmost" : "");
                var (name, _) = DescribeProcess((int)pid);

                results.Add(new OverlayWindow((int)pid, name, title.ToString(),
                    $"{rect.Left},{rect.Top} {rect.Right - rect.Left}x{rect.Bottom - rect.Top}", styles));
            }
            catch
            {
                // A window that vanishes mid-enumeration is not evidence.
            }

            return true;
        }, IntPtr.Zero);

        return results;
    }

    // ---------------------------------------------------------------------------------------
    // Interop
    // ---------------------------------------------------------------------------------------

    [StructLayout(LayoutKind.Sequential)]
    internal struct Rect
    {
        public int Left, Top, Right, Bottom;
    }

    private delegate bool EnumWindowsProc(IntPtr hwnd, IntPtr param);

    private const int ProcessDupHandle = 0x0040;
    private const uint DuplicateSameAccess = 0x00000002;
    private const uint ProcessQueryLimitedInformation = 0x00001000;

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(int infoClass, IntPtr buffer, int length, out int returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DuplicateHandle(IntPtr sourceProcess, IntPtr sourceHandle, IntPtr targetProcess, out IntPtr targetHandle, uint access, bool inherit, uint options);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int GetProcessId(IntPtr process);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationThread(IntPtr thread, int infoClass, ref IntPtr info, int length, IntPtr returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenThread(int access, bool inherit, int threadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("user32.dll")]
    private static extern bool EnumWindows(EnumWindowsProc callback, IntPtr param);

    [DllImport("user32.dll")]
    private static extern bool IsWindowVisible(IntPtr hwnd);

    [DllImport("user32.dll", EntryPoint = "GetWindowLongPtrW")]
    private static extern IntPtr GetWindowLongPtr(IntPtr hwnd, int index);

    [DllImport("user32.dll")]
    private static extern bool GetWindowRect(IntPtr hwnd, out Rect rect);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowText(IntPtr hwnd, StringBuilder text, int count);
}
