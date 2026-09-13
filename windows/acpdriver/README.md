# acpdriver — ACP kernel-mode helper

A signed kernel helper that lifts ACP out of "pure user-mode evidence scanner" and gives it the
observability advantage that EasyCheatDetector / WarGods-style desktop scanners lack.

## Why kernel mode

The desktop `ScannerEngine.cs` is entirely user-mode `ReadProcessMemory`. It cannot see:

- **Stealth DLLs** that load and immediately unmap before `Process.Modules` enumerates them.
- **Kernel-mode cheats / rootkits** that execute outside any user-mode process you can read.
- **Process creation** that happens *between* scans (launcher → inject → hide).
- **Memory** when the cheat has hooked the API the scanner relies on to read it.

A tiny, properly-signed kernel driver closes that gap. It does not need to be an "anti-cheat" in the
aggressive sense (no self-injection, no anti-debug, no root-cert install). It is a *witness*: it
observes and lets the scanner read, using page-table traversal that user-mode hooks cannot fool.

## What this scaffold provides

| File | Purpose |
| --- | --- |
| `AcpCore.c` | WDM driver: device, symlink, `IRP_MJ_DEVICE_CONTROL` handler, `PsSetCreateProcessNotifyRoutineEx`, `PsSetLoadImageNotifyRoutine`, and an `IOCTL_ACP_READ_MEMORY` handler that reads another process via `MmCopyVirtualMemory`. |
| `acpdriver.inf` | Driver package INF (template). |
| `acpdriver.vcxproj` | WDK `WindowsKernelModeDriver10.0` project, `ConfigurationType=Driver`, target `acpdriver.sys`. |

## Build (requires the WDK)

1. Install matching **Visual Studio (with C++) + Windows SDK + Windows Driver Kit** (build tools).
   The `.vcxproj` uses `WindowsKernelModeDriver10.0` platform toolset.
2. Open `acpdriver.vcxproj` in Visual Studio and build `Release | x64`. Output: `acpdriver.sys`.

## Signing (the real gate)

Windows 10 x64 **will not load an unsigned kernel driver**. You must:

- Obtain a code-signing certificate; for production you need an **EV** certificate and a
  **WHQL / Microsoft HLK signature**, which is a paid, multi-week process against hardware you own.
- Add an `acpdriver.inf` + `acpdriver.cat` catalog and sign it as part of your build.

This step is the genuine cost of moving ahead of a purely user-mode scanner. If you are not prepared
to sign and maintain a kernel driver, keep the user-mode engine and rely on server-side recording +
demo analysis instead (see below).

## Wiring it into the scanner (next step, not included)

1. In `ScannerEngine.cs`, add `DeviceIoControl` P/Invoke for `ACP_IOCTL_READ_MEMORY`.
2. Replace the `ReadProcessMemory(...)` calls in `ScanGameMemory` / `ScanInlineHooks` with a
   helper that falls back to the driver when the handle is opened, so reads are page-table based.
3. Drain the load-image / process-notify events into a module list and cross-check it against
   `Process.Modules` — any module present in the kernel log but absent from the PEB is the signature
   of an "unchained"/stealth injection.

## Realistic alternatives if you skip the driver

The project already has a tamper-resistant path that needs no driver: **server-side recording
evidence**. Have the CS 1.6 server's AMXX plugin emit telemetry at recording time; a cheat cannot
rewrite what the server already recorded. Feed those server logs plus demo replay analysis into
`tools/collect_cheat_reputation.php`. That is the cheapest trustworthy anchor, because it is
outside the player's control.

## Security note

A kernel driver that reads arbitrary process memory from any local caller is a powerful, abusable
primitive. Restrict the device: only allow the current user / a specific service, validate every
IOCTL size and address, and never expose it to remote or untrusted callers.
