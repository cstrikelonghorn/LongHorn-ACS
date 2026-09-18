# ACS 1.0.9

Windows 10 and 11, 32-bit and 64-bit. One portable executable that uses the .NET Framework 4.8 built into Windows. No installer and no administrator prompt.

- **The application file is now `ACScanner.exe`.** It used to be `ACPScanner.exe`, a leftover from the project's old name. Nothing else changes: the download you receive is still named `ACS-Scanner-<version>-windows.exe`, and the app works exactly as before.

1.0.8 keeps working; this update is cosmetic. See `VERIFY.md` to check your download.

---

# ACS 1.0.8

Windows 10 and 11, 32-bit and 64-bit. One portable executable that uses the .NET Framework 4.8 built into Windows. No installer and no administrator prompt.

- **Windows drivers are read correctly.** Most drivers that ship with Windows are signed through catalog files rather than inside the driver itself. The scanner now reads those catalogs, so ordinary system drivers are no longer listed as unsigned.
- **Fewer pointless warnings.** A sprite file whose name uses a capital "I" in place of an "l" is only flagged when it can actually stand in for a sprite the game loads. Spare files that several client builds ship are listed as context instead.
- **Cleaner reports overall.** Together with the database clean-up on the server, scans that used to end in "review required" now come back clean unless something real was found.

1.0.7 keeps working; this update is recommended. See `VERIFY.md` to check your download.

---

# ACS 1.0.7

Windows 10 and 11, 32-bit and 64-bit. One portable executable that uses the .NET Framework 4.8 built into Windows. No installer and no administrator prompt.

- **Memory checks.** The scanner now compares the game's running memory against reviewed cheat patterns. A match is review evidence, never a verdict on its own.
- **Driver checks.** Kernel drivers known to be abused for cheating, and drivers whose signature does not check out, are listed for review with their file path.
- **Honest coverage.** When a memory or hook check cannot finish, the report says so instead of showing a clean result.
- **Correct server on the report.** The connected server is no longer guessed from stray data in game memory, so reports no longer show addresses like 3.0.0.0:1024.
- **Fairer config checks.** A line in a config file no longer produces a "cheat" verdict by itself; those findings stay at review level, as intended.

1.0.6 keeps working; this update is recommended. See `VERIFY.md` to check your download.

---

# ACS 1.0.6

Windows 10 and 11, 32-bit and 64-bit. One portable executable that uses the .NET Framework 4.8 built into Windows. No installer and no administrator prompt.

- **Easier to read before you scan.** The privacy screen now says in plain words what is checked, what is sent, that the report is sent automatically, and who can see it. Same design, same choices.
- **Tip on screen.** Stay on your match server while scanning, so the admin can see where you played.

1.0.5 keeps working; this update is recommended. See `VERIFY.md` to check your download.

---

# ACS 1.0.5

Windows 10 and 11, 32-bit and 64-bit. One portable executable that uses the .NET Framework 4.8 built into Windows. No installer and no administrator prompt.

- **Clearer evidence for referees.** When the scanner flags a program in Windows' history, the report now shows when it last ran, how often, which Windows records list it, and whether the file is still on disk.
- **Recycle Bin details.** Flagged deleted files now include their original size.
- **Administrator note.** Windows keeps most run dates where only administrators can read them. Running the scanner as administrator gives more complete dates; without it, the report says so.

1.0.4 keeps working; this update is recommended. See `VERIFY.md` to check your download.

---

# ACS 1.0.4

Windows 10 and 11, 32-bit and 64-bit. One portable executable that uses the .NET Framework 4.8 built into Windows. No installer and no administrator prompt.

- **Evidence Log icon.** The Evidence Log window now shows the ACS icon in the taskbar.
- **Uploads after an old setup.** A settings file left over from an older setup no longer blocks report uploads.

1.0.3 keeps working; this update is recommended. See `VERIFY.md` to check your download.

---

# ACS 1.0.3

**Required update.** Scanner 1.0.2 and older can no longer upload reports; they show an "out of date" message. Download `ACS-Scanner-1.0.3-windows.exe` from this release or from [cslonghorn.com/acs](https://cslonghorn.com/acs/download.php) and scan again.

Windows 10 and 11, 32-bit and 64-bit. One portable executable that uses the .NET Framework 4.8 built into Windows. No installer and no administrator prompt.

- **New upload credentials.** Every report is signed by the scanner and checked by the server; unsigned or edited reports are refused.
- **Connected server detection.** The game server is read from the running game and the system's network table, including servers joined by domain name. Reports taken outside a match server are clearly marked.
- **Update notice.** The app tells you when a newer version is published.
- **Steadier scans.** Scanning runs off the interface thread, can be cancelled, and streams file hashes with bounded memory. Ordinary jump binds are no longer flagged, and file-presence findings are marked for review instead of treated as proof of use.

Known limitations: unsigned executable; no independent audit; no verified antivirus report for this exact release; no measured real-world false-positive/recall benchmark; operator-managed data retention. ACS does not claim to detect every cheat or to be immune to bypass.

See `VERIFY.md` to check your download.

---

# ACS 1.0.0

Windows 10 and 11, 32-bit and 64-bit. One portable executable with the .NET runtime built in — no installer, no extra files. Runs as administrator. Requires a running compatible Counter-Strike 1.6/GoldSrc client and an operator-provided report server configuration. No endpoint or secret is bundled.

- **Single executable.** The whole app, including its artwork, is `ACS-Scanner-1.0.0-windows.exe`.
- **Client identity from signatures.** Retail Steam is reported only when the launcher and engine are validly signed by Valve and no emulator loads Steam from the game folder. Non-Steam editions are named from load paths and markers, and the engine build date is read from the engine binary.
- **Modified is not forged.** A Valve-signed file changed after signing (how non-Steam editions patch the engine) is recorded with its hash instead of being reported as a forged signature. A certificate that does not chain to a trusted root is still reported as forged.
- **Stricter module trust.** A module's name alone no longer earns trust; it must be part of the game install or validly signed by a trusted publisher.
- **Automatic upload after consent.** The privacy screen before a scan states that the report uploads when the scan finishes; there is no second prompt.
- **Build fingerprint.** Each report records the SHA-256 prefix of the executable that produced it.
- Redesigned desktop interface and evidence log.

Client profiles include Steam/non-Steam distributions, NextClient, GoldClient, GSClient, RevEmu and server-platform components. Profile recognition is not a compatibility certification for every build. The desktop scans on demand. Continuous gameplay behavior analysis requires the separately deployed server plugin, which is not included.

Known limitations: unsigned executable; no independent audit; no verified antivirus report for this exact release; compiler warnings remain; no measured real-world false-positive/recall benchmark; operator-managed data retention. This release does not claim superiority to VAC, WarGods or ECD, detection of every cheat, or immunity to bypass.

See `VALIDATION.md`, `PRIVACY.md`, and `VERIFY.md` for evidence and limitations.
