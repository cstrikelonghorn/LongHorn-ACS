# Detection

ACS separates **artifacts** (a hash is clean or it is not) from **players** (never simply one or the other). This page describes every detection channel.

## Client-side (desktop scanner)

### 1. Module code verification
Every game module's `.text` section is compared **byte for byte** against the mapped file on disk, with relocations normalised. This catches inline hooks, detours, mid-function patches, IAT hooks and EAT hooks regardless of the technique that installed them. Managed assemblies and loader-managed sections (e.g. `fothk`) are skipped to avoid false positives.

### 2. Memory evidence
Private, executable regions that do not back any file on disk are the signature of a manual-mapped cheat DLL. Each artifact carries the first-4K hashes and extracted strings.

### 3. Inline hooks (render / timing)
`hl.exe` code is scanned for hooks on render and timing functions, the classic GoldSrc wallhack/aimbot entry points.

### 4. External-cheat probes
- Processes holding `VM_READ` / `VM_WRITE` handles on the game.
- Threads whose start address belongs to no mapped module.
- Layered click-through windows drawn over the game rect.

### 5. Script & config analysis
Every `.cfg` / `.rc` under the mod folders is tokenised, the `alias` graph is resolved, and matching is done on **control-flow shape**, not keywords. A self-referencing alias chain with `wait` toggling `+jump` is a bunny-hop script no matter what the aliases are called. Covers bunny-hop, rapid-fire, no-recoil, duck-spam, wheel-bound jump and cvar abuse.

### 6. Files, drivers & processes
- `cstrike` folder inventory with hashes (altered sprites, dropped DLLs).
- Kernel drivers with MD5/SHA256, publisher and signature validity.
- Running processes matched against cheat/tool fingerprints (Cheat Engine, injectors, debuggers, …).

### 7. Game build & client recognition
Steam, non-Steam repacks, NextClient, GSClient, GoldClient, RevEmu/RevCrew, SmartSteamEmu, Goldberg and others are identified by module/file markers and known hashes, so a client's own runtime detours are **not** treated as cheating.

## Server-side (ReHLDS plugin)

The plugin reads the usercmd stream the server already receives:

- **Aim** — snap/angle behaviour across samples.
- **Recoil** — compensation patterns inconsistent with the weapon model.
- **Movement** — strafe/bhop behaviour and command timing.
- **Long-term statistics** — per-player history, not one unlucky round.

Server-side evidence is independent of the client: faking a client profile does not affect it.

## The artifact corpus

A hand-written rule list cannot compete with volume — a cheat author only has to rename a file. The corpus records **every hash ever seen** (modules, drivers, game files) with first/last seen, times seen, and — critically — **how many distinct machines** carried it.

- Signed binary on **25+** distinct machines, not concentrated on machines reporting detections → `clean`.
- Unsigned one needs **100**.
- What remains is ranked in `review.php` by suspicion (mapped into the game, unsigned, rare, driver, concentration among detections) with a VirusTotal link and one-click **Cheat** / **Clean**.

## Deliberately excluded

Live behaviour verdicts based on `GetCursorPos` were **removed**. GoldSrc takes mouse look through DirectInput/raw input and re-centres or hides the OS cursor, so cursor deltas cannot track in-game aim — the rule fired on honest players and could never fire on a real aimbot. The capture is retained as telemetry only. Restoring behavioural verdicts requires reading `cl.viewangles` from the engine instead.

## What ACS does *not* do

- It does not ban, kick, or punish. It produces evidence for a human.
- A confirmed detection is strong evidence of a specific observation — not proof of intent.
