# ACS — ReHLDS behavioural engine

Tier 3 of the stack: the viewpoint that does not depend on the player running anything.
A Metamod plugin for ReHLDS/HLDS that watches the usercmd stream and reports evidence to
the ACP backend, where it is correlated with the desktop scanner's view of the same
player.

## Why this tier exists

The desktop scanner can only see machines that run it. This one sees everyone, and it
also closes a specific gap the scanner documented and could not fix:

> **Removed:** the live behaviour verdicts. They were derived from `GetCursorPos` deltas,
> which do not track in-game aim … Restoring behavioural verdicts requires reading
> `cl.viewangles` from the engine rather than the cursor.

A server plugin gets exactly that, for free, ~100 times a second, from every player,
with no client cooperation: `pfnCmdStart` hands over the `usercmd_t` the client sent.

## What it detects

All detection is built from the *shape* of the usercmd stream over time. There is no
screen, no target list and no mouse on the server — only angles, buttons, movement and
the entity state each command acted on.

| Rule | Severity | What it means |
|---|---|---|
| `acs-aim-instant` | DETECTED | A large angle crossed inside 1–2 usercmds. Mouse input accumulates per frame, so a physical flick spreads across several commands as the hand accelerates. |
| `acs-aim-linear` | DETECTED | The movement covered the same distance every tick in an unchanging direction — constant-speed interpolation, not a hand. Catches "smoothed"/"humanised" aimbots. |
| `acs-aim-snap` | WARNING | Quiet → fast travel → settle → shot. Real, but fast flick-shooting has the same shape, so it raises risk rather than convicting. |
| `acs-aim-tracklock` | WARNING | Post-snap tracking with sustained movement and zero direction reversals. Humans overshoot and correct back. |
| `acs-aim-reaction` | WARNING | Trigger fires as the view arrives. Pre-committed flick shots do this legitimately — corroboration only. |
| `acs-recoil-compensation` | DETECTED | Pitch input cancelled the server-side punchangle tick for tick across a full burst. |
| `acs-recoil-predictive` | DETECTED | The correction arrived *before* the kick it cancels. Reaction cannot precede its stimulus. |
| `acs-bhop-script` | WARNING→DETECTED | Frame-perfect jump chaining. `PM_Jump` blocks re-jumping while `IN_JUMP` is held, so each hop needs a separate release and press timed to the landing tick. |
| `acs-strafe-bot` | WARNING→DETECTED | Air-strafe key and yaw direction agree on essentially every tick. |
| `acs-ground-overspeed` | WARNING | Ground speed above what `PM_WalkMove` produces for any CS 1.6 weapon. |
| `acs-speedhack` | DETECTED | Summed usercmd durations exceed real elapsed time across repeated windows. |
| `acs-impossible-move` | DETECTED | `forwardmove`/`sidemove` beyond what `cl_forwardspeed` can produce on a retail client. |
| `acs-cmd-flood` | WARNING | Sustained usercmd rate above what `cl_cmdrate` permits. |
| `acs-headshot-rate` | WARNING→DETECTED | Headshot proportion far outside the honest distribution, over a large sample. |
| `acs-multikill-speed` | WARNING→DETECTED | Separate targets killed faster than the view can travel between them. |

### The one that does the most work

**Recoil.** It is the strongest server-side detector available in CS 1.6 because of a
specific property of the game: `punchangle` is authoritative. `CBasePlayer` fires along
`pev->v_angle + pev->punchangle`, server-side. A client-side "no recoil" that stops the
view shaking does **not** move the player's bullets back onto the target — it only hides
the kick.

So anything that actually *controls* recoil has to steer the mouse, and steering the
mouse means the viewangles in the usercmd stream must cancel the punchangle. That
cancellation is visible to the server with no client cooperation at all, and a hand
cannot do it as precisely or as repeatably as code.

### What is deliberately not a verdict

- **Mouse quantisation.** A human's angle deltas are integer multiples of
  `sensitivity * m_yaw`; an aimbot writes an arbitrary float. It is reported as a metric
  and never on its own as a verdict, because GoldSrc delta-encodes usercmd viewangles at
  16-bit precision (~0.0055°) — what reaches the server is already re-quantised onto a
  different grid than the client produced. For common sensitivities the structure
  survives, but at very high sensitivity or very low DPI the grids alias.
- **Byte-identical repeated commands.** Looks like a replayed macro, but a player running
  in a straight line at a stable framerate emits exactly that. Recorded as telemetry.

## Build

Needs the HLSDK and Metamod headers. HLDS and ReHLDS are 32-bit, so the plugin must be
too — on a 64-bit Linux host that means the multilib toolchain
(`apt install g++-multilib`).

```sh
make HLSDK=/path/to/hlsdk METAMOD=/path/to/metamod/metamod
```

Produces `acs_mm_i386.so` (or `acs_mm.dll` on Windows).

## Install

```
cstrike/addons/acs/acs_mm_i386.so
cstrike/addons/acs/acs.cfg          <- copy from cfg/acs.cfg
```

Add to `cstrike/addons/metamod/plugins.ini`:

```
linux addons/acs/acs_mm_i386.so
```

The plugin must load at **startup** (`PT_STARTUP`): it hooks `pfnRegUserMsg` to learn
which message ids mean `DeathMsg` and `CurWeapon`, and those are registered during game
DLL init.

## Configure

Everything is in `acs.cfg`, read directly by the plugin and **not** exec'd as server
cvars — so the uplink secret never becomes something `rcon cvarlist` can read back, and
thresholds are not changeable live by anyone holding rcon.

```
endpoint   http://127.0.0.1:8080/acp/telemetry.php
secret     <must equal ACP_TELEMETRY_SECRET on the backend>
server_id  cs-public-1
```

`ACS_ENDPOINT`, `ACS_SECRET` and `ACS_SERVER_ID` override the file, so the
config can be committed and the secret supplied per host.

With no secret set the plugin **refuses to upload** rather than sending unauthenticated
evidence — anyone who can post unsigned telemetry can fabricate a record against any
SteamID.

### Transport

Plain HTTP with an HMAC-SHA256 signature over the body. There is no TLS in-process, by
choice: linking OpenSSL into a 32-bit Metamod plugin on an arbitrary distro is a
portability problem out of proportion to the benefit. The signature authenticates the
server and protects the events from being edited in transit; it does not make them
secret. Put the backend behind a TLS-terminating reverse proxy and point `endpoint` at
the local side of it, or keep the link on a private network.

## Tuning

Start with the defaults and watch `players.php` before changing anything. The dials that
matter, in order:

- **`snap_min_deg` (18)** — the main aim sensitivity. Lowering it finds more, and finds
  more honest flick-shooters with it. This only affects the WARNING-level pattern rule;
  the DETECTED aim rules have their own criteria.
- **`bhop_streak` (8)** — raise it if your server allows a wheel-bound jump, which
  produces short legitimate streaks.
- **`recoil_r` (0.90) / `recoil_residual` (0.35)** — both must be met. Good players sit
  around 0.4–0.6 correlation with residuals several times larger, so there is a wide
  margin; tighten only if you actually see false positives.

## Tests

```sh
make test
```

Drives synthetic usercmd streams through the real engines and asserts **both**
directions: cheat-shaped input must raise the rule, and human-shaped input must not. The
second half is the one that matters — a detector that fires on everything is worse than
no detector.

The suite includes the boundary cases that found real bugs during development:

- an aggressive **flick-shooter** (fast, settled, pre-committed click) — which triggered
  the bare snap rule 30/30 times, and is why speed alone no longer produces a DETECTED
  verdict;
- a **smoothed aimbot** interpolating over 4 ticks — which the first linearity metric
  (Pearson correlation of the per-tick deltas) scored as *zero*, because a constant-speed
  straight line has no variance for a correlation to find;
- a **skilled human** compensating recoil at 80% with lag and noise — which must stay
  clear of the recoil rule.

`tests/stubs/` contains minimal fakes of the HLSDK and Metamod headers so the analysis
engines compile without an SDK checked out. They are **not** the real SDK and are never
used by the `all` target.

## Layout

```
src/
  acs.h      shared types, the tick ring, config
  meta_api.cpp  Metamod entry points and engine hooks
  player.cpp    session lifecycle, tick fan-out, angle-delta normalisation
  aim.cpp       snap detection, movement shape analysis, tracking, quantisation
  recoil.cpp    punchangle cancellation correlation and residual
  movement.cpp  bunny-hop timing, air-strafe sync, ground speed
  usercmd.cpp   time consistency, field ranges, command rate
  behavior.cpp  kills, headshots, multi-kill timing, session summary
  evidence.cpp  rate limiting, severity, risk weighting, event emission
  uplink.cpp    background worker, bounded queue, signed HTTP POST
  sha256.cpp    vendored SHA-256 / HMAC (avoids an OpenSSL dependency)
  util.cpp      config parsing, logging, JSON escaping
```

Two things about `uplink.cpp` are load-bearing: the worker never calls an engine function
(GoldSrc is single-threaded and none of its API is safe off the game thread), and the
queue is bounded so a backend that is down costs a fixed amount of memory.
