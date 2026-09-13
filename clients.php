<?php
declare(strict_types=1);

// Legitimate-client compatibility.
//
// Most of the surviving CS 1.6 population does not run the retail Steam client. They run
// NextClient, GoldClient, GSClient or one of the hundreds of repacked editions - and
// several of those modify or detour the engine *by design*. NextClient's own repository
// says so in as many words: antivirus and heuristic flags on it are "false positives
// caused by runtime detouring of engine functions".
//
// Runtime detouring of engine functions is precisely what ScanInlineHooks reports as a
// DETECTED inline hook. So without this file, ACS marks a large share of honest players
// as cheaters, which is worse than useless - it destroys the operator's trust in every
// other finding.
//
// The obvious way to fix that is also the wrong way. A whitelist keyed on "is there a
// file called nextclient.dll" is a bypass: drop that filename next to a cheat and become
// immune. Four things keep this from becoming one:
//
//  1. SCOPED. A profile explains specific ruleId + subject pairs and nothing else. A cheat
//     DLL mapped into hl.exe still trips the cheat-named and foreign-module rules, and
//     every hash still goes to the corpus.
//  2. GRADED. A profile whose marker hashes are known and matched is "verified" and
//     downgrades an explained finding to INFO. A profile matched on filename alone is
//     "claimed" and only downgrades DETECTED to WARNING - visible, ranked lower, not
//     dismissed.
//  3. NEVER SERVER-SIDE. Client profiles touch client-side artifact findings only. The
//     ReHLDS behavioural engine - aim, recoil, movement, usercmd - is not suppressed by
//     any profile, because how a player aims does not depend on which client they run.
//     A cheater who fakes a client profile still gets caught by the half of the system
//     that does not trust the client at all.
//  4. NON-DESTRUCTIVE. Nothing is deleted. The original severity is preserved on the
//     finding so an admin can always see what was downgraded and why.

/**
 * Loads the client profile database. Returns an empty profile list rather than throwing:
 * a missing or malformed profile file must degrade to "no client recognised", never take
 * down report ingestion.
 */
function acs_client_profiles(array $config): array
{
    // Keyed by path, not a bare singleton: a caller may legitimately point at a
    // different profile file (tests do), and a singleton would silently serve the first
    // one loaded for the rest of the request.
    static $cache = [];

    $path = $config['clientProfilesFile'] ?? (__DIR__ . '/database/client_profiles.json');
    if (array_key_exists($path, $cache)) {
        return $cache[$path];
    }

    if (!is_file($path)) {
        return $cache[$path] = ['version' => 0, 'profiles' => []];
    }

    $data = json_decode((string) @file_get_contents($path), true);
    if (!is_array($data) || !is_array($data['profiles'] ?? null)) {
        return $cache[$path] = ['version' => 0, 'profiles' => []];
    }

    return $cache[$path] = $data;
}

/** Lowercased module names and file names present in a report. */
function acs_client_surface(array $report): array
{
    $modules = [];
    foreach ((array) ($report['modules'] ?? []) as $m) {
        if (!is_array($m)) continue;
        $name = strtolower(trim((string) ($m['name'] ?? '')));
        if ($name !== '') $modules[$name] = strtolower((string) ($m['sha256'] ?? ''));
    }

    $files = [];
    foreach ((array) ($report['hlFiles'] ?? []) as $f) {
        if (!is_array($f)) continue;
        $rel = strtolower(trim((string) ($f['relativePath'] ?? '')));
        if ($rel !== '') $files[$rel] = strtolower((string) ($f['sha256'] ?? ''));
    }

    return ['modules' => $modules, 'files' => $files];
}

/**
 * Identifies which known client a report came from.
 *
 * Returns the matched profile plus how it was matched. `verified` means a hash listed in
 * the profile was actually present; without that the match is only a filename claim and
 * is treated as weaker evidence everywhere downstream.
 */
function acs_client_identify(array $report, array $config): ?array
{
    $db      = acs_client_profiles($config);
    $surface = acs_client_surface($report);
    $hashes  = array_values(array_filter(array_merge(
        array_values($surface['modules']),
        array_values($surface['files'])
    )));

    $noSteam = true;
    foreach (array_keys($surface['modules']) as $name) {
        if ($name === 'steamclient.dll') { $noSteam = false; break; }
    }

    $best = null;
    foreach ($db['profiles'] as $profile) {
        if (!is_array($profile)) continue;
        $markers = is_array($profile['markers'] ?? null) ? $profile['markers'] : [];
        $matched = [];

        foreach ((array) ($markers['modules'] ?? []) as $needle) {
            $needle = strtolower((string) $needle);
            foreach (array_keys($surface['modules']) as $name) {
                if ($name === $needle || str_contains($name, $needle)) {
                    $matched[] = 'module:' . $name;
                }
            }
        }
        foreach ((array) ($markers['files'] ?? []) as $needle) {
            $needle = strtolower((string) $needle);
            foreach (array_keys($surface['files']) as $rel) {
                if (str_contains($rel, $needle)) {
                    $matched[] = 'file:' . $rel;
                }
            }
        }

        // The generic non-Steam profile matches on the absence of steamclient.dll. It is
        // only ever a fallback, so it must not win over a real client match.
        $isFallback = (bool) ($markers['noSteamBuild'] ?? false);
        if ($isFallback && $noSteam && count($matched) === 0) {
            $matched[] = 'build:no-steam';
        }

        $need = max(1, (int) ($markers['minMatches'] ?? 1));
        if (count($matched) < $need) {
            continue;
        }

        $known    = array_map('strtolower', (array) ($profile['knownHashes']['sha256'] ?? []));
        $verified = count($known) > 0 && count(array_intersect($known, $hashes)) > 0;

        $candidate = [
            'id'         => (string) ($profile['id'] ?? ''),
            'name'       => (string) ($profile['name'] ?? ''),
            'url'        => (string) ($profile['url'] ?? ''),
            'confidence' => (string) ($profile['confidence'] ?? 'inferred'),
            'verified'   => $verified,
            'fallback'   => $isFallback,
            'matchedOn'  => array_values(array_unique($matched)),
            'profile'    => $profile,
        ];

        // A specific client always beats the generic non-Steam fallback; among equals,
        // more marker matches wins.
        if ($best === null
            || ($best['fallback'] && !$isFallback)
            || (!$isFallback && count($candidate['matchedOn']) > count($best['matchedOn']))) {
            $best = $candidate;
        }
    }

    return $best;
}

/**
 * Canonical key for a rule id so profiles keep matching across the engine rename.
 *
 * The live desktop engine emits `acp-*` ids (acp-inline-hook, acp-foreign-module),
 * while the profile database and the original test suite were written against the
 * older `acs-*` namespace. Without collapsing the two prefixes a profile is loaded,
 * reports "recognised", and explains nothing — the exact silent no-op that keeps
 * honest NextClient / emulator users marked as cheaters. `ecd-`/`wcd-` are a
 * different import source and are left alone.
 */
function acs_client_rule_key(string $ruleId): string
{
    $ruleId = strtolower(trim($ruleId));
    return str_starts_with($ruleId, 'acs-') ? 'acp-' . substr($ruleId, 4) : $ruleId;
}

/**
 * The filenames a finding's subject actually identifies.
 *
 * Subjects take a few shapes: "name — C:\path\name.dll", "steamclient.dll: 1 byte(s)",
 * "hw.dll!SV_Frame @0x1 -> 0x2 (unbacked memory)" and bare "C:\cs\aimbot.dll".
 *
 * A bare-word needle must only ever match one of these filenames, never the surrounding
 * path. Matching the raw subject string is how a *directory* name came to excuse a cheat:
 * a loader dropped at C:\Users\x\dproto_fix\wh.dll contains "dproto", so the non-Steam
 * repack profile quietly downgraded it from DETECTED to WARNING.
 */
function acs_subject_identifiers(string $subject): array
{
    $ids = [];

    // Basename of every path-looking run in the subject. Handles drive letters and spaces
    // ("C:\Program Files (x86)\...\muzzIeflash5.spr") which a whitespace split cannot.
    if (preg_match_all('#[\\\\/]([^\\\\/]+\.[A-Za-z0-9_]+)#', $subject, $matches)) {
        foreach ($matches[1] as $basename) {
            $ids[] = strtolower(trim($basename));
        }
    }

    // A leading bare filename, i.e. the module a hook or patch finding is about.
    if (preg_match('/^([^\s\\\\\/:!,]+\.[A-Za-z0-9_]+)/', ltrim($subject), $lead)) {
        $ids[] = strtolower($lead[1]);
    }

    return array_values(array_unique(array_filter($ids)));
}

/** Does a bare-word needle name this file? "podbot" matches podbot_mm.dll, not wh.dll. */
function acs_identifier_matches(string $identifier, string $needle): bool
{
    if ($identifier === $needle) {
        return true;
    }
    // Needle carries no extension: compare against the filename stem, allowing the
    // "<needle>_<variant>" suffix real plugins use (dproto -> dproto_mm.dll).
    $stem = (string) preg_replace('/\.[^.]+$/', '', $identifier);
    return $stem === $needle || str_starts_with($stem, $needle . '_') || str_starts_with($identifier, $needle . '.');
}

/** Does this explain-entry cover the given finding? */
function acs_client_explains_finding(array $entry, string $ruleId, string $subject): bool
{
    $rules = array_map(
        static fn($id): string => acs_client_rule_key((string) $id),
        (array) ($entry['ruleIds'] ?? [])
    );
    if (count($rules) > 0 && !in_array(acs_client_rule_key($ruleId), $rules, true)) {
        return false;
    }

    $needles = (array) ($entry['subjectMatch'] ?? []);
    if (count($needles) === 0) {
        return true;   // rule-wide
    }

    $identifiers = acs_subject_identifiers($subject);
    $pathSubject = strtolower(str_replace('\\', '/', $subject));

    foreach ($needles as $needle) {
        $needle = strtolower(trim((string) $needle));
        if ($needle === '') {
            continue;
        }

        // A needle written as a path fragment ("addons/reunion") is meant to match a
        // location, so it still matches the path - with separators normalised so the
        // Windows and POSIX spellings behave identically.
        if (str_contains($needle, '/') || str_contains($needle, '\\')) {
            if (str_contains($pathSubject, str_replace('\\', '/', $needle))) {
                return true;
            }
            continue;
        }

        foreach ($identifiers as $identifier) {
            if (acs_identifier_matches($identifier, $needle)) {
                return true;
            }
        }
    }

    return false;
}

/**
 * Applies a client profile to a report in place.
 *
 * Findings the profile explains are downgraded, never removed, and carry the reason plus
 * their original severity so the downgrade is auditable.
 */
function acs_client_apply(array &$report, array $config): array
{
    $match = acs_client_identify($report, $config);
    if ($match === null) {
        $report['client'] = ['recognised' => false];
        return $report['client'];
    }

    $profile = $match['profile'];

    // Verified profiles (a known hash was actually present) can take a finding all the way
    // down to informational. A filename-only match cannot: it drops DETECTED to WARNING so
    // the evidence stays visible and ranked, because a filename is exactly what a cheat
    // would forge to get here.
    $floor = ($match['verified'] && ($match['confidence'] ?? '') === 'documented') ? 'INFO' : 'WARNING';

    $downgraded = 0;
    $annotated  = 0;
    $findings   = is_array($report['findings'] ?? null) ? $report['findings'] : [];

    foreach ($findings as $i => $finding) {
        if (!is_array($finding)) continue;

        $ruleId   = (string) ($finding['ruleId'] ?? '');
        $subject  = (string) ($finding['subject'] ?? '');
        $severity = strtoupper((string) ($finding['severity'] ?? 'INFO'));
        if ($severity === 'INFO') continue;

        foreach ((array) ($profile['explains'] ?? []) as $entry) {
            if (!is_array($entry) || !acs_client_explains_finding($entry, $ruleId, $subject)) {
                continue;
            }

            // The annotation is unconditional: an admin reading the report should see why
            // a finding is probably benign even in the case where the severity does not
            // move. That case is real - a WARNING explained by an unverified profile
            // stays a WARNING, because the floor for a filename-only match is WARNING and
            // severity is only ever moved downward.
            $findings[$i]['explainedBy'] = [
                'client'   => $match['name'],
                'id'       => $match['id'],
                'verified' => $match['verified'],
                'reason'   => (string) ($entry['reason'] ?? ''),
            ];
            $annotated++;

            $new = ($floor === 'INFO') ? 'INFO' : ($severity === 'DETECTED' ? 'WARNING' : $severity);
            if ($new !== $severity) {
                $findings[$i]['originalSeverity'] = $severity;
                $findings[$i]['severity']         = $new;
                $findings[$i]['confidence']       = $new === 'INFO' ? 'low' : 'medium';
                $downgraded++;
            }
            break;
        }
    }
    $report['findings'] = $findings;

    // Module integrity: the same modules that carry the client's own detours.
    $allow = array_map('strtolower', (array) ($profile['moduleIntegrity']['allowModified'] ?? []));
    $integrityExplained = 0;
    if (count($allow) > 0 && is_array($report['moduleIntegrity'] ?? null)) {
        foreach ($report['moduleIntegrity'] as $k => $entry) {
            if (!is_array($entry)) continue;
            $name = strtolower((string) ($entry['module'] ?? $entry['name'] ?? ''));
            if ($name === '' || !in_array($name, $allow, true)) continue;

            // ModuleIntegrity emits status: "clean" | "patched" | "inconclusive". An
            // earlier version of this line tested an $entry['clean'] boolean that the
            // scanner never writes, so the ?? default made every entry look clean and
            // this whole block was dead code.
            if (strtolower((string) ($entry['status'] ?? 'clean')) !== 'patched') continue;

            $report['moduleIntegrity'][$k]['explainedBy'] = [
                'client' => $match['name'],
                'id'     => $match['id'],
                'reason' => (string) ($profile['moduleIntegrity']['reason'] ?? ''),
            ];
            $integrityExplained++;
        }
    }

    $report['client'] = [
        'recognised'         => true,
        'id'                 => $match['id'],
        'name'               => $match['name'],
        'url'                => $match['url'],
        'confidence'         => $match['confidence'],
        'verified'           => $match['verified'],
        'fallback'           => $match['fallback'],
        'matchedOn'          => $match['matchedOn'],
        'downgraded'         => $downgraded,
        'annotated'          => $annotated,
        'integrityExplained' => $integrityExplained,
        'note'               => $match['verified']
            ? 'Client identified by a known binary hash.'
            : 'Client identified by filename only - no known hash for this build is on file, '
              . 'so explained findings are downgraded to WARNING rather than dismissed. '
              . 'Server-side behavioural evidence is never affected by a client profile.',
    ];

    return $report['client'];
}
