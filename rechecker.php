<?php
declare(strict_types=1);

/**
 * ReChecker resources.ini generator.
 *
 * WHY THIS EXISTS
 *   ACS signatures only ever reached the desktop client, which the suspect runs voluntarily and
 *   can decline to run at all. ReChecker (rehlds/rechecker) already runs on the game server and
 *   can force every connecting client to hash named files and be actioned on a match -- an
 *   enforcement channel that does not depend on the player's cooperation.
 *
 *   This endpoint renders the signature database into that format, so an admin points ReChecker
 *   at ACS once and every new signature reaches every server automatically.
 *
 * FORMAT
 *   "<path>"  <hash|MISSING|UNKNOWN>  "<command>"  [BREAK]
 *
 *   - <path> is relative to the MOD directory (cstrike/), so "../opengl32.dll" is the game root.
 *   - UNKNOWN matches a present file whose hash was not explicitly ignored.
 *   - MISSING matches an absent file and must never be used to detect a forbidden file.
 *   - ReChecker accepts a full MD5 or its first four bytes (8 hexadecimal characters).
 *   - The command string is double-quoted, so any text inside it must use SINGLE quotes.
 *
 * USAGE
 *   curl -o resources.ini "https://your-host/acp/rechecker.php?action=resources"
 *   then drop it in cstrike/addons/rechecker/resources.ini
 *
 *   Query parameters:
 *     command=kick|amx_kick|ban   response for a hit (default: amx_kick)
 *     bantime=<minutes>           ban duration when command=ban (default: 0, permanent)
 */

require __DIR__ . '/config.php';

const ACP_RECHECKER_EXTENSIONS = ['dll', 'exe', 'asi', 'ini', 'so', 'sys', 'cfg', 'wad', 'mdl', 'spr'];

const ACP_RECHECKER_NOTE =
    'Hash rules use the database MD5 values. Name-only UNKNOWN rules are comments unless ' .
    'name_only=1 is explicitly requested; review them before enforcement.';

/**
 * Curated rules that do not come from a cheat-name signature but are worth enforcing on every
 * server. A stock Counter-Strike install has no opengl32.dll in the game root -- the real one
 * lives in System32 -- so a client carrying one is running the classic GoldSrc render hook.
 * The ACS engine already treats this as DETECTED, so the two stay consistent.
 */
const ACP_RECHECKER_CURATED = [
    ['../opengl32.dll', 'Local opengl32.dll in the game root (classic GoldSrc render hook)'],
    ['../opengl32.log', 'Render-hook log file left in the game root'],
];

/**
 * Pull literal file names out of a signature's match patterns.
 *
 * The database stores regexes, not file names, so only unambiguous literals are taken. A stem may
 * contain escaped dots (CS-1\.6-Cheat) and the extension may be an alternation
 * (vermillion\.(?:asi|dll|ini)), both of which are expanded. Anything else is skipped rather than
 * guessed at -- a wrong name here becomes a wrong kick on a live server.
 */
function acp_rechecker_literal_files(array $rule): array
{
    $match = is_array($rule['match'] ?? null) ? $rule['match'] : [];
    $found = [];
    $extensions = implode('|', ACP_RECHECKER_EXTENSIONS);

    // stem (letters/digits/_/-, optionally with escaped dots)  \.  then either (?:a|b|c) or ext
    //
    // The word-boundary anchor belongs to the bare-extension branch only. After a ")" -- the end
    // of an alternation group -- the next character in these patterns is "(", and \b never matches
    // between two non-word characters, so anchoring the group branch silently dropped every
    // multi-extension signature.
    $regex = '/([A-Za-z0-9_\-]+(?:\\\\\.[A-Za-z0-9_\-]+)*)'
        . '\\\\\.'
        . '(?:\(\?:([A-Za-z0-9|]+)\)|(' . $extensions . ')\b)/i';

    foreach (['path_regex', 'report_regex', 'filename_regex'] as $key) {
        foreach ((array) ($match[$key] ?? []) as $pattern) {
            // Remove zero-width word-boundary tokens before extracting literals. Otherwise
            // "\\binjmthd\\.ini\\b" is misread as the filename "binjmthd.ini".
            $pattern = str_replace('\\b', ' ', (string) $pattern);
            if (!is_string($pattern) || !preg_match_all($regex, $pattern, $matches, PREG_SET_ORDER)) {
                continue;
            }

            foreach ($matches as $hit) {
                $stem = str_replace('\\.', '.', $hit[1]);
                if (preg_match('/^[A-Za-z0-9_\-.]+$/', $stem) !== 1) {
                    continue;
                }

                // preg drops trailing groups that did not participate, so the bare-extension
                // group is absent whenever the alternation branch matched.
                $bare = $hit[3] ?? '';
                $exts = $bare !== '' ? [$bare] : explode('|', $hit[2]);
                foreach ($exts as $ext) {
                    $ext = strtolower($ext);
                    if (!in_array($ext, ACP_RECHECKER_EXTENSIONS, true)) {
                        continue;   // alternation held something that is not a real extension
                    }

                    $found[strtolower($stem) . '.' . $ext] = true;
                }
            }
        }
    }

    return array_keys($found);
}

/** ReChecker understands full MD5 values and four-byte (8 hex character) MD5 prefixes. */
function acp_rechecker_md5s(array $rule): array
{
    $match = is_array($rule['match'] ?? null) ? $rule['match'] : [];
    $hashes = [];
    foreach ((array) ($match['md5'] ?? []) as $value) {
        $value = strtolower(trim((string) $value));
        if (preg_match('/^(?:[a-f0-9]{8}|[a-f0-9]{32})$/', $value) === 1) {
            $hashes[$value] = true;
        }
    }
    return array_keys($hashes);
}

/** Strip anything that would break out of the quoted fields. */
function acp_rechecker_text(string $value): string
{
    return trim(str_replace(['"', "'", "\r", "\n", "\t"], ['', '', ' ', ' ', ' '], $value));
}

function acp_rechecker_render(array $database, string $verb = 'amx_kick', int $banTime = 0, bool $includeNameOnly = false): string
{
    if (!in_array($verb, ['kick', 'amx_kick', 'ban'], true)) {
        $verb = 'amx_kick';
    }
    $banTime = max(0, $banTime);
    $buildCommand = static function (string $label) use ($verb, $banTime): string {
        $label = acp_rechecker_text($label);
        return $verb === 'ban'
            ? sprintf("amx_ban [userid] %d 'ACS: %s ([file_name])'", $banTime, $label)
            : sprintf("%s [userid] 'ACS: %s ([file_name])'", $verb, $label);
    };

    $rules = is_array($database['signatures'] ?? null) ? $database['signatures'] : [];
    $lines = [
        '; ReChecker resources.ini generated by ACS (Anti-Cheat Scanner) by LongHorn',
        '; database revision: ' . acp_rechecker_text((string) ($database['databaseRevision'] ?? 'unknown')),
        '; generated: ' . gmdate('Y-m-d\TH:i:s\Z'),
        ';',
        '; UNKNOWN detects a present file. MISSING detects an absent file and is never used here.',
        '; Paths are relative to the mod directory, so "../name" is the game root.',
        '; ' . ACP_RECHECKER_NOTE,
        ';',
        '; REVIEW BEFORE DEPLOYING. Start with amx_kick and inspect logs before using bans.',
        '',
    ];
    $emitted = [];
    $curatedCount = 0;
    $signatureCount = 0;
    $reviewCount = 0;

    $emit = static function (string $path, string $hash, string $command, bool $active) use (&$lines, &$emitted): bool {
        $key = strtolower($path . ':' . $hash);
        if (isset($emitted[$key])) return false;
        $emitted[$key] = true;
        $line = sprintf('"%s"%s%s%s"%s"%sBREAK', $path, "\t", $hash, "\t", $command, "\t");
        $lines[] = $active ? $line : '; REVIEW name-only: ' . $line;
        return true;
    };

    $lines[] = '; -- curated name-only rules ---------------------------------------------------';
    foreach (ACP_RECHECKER_CURATED as [$path, $label]) {
        if ($emit($path, 'UNKNOWN', $buildCommand($label), $includeNameOnly)) {
            $includeNameOnly ? $curatedCount++ : $reviewCount++;
        }
    }

    $lines[] = '';
    $lines[] = '; -- from the ACS signature database -------------------------------------------';
    foreach ($rules as $rule) {
        if (!is_array($rule) || ($rule['enabled'] ?? true) === false
            || strtolower((string) ($rule['confidence'] ?? '')) !== 'high'
            || strtoupper((string) ($rule['severity'] ?? '')) !== 'DETECTED') {
            continue;
        }
        $files = acp_rechecker_literal_files($rule);
        if ($files === []) continue;
        $hashes = acp_rechecker_md5s($rule);
        $label = (string) ($rule['name'] ?? $rule['id'] ?? 'signature');
        $command = $buildCommand($label);
        foreach ($files as $file) {
            foreach ([$file, '../' . $file] as $path) {
                if ($hashes !== []) {
                    foreach ($hashes as $hash) {
                        if ($emit($path, $hash, $command, true)) $signatureCount++;
                    }
                } elseif ($emit($path, 'UNKNOWN', $command, $includeNameOnly)) {
                    $includeNameOnly ? $signatureCount++ : $reviewCount++;
                }
            }
        }
    }

    $lines[] = '';
    $lines[] = sprintf('; %d curated active, %d signature active, %d name-only review rule(s)',
        $curatedCount, $signatureCount, $reviewCount);
    return implode("\n", $lines) . "\n";
}

if (realpath((string) ($_SERVER['SCRIPT_FILENAME'] ?? '')) === __FILE__) {
    $action = (string) ($_GET['action'] ?? 'resources');
    if ($action !== 'resources') {
        acp_json_response(['ok' => false, 'error' => 'Unknown action'], 404);
    }
    $database = acp_load_database($acpConfig);
    $includeNameOnly = filter_var($_GET['name_only'] ?? false, FILTER_VALIDATE_BOOLEAN);
    header('Content-Type: text/plain; charset=utf-8');
    header('Content-Disposition: attachment; filename="resources.ini"');
    echo acp_rechecker_render(
        $database,
        (string) ($_GET['command'] ?? 'amx_kick'),
        (int) ($_GET['bantime'] ?? 0),
        $includeNameOnly
    );
}
