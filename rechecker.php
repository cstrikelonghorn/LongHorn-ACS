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
 *   - MISSING fires when the client HAS a file it should not have. That is what these rules use:
 *     the database stores md5/sha256, while ReChecker's hash column takes the engine's 8-hex
 *     CRC32, so hash-exact rules cannot be generated from it yet (see ACP_RECHECKER_NOTE below).
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
    'Hash-exact rules are not generated: ReChecker compares the engine CRC32 (8 hex digits) while ' .
    'the ACS database stores md5/sha256. Add a "crc32" field to a signature to enable them.';

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

    foreach (['path_regex', 'report_regex'] as $key) {
        foreach ((array) ($match[$key] ?? []) as $pattern) {
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

/** Strip anything that would break out of the quoted fields. */
function acp_rechecker_text(string $value): string
{
    return trim(str_replace(['"', "'", "\r", "\n", "\t"], ['', '', ' ', ' ', ' '], $value));
}

$action = (string) ($_GET['action'] ?? 'resources');
if ($action !== 'resources') {
    acp_json_response(['ok' => false, 'error' => 'Unknown action'], 404);
}

$verb = (string) ($_GET['command'] ?? 'amx_kick');
if (!in_array($verb, ['kick', 'amx_kick', 'ban'], true)) {
    $verb = 'amx_kick';
}
$banTime = max(0, (int) ($_GET['bantime'] ?? 0));

/** Build the command field. Inner text uses single quotes; the field itself is double-quoted. */
$buildCommand = static function (string $label) use ($verb, $banTime): string {
    $label = acp_rechecker_text($label);

    if ($verb === 'ban') {
        return sprintf("amx_ban [userid] %d 'ACS: %s ([file_name])'", $banTime, $label);
    }

    return sprintf("%s [userid] 'ACS: %s ([file_name])'", $verb, $label);
};

$database = acp_load_database($acpConfig);
$rules = is_array($database['signatures'] ?? null) ? $database['signatures'] : [];

$lines = [];
$lines[] = '; ReChecker resources.ini generated by ACS (Anti-Cheat Scanner) by LongHorn';
$lines[] = '; database revision: ' . acp_rechecker_text((string) ($database['databaseRevision'] ?? 'unknown'));
$lines[] = '; generated: ' . gmdate('Y-m-d\TH:i:s\Z');
$lines[] = ';';
$lines[] = '; Each rule makes the connecting client hash a named file. MISSING fires when the client';
$lines[] = '; HAS a file it should not -- no client-side scanner required, and the player cannot';
$lines[] = '; decline the check.';
$lines[] = ';';
$lines[] = '; Paths are relative to the mod directory, so "../name" is the game root.';
$lines[] = '; ' . ACP_RECHECKER_NOTE;
$lines[] = ';';
$lines[] = '; REVIEW BEFORE DEPLOYING. A rule that names a file honest players legitimately have';
$lines[] = '; will kick them. Start with amx_kick and read the logs before switching to a ban.';
$lines[] = '';

$emitted = [];
$curatedCount = 0;
$signatureCount = 0;

$lines[] = '; -- curated rules -------------------------------------------------------------';
foreach (ACP_RECHECKER_CURATED as [$path, $label]) {
    $emitted[$path] = true;
    $curatedCount++;
    $lines[] = sprintf('"%s"%sMISSING%s"%s"%sBREAK', $path, "\t", "\t", $buildCommand($label), "\t");
}

$lines[] = '';
$lines[] = '; -- from the ACS signature database -------------------------------------------';

foreach ($rules as $rule) {
    if (!is_array($rule) || ($rule['enabled'] ?? true) === false) {
        continue;
    }

    // Only high-confidence signatures become server-side enforcement. Anything weaker stays
    // review evidence in the desktop report; it must not be able to kick a player by itself.
    if (strtolower((string) ($rule['confidence'] ?? '')) !== 'high'
        || strtoupper((string) ($rule['severity'] ?? '')) !== 'DETECTED') {
        continue;
    }

    $label = (string) ($rule['name'] ?? $rule['id'] ?? 'signature');
    $command = $buildCommand($label);
    $match = is_array($rule['match'] ?? null) ? $rule['match'] : [];
    $rawCrc = $rule['crc32'] ?? $match['file_crc32'] ?? $match['crc32'] ?? null;
    $hashToken = 'MISSING';
    if (is_string($rawCrc) && preg_match('/^(?:0x)?([A-Fa-f0-9]{8})$/', trim($rawCrc), $m)) {
        $hashToken = '0x' . strtoupper($m[1]);
    }

    foreach (acp_rechecker_literal_files($rule) as $file) {
        // A cheat file may sit in the mod folder or in the game root; check both.
        foreach ([$file, '../' . $file] as $path) {
            $ruleKey = $path . ':' . $hashToken;
            if (isset($emitted[$ruleKey])) {
                continue;
            }

            $emitted[$ruleKey] = true;
            $signatureCount++;
            $lines[] = sprintf('"%s"%s%s%s"%s"%sBREAK', $path, "\t", $hashToken, "\t", $command, "\t");
        }
    }
}

$lines[] = '';
$lines[] = sprintf('; %d curated rule(s), %d signature rule(s), %d total',
    $curatedCount, $signatureCount, $curatedCount + $signatureCount);

header('Content-Type: text/plain; charset=utf-8');
header('Content-Disposition: attachment; filename="resources.ini"');
echo implode("\n", $lines) . "\n";
