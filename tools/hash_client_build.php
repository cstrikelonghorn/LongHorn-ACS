<?php
declare(strict_types=1);

/**
 * Generate knownHashes for a client profile from a clean install.
 *
 * A profile matched only on filenames is treated as "claimed": an explained finding is
 * downgraded to WARNING and never to INFO, because a filename is exactly what a cheat
 * would forge. Supplying the real hashes of a build promotes it to "verified", which is
 * what lets an honest player on that build come back fully clean.
 *
 * Usage:
 *   php tools/hash_client_build.php "C:\Program Files (x86)\LongHorn\Counter-Strike 1.6 Pro"
 *   php tools/hash_client_build.php <dir> --profile longhorn-cs16-pro --write
 *
 * Without --write it prints the JSON block for you to paste. With --write it inserts the
 * hashes into database/client_profiles.json for the named profile.
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('This tool runs from the command line only.');
}

require __DIR__ . '/../config.php';

$args    = array_slice($argv, 1);
$dir     = '';
$profile = '';
$write   = false;

for ($i = 0; $i < count($args); $i++) {
    if ($args[$i] === '--profile' && isset($args[$i + 1])) { $profile = $args[++$i]; continue; }
    if ($args[$i] === '--write') { $write = true; continue; }
    if ($dir === '') { $dir = $args[$i]; }
}

if ($dir === '' || !is_dir($dir)) {
    fwrite(STDERR, "Usage: php tools/hash_client_build.php <install-dir> [--profile <id>] [--write]\n");
    exit(1);
}
if ($write && $profile === '') {
    fwrite(STDERR, "--write requires --profile <id>\n");
    exit(1);
}

// The files worth pinning: the engine and client binaries a profile allows to differ, plus
// any launcher/marker DLL that identifies the build. Hashing the whole tree would bloat the
// profile with map and sprite hashes that identify nothing.
$interesting = [
    'hw.dll', 'sw.dll', 'client.dll', 'gameui.dll', 'vgui2.dll', 'opengl32.dll', 'd3d9.dll',
    'hl.exe', 'filesystem_stdio.dll', 'steam_api.dll', 'steam_api_c.dll', 'steamclient.dll',
];

$found = [];
$iterator = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS | FilesystemIterator::UNIX_PATHS),
    RecursiveIteratorIterator::LEAVES_ONLY
);

foreach ($iterator as $file) {
    /** @var SplFileInfo $file */
    if (!$file->isFile()) {
        continue;
    }
    $name = strtolower($file->getFilename());
    $ext  = strtolower($file->getExtension());

    // Named binaries always; any other .dll/.exe sitting in the install root, which is
    // where a custom launcher or marker module lives.
    $isNamed = in_array($name, $interesting, true);
    $isRootBinary = in_array($ext, ['dll', 'exe'], true)
        && rtrim(str_replace('\\', '/', $file->getPath()), '/') === rtrim(str_replace('\\', '/', $dir), '/');

    if (!$isNamed && !$isRootBinary) {
        continue;
    }
    if ($file->getSize() > 128 * 1024 * 1024) {
        continue;
    }

    $sha = hash_file('sha256', $file->getPathname());
    if ($sha === false) {
        continue;
    }
    $found[$sha] = str_replace('\\', '/', substr($file->getPathname(), strlen($dir) + 1));
}

if (count($found) === 0) {
    fwrite(STDERR, "No client binaries found under {$dir}\n");
    exit(1);
}

fwrite(STDERR, sprintf("Hashed %d file(s) under %s\n\n", count($found), $dir));
foreach ($found as $sha => $rel) {
    fwrite(STDERR, sprintf("  %s  %s\n", $sha, $rel));
}
fwrite(STDERR, "\n");

$block = ['sha256' => array_keys($found)];

if (!$write) {
    echo json_encode($block, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";
    fwrite(STDERR, "Paste the sha256 array into the profile's knownHashes, or re-run with --profile <id> --write.\n");
    exit(0);
}

$path = $acpConfig['clientProfilesFile'];
$db   = json_decode((string) file_get_contents($path), true);
if (!is_array($db) || !is_array($db['profiles'] ?? null)) {
    fwrite(STDERR, "Cannot read {$path}\n");
    exit(1);
}

$updated = false;
foreach ($db['profiles'] as $i => $p) {
    if (($p['id'] ?? '') !== $profile) {
        continue;
    }
    $existing = (array) ($p['knownHashes']['sha256'] ?? []);
    $merged   = array_values(array_unique(array_merge($existing, array_keys($found))));
    $db['profiles'][$i]['knownHashes']['sha256'] = $merged;
    $updated = true;
    fwrite(STDERR, sprintf("Profile '%s': %d -> %d hash(es)\n", $profile, count($existing), count($merged)));
}

if (!$updated) {
    fwrite(STDERR, "No profile with id '{$profile}'\n");
    exit(1);
}

// Write via a temp file so an interrupted run cannot leave a truncated profile database,
// which would silently disable client compatibility for every player.
$tmp = $path . '.tmp';
file_put_contents($tmp, json_encode($db, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n");
rename($tmp, $path);
fwrite(STDERR, "Written to {$path}\n");
