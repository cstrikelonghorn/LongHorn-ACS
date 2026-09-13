# Contributing

Thanks for considering a contribution to LongHorn ACS. This repository is currently **private and in development**, so please coordinate before starting large changes.

## Ways to help

- Report false positives/negatives with a report link and a clear description.
- Suggest or submit client profiles for known CS 1.6 clients and Steam emulators.
- Improve documentation (`docs/`) and translations.
- Report bugs / request features via the GitHub issue templates.

## Development setup

**Web (PHP 8.2+)**

```bash
php -S localhost:8000           # serve from the repo root
php -l index.php                # syntax check a file
```

**Desktop (C#/.NET)**

```powershell
dotnet restore windows/ACPScanner.csproj
dotnet build   windows/ACPScanner.csproj
dotnet publish windows/ACPScanner.csproj -c Release -r win-x64 --self-contained
```

## Tests

```bash
ACPDIR="$(pwd)" php tests/client_profiles_test.php
ACPDIR="$(pwd)" php tests/behavior_test.php
ACPDIR="$(pwd)" php tests/risk_thresholds_test.php
```

CI runs the C# build and the PHP syntax/tests (see `.github/workflows/ci.yml`).

## Coding standards

- **Never commit** player data, tokens, or runtime databases — see `.gitignore`.
- Keep changes scoped; explain the *why* in comments where a decision was non-obvious.
- Match the surrounding style (PHP: `declare(strict_types=1)`; C#: nullable enabled).
- A client profile or detection rule should include a short rationale.

## Pull requests

1. Branch from `main`.
2. Make the change with a focused diff and a clear description.
3. Ensure CI is green.
4. Reference any related issue.

By contributing you agree your work may be used under the project's license.
