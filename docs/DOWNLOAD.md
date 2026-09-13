# Download & Install

> **The scanner only runs while Counter-Strike is already open.** It attaches to a live `hl.exe` — there is nothing to inspect otherwise.

## Requirements

| | |
|---|---|
| OS | Windows 10 / 11 — 32-bit or 64-bit |
| Game | Counter-Strike 1.6 (`hl.exe` / `cstrike.exe`) |
| Runtime | .NET (bundled in the self-contained build) |
| Rights | Administrator (Windows asks when the app starts; needed to identify the joined server from live traffic) |
| Server | A reachable ACS web deployment (`api.php`) |

## Install

1. **Get the release.** Download `ACS-Scanner-X.Y.Z-windows.exe` from the repository **Releases**, or from the project Download page. It is the whole app — one file, nothing to extract.
2. **Put it anywhere** (e.g. `C:\Tools\ACS`).
3. **Configure only when using a different deployment.** The operator download is ready for its own service. To override it, put `acp-settings.json` next to `ACPScanner.exe`, or in `%APPDATA%\LongHorn ACS\`:

   ```json
   {
     "apiUrl": "https://your-host/acp/api.php",
     "apiToken": "THE_SAME_VALUE_AS_ACP_API_TOKEN"
   }
   ```

   - `apiUrl` → the HTTPS URL of your deployed `api.php`.
   - `apiToken` → the same value as the server's `ACP_API_TOKEN`.
   - Environment variables `ACS_API_URL` / `ACS_API_TOKEN` override the file.

4. **Start Counter-Strike 1.6** and join a server (or stay at the main menu).
5. **Run the scanner**, read the privacy screen and press **Start scan**. The signed report uploads automatically when the scan finishes.

## Verify the download

Every release publishes a SHA-256 checksum. On Windows:

```powershell
Get-FileHash .\ACS-Scanner-1.0.0-windows.exe -Algorithm SHA256
```

Compare it against the value in the release notes. You can also check the build on VirusTotal via the link on the Download page.

## Building from source

```powershell
dotnet restore windows/ACPScanner.csproj
dotnet publish windows/ACPScanner.csproj -c Release
```

Output is a single executable in `windows/release/`. The optional kernel helper in `windows/acpdriver/` is a reference scaffold and needs the WDK + a signed certificate before it can be built or loaded.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Upload fails / 401 | `apiToken` on the client must equal `ACP_API_TOKEN` on the server. |
| Upload fails / local-only | The server has no `ACP_API_TOKEN` set; uploads are local-only until it is. |
| "No game found" | Counter-Strike (`hl.exe`) must be running before you scan. |
| Thin memory evidence | Run the scanner as administrator. |
| Firewall prompt the first run | Allowed — the app calls your `api.php` over HTTPS. |
| "Windows protected your PC" | SmartScreen warns about every new unsigned app; the scanner is not code-signed yet. Check the SHA-256 (see *Verify the download*), then **More info → Run anyway**. |

See also: [FAQ](FAQ.md) · [Deployment](DEPLOYMENT.md) · [Security](../SECURITY.md)
