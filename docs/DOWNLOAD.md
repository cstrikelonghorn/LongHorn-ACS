# Download & Install

> **The scanner only runs while Counter-Strike is already open.** It attaches to a live `hl.exe` — there is nothing to inspect otherwise.

## Requirements

| | |
|---|---|
| OS | Windows 10 / 11 (x64) |
| Game | Counter-Strike 1.6 (`hl.exe` / `cstrike.exe`) |
| Runtime | .NET (bundled in the self-contained build) |
| Rights | Administrator recommended (deeper memory/process evidence) |
| Server | A reachable ACS web deployment (`api.php`) |

## Install

1. **Get the release.** Download the latest `ACS-Scanner-vX.Y.Z.zip` from the repository **Releases**, or from the project Download page.
2. **Extract** it anywhere (e.g. `C:\Tools\ACS`).
3. **Configure** `acp-settings.json` next to the executable:

   ```json
   {
     "apiUrl": "https://your-host/acp/api.php",
     "apiToken": "THE_SAME_VALUE_AS_ACP_API_TOKEN"
   }
   ```

   - `apiUrl` → the HTTPS URL of your deployed `api.php`.
   - `apiToken` → the same value as the server's `ACP_API_TOKEN`.
   - Environment variables `ACP_API_URL` / `ACP_API_TOKEN` override the file.

4. **Start Counter-Strike 1.6** and join a server (or stay at the main menu).
5. **Run the scanner**, press **Scan**, and let it finish. The signed report uploads automatically.

## Verify the download

Every release publishes a SHA-256 checksum. On Windows:

```powershell
Get-FileHash .\ACS-Scanner-v3.3.0.zip -Algorithm SHA256
```

Compare it against the value in the release notes. You can also check the build on VirusTotal via the link on the Download page.

## Building from source

```powershell
dotnet restore windows/ACPScanner.csproj
dotnet publish windows/ACPScanner.csproj -c Release -r win-x64 --self-contained
```

Output lands in `windows/publish/`. The optional kernel helper in `windows/acpdriver/` is a reference scaffold and needs the WDK + a signed certificate before it can be built or loaded.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Upload fails / 401 | `apiToken` on the client must equal `ACP_API_TOKEN` on the server. |
| Upload fails / local-only | The server has no `ACP_API_TOKEN` set; uploads are local-only until it is. |
| "No game found" | Counter-Strike (`hl.exe`) must be running before you scan. |
| Thin memory evidence | Run the scanner as administrator. |
| Firewall prompt the first run | Allowed — the app calls your `api.php` over HTTPS. |

See also: [FAQ](FAQ.md) · [Deployment](DEPLOYMENT.md) · [Security](../SECURITY.md)
