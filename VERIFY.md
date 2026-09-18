# Verify ACS 1.1.0

Download only from [cstrikelonghorn/LongHorn-ACS Releases](https://github.com/cstrikelonghorn/LongHorn-ACS/releases). The release file is the single executable `ACS-Scanner-1.1.0-windows.exe`. The public repository contains release documentation; the scanner source remains private.

## Verify the exact file

Download `CHECKSUMS.sha256` from the same tagged release and compare:

```powershell
Get-FileHash .\ACS-Scanner-1.1.0-windows.exe -Algorithm SHA256
```

Expected SHA-256: `7fade053e82a466e01f72de6c72e302a3a5837b098230a1f2fa5f9d610557b13`

`FILE-MANIFEST.json` lists every release file with its size and hash. A matching checksum detects differences from the published file; it does not prove safety or protect you if the publisher's release account is compromised.

Every report ACS uploads records the first 12 characters of this SHA-256 as its build fingerprint (`7fade053e82a` for this release), so a report can always be traced to the exact executable that produced it.

## Publisher signature

```powershell
Get-AuthenticodeSignature .\ACS-Scanner-1.1.0-windows.exe
```

**This release is unsigned.** Expected status: `NotSigned`. No trusted publisher certificate was available during preparation. Signing and timestamping must occur before generating a future release's final checksums.

Windows reputation warnings may occur. Do not disable antivirus, SmartScreen, or other protections to use this app. A signed release would identify its publisher and protect signed-file integrity; signing alone is not a safety certification.

## Independent review and antivirus status

No independent security audit or verified antivirus analysis of this exact release has been completed. Automated regression tests are developer checks, not a malware scan. No simulated vendor results or clean certificates are published.

Standard online malware-scanning submissions may share uploaded files with security partners. Submit only the distributable release file, never settings containing secrets or player reports. Interpret detections individually; zero detections does not prove absence of abusive behavior.

References: [GitHub Releases](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases), [Microsoft signing and reputation](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation), [Microsoft software submissions](https://www.microsoft.com/en-us/wdsi/filesubmission).
