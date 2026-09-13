# Verify ACS 3.3.1-beta.1

Download only from [cstrikelonghorn/LongHorn-ACS Releases](https://github.com/cstrikelonghorn/LongHorn-ACS/releases). The ZIP filename is `ACS-Scanner-3.3.1-beta.1-win-x64.zip`. The public repository contains release documentation; the scanner source remains private.

## Verify the exact file

Download `CHECKSUMS.sha256` from the same tagged release and compare the ZIP hash:

```powershell
Get-FileHash .\ACS-Scanner-3.3.1-beta.1-win-x64.zip -Algorithm SHA256
```

After extraction, compare `ACPScanner.exe` and `ACPScanner.dll` with the published checksums. `FILE-MANIFEST.json` lists hashes for all packaged files. A matching checksum detects differences from the published file; it does not prove safety or protect you if the publisher's release account is compromised.

## Publisher signature

```powershell
Get-AuthenticodeSignature .\ACS-Scanner\ACPScanner.exe
Get-AuthenticodeSignature .\ACS-Scanner\ACPScanner.dll
```

**This beta is unsigned.** Expected status for the app's own EXE and DLL: `NotSigned`. No trusted publisher certificate was available during preparation. Some bundled Microsoft runtime files have their own signatures; those do not sign ACS. Signing and timestamping must occur before generating a future release's final checksums.

Windows reputation warnings may occur. Do not disable antivirus, SmartScreen, or other protections to use this app. A signed release would identify its publisher and protect signed-file integrity; signing alone is not a safety certification.

## Independent review and antivirus status

No independent security audit or verified antivirus analysis of this exact release has been completed. Automated regression tests are developer checks, not a malware scan. No simulated vendor results or clean certificates are published. Reviewers can request confidential access through the maintainer's GitHub profile; no review or NDA has been represented as completed.

Standard online malware-scanning submissions may share uploaded files with security partners. Submit only a distributable release file, never settings containing secrets or player reports. Interpret detections individually; zero detections does not prove absence of abusive behavior.

References: [GitHub Releases](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases), [Microsoft signing and reputation](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation), [Microsoft software submissions](https://www.microsoft.com/en-us/wdsi/filesubmission).
