# Developer validation — 1.0.0

Performed locally on 64-bit Windows, 2026-09-14, including the scanner's system probes run as a 32-bit process. These are maintainer-run checks, not an independent audit or malware certification.

| Check | Result |
| --- | --- |
| Self-contained single-file 32-bit Release publish (runs on 32-bit and 64-bit Windows) | Succeeded; 0 errors, 130 compiler warnings |
| Desktop regression checks | 54 passed; system probes also run as a 32-bit process on 64-bit Windows (10 passed) |
| Backend regression suites | 8 suites passed; 133 assertions |
| Signature-feed validation | 5 tests passed |

Desktop checks cover ordinary binds versus recursive scripts, disguised executable configs, informational severity, verified file hashes versus hash-looking filenames, HTTPS requirements, cancellation, file-budget coverage, upload consent failing closed, the privacy notice, signature classification (modified versus forged), module trust by install location, and client identity from Authenticode signatures and Steam DLL load paths.

Backend checks cover identity/risk handling, compatibility-profile boundaries, signed report ingestion and server-side recomputation, report access controls, indexing, release reputation, and the report page using the scanner's signature-verified client verdict.

Client identity was additionally checked against two real installations on the development machine: a retail Steam Half-Life (verified Steam; Valve-signed launcher and engine) and a non-Steam ESK edition (identified as non-Steam; engine carries Valve's signature over modified contents).

Compiler warnings remain, chiefly nullable reference analysis and native structure fields. The executable is unsigned.

## Limits

This release has no demonstrated real-world detection-rate, false-positive-rate, or scan-speed benchmark across the claimed client families. Passing synthetic compatibility tests is not a certification for every client build. No claim of superiority to VAC, WarGods, or other products is established.

The executable has no configured report API. GitHub hosts downloads and documentation, not the report backend. An operator must deploy and configure that separately before players can scan.

Private source and test fixtures remain outside this repository. Public readers cannot independently reproduce those source-level tests from this distribution repository alone.
