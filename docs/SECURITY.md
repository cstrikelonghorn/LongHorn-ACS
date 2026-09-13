# Security reporting

This is a prerelease. Independent audit, publisher signing, adversarial testing, and a full live-client compatibility matrix remain outstanding.

If the repository's Security tab offers **Report a vulnerability**, use it for private reports. Private vulnerability reporting must be enabled by the repository owner; do not assume it is enabled. Otherwise open a minimal issue requesting a private contact channel, without exploit details, credentials, player identifiers, private report links, or attachments containing personal data.

Include the version and SHA-256, expected and observed behavior, and a minimal reproduction using synthetic data. Do not test against other players or third-party servers without their permission. No bug-bounty payment or response-time commitment is offered here.

Security properties have limits: the client runs on a player-controlled machine; a shared client token is not hardware attestation; code secrecy does not prevent reverse engineering. Server administrators must protect secrets, authenticated access, report retention and storage outside the public web root.

Maintainer: [cstrikelonghorn](https://github.com/cstrikelonghorn).
