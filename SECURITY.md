# Security and threat model

## Threat model

PyThreatAnalyzer is a local static-analysis tool. Scanned files are treated as untrusted: the application does not execute them or upload them. Some optional components (for example, updating community YARA rules) contact an explicitly configured remote source when the operator invokes that action.

The tool assumes the user controls the application directory, its configuration, and its local data files. It is not a sandbox and does not defend against a local attacker who can modify the application, Python environment, configuration, or trusted model files. Static signatures and heuristics can miss novel threats and can produce false positives.

## ML model trust

Pickle/joblib models are rejected because loading them can execute code. `.skops` is safer but still contains complex serialized objects. Models stored inside the application directory are assumed to have been created or reviewed by the operator. Models outside that directory are rejected unless `trusted_ml_model_sha256` is configured with the expected SHA-256 obtained through an authenticated channel independent of the model file. A neighboring `.sha256` file by itself is not authenticated provenance.

Structural checks after deserialization reduce malformed-tree risks; they do not establish who created a model. Keep the model and configuration writable only by trusted users.

## Coverage and risk are separate

`analysis_status='INCOMPLETE'` means one or more analysis sources failed or were unavailable. It does not itself mean that the file is more or less malicious. `risk_level` is computed from the detections produced by the layers that completed. Review `analysis_warnings` before treating a low-risk result as reassuring.

## Dependencies and rule updates

Install from the hash-locked requirements files. Review lock changes and update them through the documented compiler command. YARA rules are code-like detection inputs and can affect performance and detections; updates require an explicit reviewed commit SHA. Verify commit signatures when the upstream publisher provides them.

Threat-data ingestion is opt-in. Keep `ABUSE_CH_KEY` in the environment only; never commit API credentials, malware samples, or unreviewed community rules. Review `data/NOTICE` and the current source terms before bundling imported data. Run `scripts/check-data-coverage.sh --strict` and verify `data/checksums.txt` before preparing a data-enabled release.

## Release bundle verification

Release automation checks the SHA-256 sidecar before extraction and verifies the detached GPG signature. Configure Actions secret `GPG_PRIVATE_KEY` and `GPG_PASSPHRASE`, plus Actions variables `GPG_PUBLIC_KEY` and `GPG_FINGERPRINT`. The accepted signer is pinned to the configured **primary key fingerprint**; verification must report a GnuPG `VALIDSIG` status and its primary fingerprint must match the pin. A signing subkey is accepted only when GnuPG reports the pinned primary fingerprint. Rotate the pin only after independently authenticating the new primary fingerprint, then update the repository secret and signing key together. ZIP extraction rejects absolute paths, parent traversal, unexpected top-level roots, symlinks, and bundles exceeding the configured entry-count or uncompressed-size limits. On Windows, where ownership checks are unavailable, do not extract releases into directories writable by untrusted users and inspect reparse points/symlinks before trusting the extracted tree.

### Release-signing key

Release ZIP files and their SHA-256 sidecars are signed with a detached GPG
signature. The primary-key fingerprint is:

```
69C1 1E55 7CF2 0CC9 B3C2 C2CA A91A 7A5A A603 461C
```

Before trusting a release, import the public key, confirm that
`gpg --fingerprint` shows exactly the fingerprint above, and verify both
signatures and the checksum:

```sh
gpg --verify PyThreatAnalyzer_X.Y.Z.zip.sha256.asc PyThreatAnalyzer_X.Y.Z.zip.sha256
sha256sum --check PyThreatAnalyzer_X.Y.Z.zip.sha256
gpg --verify PyThreatAnalyzer_X.Y.Z.zip.asc PyThreatAnalyzer_X.Y.Z.zip
```

A "Good signature" from a different fingerprint must be rejected. The release
workflow performs the same fingerprint comparison before publishing.

## Log directory

The log directory must be trusted. `setup_logging` refuses a log directory (or log file) that is a symlink, and refuses ancestor symlinks owned by non-root users; symlinks owned by root (for example `/tmp`, `/var`) are tolerated. On Windows ownership cannot be checked.

## Reporting vulnerabilities

Do not include malware samples, secrets, or personal data in public reports. Report security issues privately to the project maintainer and include the affected version, reproduction steps, and impact. Add a maintainer contact address before publishing this file; none was supplied for this project.
