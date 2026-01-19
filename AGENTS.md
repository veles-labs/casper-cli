## Operational Notes

- Avoid TOCTOU patterns when deleting files. Prefer a direct remove and ignore `NotFound` errors instead of `exists()` checks.
- Do not suppress deprecation warnings with `#[allow(deprecated)]`; update code to remove deprecated APIs.
- Prefer memory-hard KDFs (Argon2id/scrypt) with documented parameters; avoid plaintext secrets unless explicitly requested (e.g., `--unencrypted`) and warn loudly.
- Zeroize sensitive buffers and avoid cloning secret material unless necessary.
- Use AEAD with unique nonces and bind context via AAD when encrypting secrets.
- Fail closed on crypto errors; never ignore authentication/decryption failures.
- Use atomic writes and restrictive file permissions (0600 files, 0700 dirs) for secret material.
- Before finishing a task, run at least `cargo check` and report failures.
- Keep `README.md` in sync with user-facing command changes and behaviors.
- Update `CHANGELOG.md` for user-facing changes; list them under `[Unreleased]` in the appropriate section.
- Avoid backward-compatibility defaults or legacy migrations unless explicitly requested.
