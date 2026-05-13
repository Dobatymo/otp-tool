# TODO

- Add backwards-compatible Argon2id support by storing the KDF algorithm in new database metadata, continuing to read existing Argon2i files, and optionally re-encrypting with Argon2id during password changes or an explicit migration command.
- Add a HOTP counter increment workflow. HOTP entries can be displayed, but there is currently no command or UI flow to advance and persist the counter after using a code.
- Ensure Argon2 opslimit and memlimit are configurable during initial database creation. The knobs exist for password changes, but database initialization currently does not expose or apply them explicitly.
