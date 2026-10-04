# Changelog

## 2.0.0 — 2026-10-04

A rewrite. The two hand-copied 500-line scripts of 1.0 became one tested package,
and the project gained the feature it most needed: proof that what it encrypts
can be opened again.

### Added

- **Round-trip proof.** Encryption is not reported as successful until a random
  threshold-sized subset of the new keys has decrypted the result back to a
  byte-identical copy.
- **`reseal`**: re-encrypt for a different set of keyholders without the
  plaintext leaving a scrubbed temporary folder. Deletes the old ciphertext, so a
  removed keyholder's key stops working, and names the key files that are now dead.
- **`doctor`**: a read-only health check of binaries, key list, checksums, and
  the threshold sealed inside the ciphertext. `check-key` and `inspect` answer the
  narrower questions.
- **`vault.json`**: records original filename and extension separately, sizes and
  SHA-256 of plaintext and ciphertext. Optional; a damaged one never blocks
  decryption.
- **Handoff paperwork**: a letter per keyholder, `READ ME FIRST.txt` for whoever
  finds the vault, and a distribute-then-delete checklist for the owner.
- **`tools/build_release.py`**: compiles the decryptor with Nuitka and packages it
  for beneficiaries who have no Python, refusing to include private keys or
  decrypted documents.
- **Shared-folder handoff profile** (`--shared-folder`, `--key-prefix`,
  `--key-notes`) for owners who keep each key in a cloud folder shared per person.
- Launchers for macOS (`.command`) and Linux, and an owner-facing encrypt launcher.
- A test suite (161 tests, standard library `unittest`), CI on three platforms,
  `SECURITY.md`, and architecture notes.

### Fixed

- A threshold written inside a YAML comment was read as the real one.
- A threshold larger than the number of keys encrypted happily and could never
  be opened.
- A filename containing a dot (`taxes 2024.1.pdf`) decrypted to a file with a
  mangled extension that nothing would open.
- Running the encryptor twice left two `.age` files and a vault that refused to
  decrypt. The wizard now asks which to open.
- A relative binaries path broke decryption outright, because `age` refuses a
  plugin that resolves inside the current directory.
- The Windows launcher activated a virtual environment nothing created, fell
  through to the Microsoft Store stub, and closed its window on every error.
- Progress lines reported "Done" for work that had failed, and the wizard could
  finish on "Step 6 of 5".
- A Python without Tk crashed on import; it now falls back to a typed path.
- Keyholder names containing path separators or Windows device names could write
  a key outside the keys folder, or fail after the key was generated.
- Key material is redacted from anything the binaries print before it reaches
  the screen.
- Saving any file failed on Python 3.9, the oldest supported version, because of
  an argument `Path.write_text` only gained in 3.10. Found by the first CI run.
- On Windows with OneDrive folder backup, output went to an empty `~/Desktop`
  nobody looks at.

### Changed

- Standard library only, including a strict parser for the YAML subset in
  `recipients.yaml`.
- Secrets are passed over stdin, never on a command line; key files are created
  exclusively with owner-only permissions and overwritten before deletion.

## 1.0.0 — 2025-05-27

Initial public version: a Python port of a PowerShell original. Two standalone
scripts wrapping `age` and `age-plugin-sss`, with a sample vault.
