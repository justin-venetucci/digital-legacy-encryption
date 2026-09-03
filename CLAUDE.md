# CLAUDE.md

Guidance for Claude Code (claude.ai/code) working in this repository.

## What this is

A tool that encrypts one document so it can only be decrypted when *N of M*
keyholders bring their key files together. It wraps the `age` CLI plus the
`age-plugin-sss` Shamir Secret Sharing plugin.

The decryption path is aimed at **non-technical beneficiaries**, probably
grieving, using it once, with nobody to ask. That constraint drives most of the
design: plain-language errors with actionable hints, a retry on every rejection,
and printable paperwork explaining what a key file is.

## Commands

```bash
python internals/scripts/encrypt.py            # guided encryption wizard
python internals/scripts/decrypt.py            # guided decryption wizard
python internals/scripts/encrypt.py --doctor   # health check (read-only)
python tests/run_tests.py                      # the whole suite
```

Everything is also reachable non-interactively, which is how the suite drives it:

```bash
python internals/scripts/encrypt.py --file DOC --shares 3 --threshold 2 \
       --name Alice --name Bob --name Carol --owner "Name"
python internals/scripts/decrypt.py --key K1.yaml --key K2.yaml --output DIR
python internals/scripts/encrypt.py check-key FILE
python internals/scripts/encrypt.py inspect
python internals/scripts/encrypt.py handoff
python internals/scripts/encrypt.py reseal --key K1 --key K2 \
       --shares 3 --threshold 2 --name Alice --name Bob --name Dad
```

Root-level `.bat` / `.command` / `.sh` wrappers are the shipped entry points.
They locate a Python themselves and no longer require a `.venv`.

## Architecture

### One package, two thin entry points

`internals/digital_legacy/` holds everything. `internals/scripts/encrypt.py` and
`decrypt.py` are ~40-line shims that add `internals/` to `sys.path` and call
`digital_legacy.cli`; they exist at those paths because every wrapper and every
set of instructions already points there.

| Module | Responsibility |
|--------|----------------|
| `errors.py` | One exception hierarchy. Every error carries a lay-reader `message` and an actionable `hint`. |
| `console.py` | All terminal I/O. Colour (with Windows VT enabling), banners, step numbering, honest progress, validated prompts. |
| `picker.py` | File selection: lazy Tk import, typed-path fallback. |
| `layout.py` | Every "which folder?" answer. Honours `DIGITAL_LEGACY_ROOT`. |
| `toolchain.py` | Binary discovery and the *only* way to run one. |
| `agekeys.py` | Key generation, parsing, share files, permissions, shredding. |
| `policy.py` | `recipients.yaml` parse / validate / render. |
| `vault.py` | The encrypted folder, `vault.json`, integrity checks. |
| `sss.py` | `age-plugin-sss` wrapper; secure temp directories. |
| `operations.py` | encrypt / verify / decrypt orchestration. |
| `handoff.py` | Printable letters and checklists. |
| `doctor.py` | Read-only health check. |
| `wizards.py` | The two guided flows. |
| `cli.py` | argparse dispatch. |

An earlier version of this project deliberately kept two independent, hand-copied
scripts. That was reverted: the copies drifted and each grew defects the other
lacked. The property worth preserving — a beneficiary needs nothing but a Python
interpreter — comes from having **no third-party dependencies**, not from having
two copies of the code.

### Standard library only

No runtime dependencies, on purpose, and none should be added.

- YAML is parsed by a small strict subset parser in `policy.py`. Do not add
  PyYAML. `recipients.yaml` must stay YAML because `age-plugin-sss` consumes it;
  everything else this tool writes is JSON.
- Tk is imported lazily. A missing Tk must degrade to a typed path, never crash.
- Tests use `unittest`, not pytest, so the suite has the same footprint as the
  shipped code.

### Binary discovery and the PATH trick

`age` finds plugins by looking up `age-plugin-<name>` on `PATH`, so every
subprocess runs with the binaries directory prepended. `Toolchain.run` is the
single code path for this and cannot forget it.

**The directory must be absolute.** Go's `exec.LookPath` refuses a hit that
resolves inside the current directory (`"age-plugin-sss resolves to executable in
current directory"`), so a relative `PATH` entry breaks decryption outright.
`Toolchain.discover` and `build_env` both call `.resolve()`.

Binaries are not committed — only `*.placeholder` files and the vendored
`LICENSE.txt`. A fresh clone therefore fails discovery with a checklist, and the
integration tests skip themselves. That is the expected state.

### The vault

`internals/encrypted/` holds the ciphertext, exactly one `*.yaml` policy file,
and an optional `vault.json`.

- **More than one `.yaml`** is still fatal — guessing which applies could encrypt
  to the wrong people.
- **More than one `.age`** is *not* fatal any more. The decrypt wizard asks which
  to open. Running the old encryptor twice created this state and bricked the
  vault permanently.
- **`vault.json` is optional.** Pre-2.0 vaults still open through a corrected
  filename parser, and a damaged manifest never blocks decryption.
- Plaintext stem and suffix are stored *separately*. Never re-derive an extension
  by splitting a display filename; that is the bug that produced files nothing
  could open.

### Crypto data flow

**Encrypt** — `age-keygen` once per share → public keys into `recipients.yaml`
→ `age-plugin-sss --generate-recipient` → one composite recipient →
`age -e -r <recipient>`. Written to a `.partial` name and renamed on success.

**Verify** — a random threshold-sized subset of the fresh shares reconstructs an
identity, decrypts to a scrubbed temp file, and its SHA-256 is compared to the
source. **Encryption is not reported as successful until this passes.** Do not
weaken this; it is the feature that makes the tool trustworthy.

**Decrypt** — each key file's secret is derived to a public key and checked for
membership in `recipients.yaml` (a readable early error, not a cryptographic
test) → `age-plugin-sss --generate-identity` → `age -d -i`. Real failure is still
caught from age's stderr, which also shreds the empty output file age created.

Output goes to the Desktop as `[SENSITIVE] <name> - Decrypted <date><ext>`,
falling back to the home directory when there is no Desktop.

**Reseal** — decrypt with the current keys into a scrubbed temp dir, re-encrypt
under a new policy, verify, then delete the old ciphertext. Deleting it is not
optional politeness: leaving it means every removed keyholder still has access
and the reseal accomplished nothing. Stale key files are *named*, never deleted
— the folder may hold a share for another vault, and destroying a secret on a
guess is irreversible. The staleness check must run *after* the new shares are
written, or it names files that are about to be overwritten.

### Conventions to preserve

- **Errors**: raise a `DigitalLegacyError` subclass with a plain sentence and a
  hint. Never `sys.exit`, never let a traceback reach the user.
- **Secrets**: over stdin, never argv. Files created `O_EXCL` 0600, plus `icacls`
  on Windows. Overwrite before unlinking.
- **Progress**: use `console.task(...)` as a context manager so the outcome
  reflects what happened. Never pass a hardcoded success.
- **Step numbers**: `console.set_steps()` then `console.banner()`. Do not
  hand-count.

## Testing

```bash
python tests/run_tests.py
```

Two layers: `FakeToolchain` for logic (fast, runs anywhere) and real-binary
integration tests that skip when `age` is absent. `tests/support.py` refuses to
run against the working copy — an early version of the wizard tests let the CLI
discover its own layout and overwrote the committed sample vault. Always pass
`layout=` explicitly when calling `cli.main` from a test.

`internals/encrypted/` ships a working sample (a PDF, 2 of 3, shares in
`internals/sample-keys/`). The suite decrypts it on every run so it cannot
silently rot. Keep that set consistent.

## Working in this repo

`.gitignore` covers generated private keys, real ciphertext, the handoff folder,
and the binaries, while allowing the intentional sample vault through. Check it
still holds before adding anything to `internals/encrypted/`.
