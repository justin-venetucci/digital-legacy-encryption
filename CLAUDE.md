# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Two interactive terminal wizards that wrap the `age` CLI plus the `age-plugin-sss` Shamir Secret Sharing plugin, so that a sensitive document can be encrypted once and later decrypted only when *N of M* keyholders bring their key files together. `decrypt.py` is aimed at non-technical beneficiaries, which is why it is heavy on step banners, spinners, and per-error recovery prompts.

## Commands

```bash
python internals/scripts/encrypt.py    # encrypt a file, optionally generating new key shares
python internals/scripts/decrypt.py    # collect key shares and decrypt
```

The root wrappers `Decrypt My Information-Windows.bat` / `Decrypt My Information-MacOS.sh` are the shipped entry points for beneficiaries. They activate a `.venv` at the repo root and use relative paths, so they only work when run with the repo root as the working directory, and only after a venv exists there. Nothing in the repo creates that venv.

Sanity-check the vendored binaries (they are not in git — see below):

```bash
internals/binaries/age --version
```

There is no test suite, linter, build step, CI, or `requirements.txt`. The only real verification is a manual round trip: run `encrypt.py` on a throwaway file, then `decrypt.py` with the generated keys.

**These scripts cannot be run non-interactively.** Both block on `input()` and open Tk file-selection dialogs. Do not try to exercise them end to end from an agent session; verify changes by reading the code, by importing the module and calling individual methods, or by driving `age` / `age-plugin-sss` directly with the same arguments the scripts build.

## Architecture

### Mirrored, deliberately duplicated scripts

`internals/scripts/encrypt.py` (`DigitalLegacyEncryptor`) and `internals/scripts/decrypt.py` (`DigitalLegacyDecryptor`) are independent single-class scripts with no shared module. They repeat the same skeleton — path fields in `__init__`, then `set_up_paths_and_validation()` → `set_up_temp_directory()` → `prepare_environment()` → a `run()` that drives a numbered step wizard — and each carries its own copy of the UI helpers (`_print_colored`, banner, spinner/`show_processing_step`). A change to shared behavior (colors, banners, path layout, binary naming) usually has to be made twice. Keep them independent unless asked otherwise; self-containment is a design goal, not an oversight.

Step counting differs: `decrypt.py` computes `total_steps = threshold + 3` because it prompts once per required key, while `encrypt.py` hardcodes `total_steps = 5` and bumps `current_step` inline.

### Standard library only

No third-party imports anywhere, on purpose ("designed for long-term compatibility"). Consequences to preserve:

- YAML is read with regex and written with f-string concatenation. There is no PyYAML dependency; don't add one.
- File pickers use `tkinter.filedialog`, so a working Tk is an implicit runtime requirement.

### Binary discovery and the PATH trick

Binaries live in `internals/binaries/` and are resolved relative to `__file__`, with `.exe` appended when `os.name == 'nt'`. `prepare_environment()` copies `os.environ`, prepends the binaries directory to `PATH`, and stores it as `self.env`; **every `subprocess.Popen` call must pass `env=self.env`**, because that is how the `age` binary locates the `age-plugin-sss` executable (age resolves plugins by looking up `age-plugin-<name>` on `PATH`).

The binaries are not committed — only `age.exe.placeholder`, `age-keygen.exe.placeholder`, `age-plugin-sss.exe.placeholder`, and the plugin's vendored `LICENSE.txt`. Both scripts fail up front with a "Missing required files" list if the real executables are absent, so that error is the expected state in a fresh clone.

### Single-file-by-convention in `internals/encrypted/`

`internals/encrypted/` must hold exactly one `*.age` file and exactly one `*.yaml` file; both scripts `glob()` for them and treat *more than one* as a fatal error, never picking a "default" name. `decrypt.py` errors if either is missing; `encrypt.py` instead writes a blank `recipients.yaml` skeleton when no yaml is present. Any feature that adds a second encrypted file or a second config in that folder breaks both scripts.

### Crypto data flow

Encrypt: `age-keygen` once per share → public keys collected into `recipients.yaml` (`threshold:` scalar + `shares:` list of `age1…`) → `age-plugin-sss --generate-recipient recipients.yaml` produces one composite SSS recipient string → `age -e -r <recipient> -o "<name> - Encrypted <date><ext>.age" <source>`. Private keys are written as individual `Key for Digital Legacy - <name>.yaml` files into `internals/age-keys-DISTRIBUTE-AND-DELETE/`; the directory name is the instruction — those files are the only copies of the secrets and are meant to leave the machine.

Decrypt: parse `recipients.yaml` with regex for threshold and public keys → per key file, extract `AGE-SECRET-KEY-…` (matched as `^(AGE-SECRET-KEY-[A-Z0-9]+)$`, MULTILINE) → derive the public key via `age-keygen -y` on stdin → accept only if that public key appears in `recipients.yaml`'s `shares` → once `threshold` distinct keys are accepted, write an `identities:` yaml into the temp dir, run `age-plugin-sss --generate-identity` to get a combined identity, then `age -d -i <identity> -o <output> <file.age>`.

Note that the "wrong key" check is membership in `recipients.yaml`, not a cryptographic test against the ciphertext — it exists to give beneficiaries an immediate, readable error instead of a late `age` failure. Real failure is still caught by matching `"no identity matched any of the recipients"` in age's stderr, which also deletes the partial output file.

Decrypted output goes to the user's Desktop as `[SENSITIVE] <name> - Decrypted <date><ext>`, with a `(n)` counter to avoid overwriting.

### Error handling convention

Each script defines one exception type (`EncryptionError` / `DecryptionError`). Helper methods raise it with a message written for a lay reader; `run()` catches it, prints in red, and — in `decrypt.py`'s key-collection loop — offers a retry rather than exiting. Rejected key paths are recorded in `self.attempted_keys` so the same file can't be submitted twice. New failure modes should follow that pattern: raise the custom exception with an end-user-facing sentence, don't `sys.exit` or let a traceback escape.

## Repo facts that contradict the README

- The README's layout diagram and usage examples show `scripts/`, `sample-keys/`, and `encrypted/` at the repo root. They are all under `internals/`.
- The README links `LICENSE.txt`; the project license file is `LICENSE`. `internals/binaries/LICENSE.txt` is the vendored `age-plugin-sss` license, not this project's.
- `decrypt.py`'s file dialog opens in `internals/keys`, a directory that does not exist; the demo shares are in `internals/sample-keys/`.

## Working in this repo

There is no `.gitignore`. Running `encrypt.py` inside a clone leaves real private keys in `internals/age-keys-DISTRIBUTE-AND-DELETE/` and real ciphertext in `internals/encrypted/`, all of them untracked-but-uncovered and easy to commit by accident. The committed `internals/sample-keys/*.yaml` and the sample `.age` PDF are intentional demo material and match the committed `recipients.yaml`; leave that set consistent, since it is the only working end-to-end example.
