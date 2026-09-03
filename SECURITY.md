# Security model

What this tool protects, what it does not, and where the sharp edges are. Read
this before trusting anything real to it.

## What it is

A document is encrypted with [`age`](https://age-encryption.org) to a composite
recipient produced by [`age-plugin-sss`](https://github.com/olastor/age-plugin-sss),
which implements Shamir Secret Sharing over the file key. `M` X25519 keypairs are
generated; any `N` of the private keys reconstruct the file key, and fewer than
`N` reveal nothing about it.

All cryptography is done by `age` and the plugin. This project generates no key
material of its own, implements no primitives, and rolls nothing by hand. Its
job is orchestration, validation, and telling a non-technical person what to do.

## What it protects against

- **Someone reading the encrypted file.** Without `N` shares it is
  indistinguishable from noise. It is safe to store on a cloud drive, a USB
  stick left with a will, or a public repository.
- **A single keyholder acting alone** (when `N > 1`). One share reveals nothing.
- **Losing a keyholder** (when `N < M`). The remaining shares still work.
- **Silent corruption.** `vault.json` records SHA-256 of both plaintext and
  ciphertext; `doctor` compares them, and decryption checks the recovered file
  against the recorded plaintext digest.
- **Producing a file that cannot be opened again.** Encryption is not reported as
  successful until a random `N`-sized subset of the fresh shares has actually
  decrypted the result back to a byte-identical copy.

## What it does not protect against

Stated plainly, because a legacy tool that oversells itself is worse than none.

- **A compromised machine.** If the computer running encryption or decryption is
  compromised, so is the document. There is no defence here against a keylogger,
  a malicious Python, or a tampered `age` binary.
- **`N` keyholders colluding.** That is the design, not a flaw. Choose `N` with
  that in mind.
- **Losing more than `M − N` shares.** The document is then unrecoverable by
  anyone, including the authors of this software and the authors of `age`. There
  is no backdoor, no recovery service, and no support address that can help.
- **Coercion.** Someone who can compel `N` keyholders can read the document.
- **Metadata.** The ciphertext's filename, size, and modification time are
  visible, as are the *number* of shares and the threshold — `age-plugin-sss
  --inspect` reads them straight out of the file. Keyholder names live in
  `vault.json` in the clear.
- **Memory.** Private keys pass through Python `str` objects, which cannot be
  reliably zeroed and may be copied by the garbage collector or written to a swap
  file or hibernation image. Mitigating this properly needs a different language.
- **Quantum adversaries.** X25519 is not post-quantum. For a document that must
  stay secret for decades against a state-level adversary, this is a real
  consideration.

## Where the secrets are, and for how long

| Material | Location | Lifetime |
|----------|----------|----------|
| Private shares | `internals/age-keys-DISTRIBUTE-AND-DELETE/` | Until *you* delete them. `doctor` nags while they exist. |
| Reconstructed identity | 0700 temp directory | One operation, then overwritten and unlinked. |
| Decrypted document | Desktop, `[SENSITIVE]`-prefixed | Until the beneficiary deletes it. |
| Public keys, threshold | `internals/encrypted/recipients.yaml` | Permanent. Contains no secrets. |

**Overwriting is best-effort.** `shred()` writes random bytes before unlinking,
which removes the easy recovery case. On SSDs with wear levelling, copy-on-write
filesystems, or journalled volumes, the original blocks may survive anyway. Treat
it as hygiene, not erasure.

## File permissions

Key files are created with `O_EXCL` and mode `0600`, so they are never briefly
world-readable between creation and a later `chmod`.

On Windows, POSIX mode bits do not do this — `os.chmod` there only toggles the
read-only attribute, and a new file inherits its parent folder's ACL, which on a
shared machine can mean every local account can read it. The tool therefore also
runs `icacls <file> /inheritance:r /grant:r <user>:F`, stripping inherited
entries and granting only the current account. This is best-effort: it is not
checked, and it does not help against an administrator or against files that have
already been copied elsewhere.

## Trusting the binaries

The three binaries are downloaded by you and are not verified by this tool. A
substituted `age` could exfiltrate the document or encrypt to an attacker's key.

- Download from the official release pages, and verify the checksums those pages
  publish.
- `vault.json` records a SHA-256 prefix of each binary at encryption time, and
  `doctor` reports when one has changed since. That detects drift, not an
  attacker who was present from the start.

## Changing the keyholders

`reseal` re-encrypts a document for a different set of people. Two things about
it are worth understanding:

- **It deletes the old encrypted file, and must.** Shamir shares cannot be
  revoked; the only thing that stops a removed keyholder is the disappearance of
  the ciphertext their key opens. If you have copies elsewhere — a USB stick, a
  cloud drive, a backup — those copies are still readable with the old keys, and
  `reseal` cannot reach them. Destroy them too, or accept that the old
  arrangement persists wherever they live.
- **It cannot un-read what was already read.** Anyone who has already decrypted
  and kept a copy still has it. Resealing changes future access, not past.

## Choosing an arrangement

The cryptography is the reliable part. Estates fail on the human side.

- **`N = 1`** means every keyholder can read the document alone, and one stolen
  key is a full disclosure.
- **`N = M`** means one lost key destroys the document permanently.
- **`N = 2, M = 3`** is the default for a reason: no one acts alone, and one loss
  is survivable.
- Consider whether the keyholders will still be reachable, alive, and on
  speaking terms in fifteen years. Shares held by people who will end up on
  opposite sides of a dispute are shares that will not be combined.
- Keep shares physically separate from the encrypted document. Storing both on
  the same USB stick reduces the whole scheme to "a file on a USB stick".

## Long-term durability

- Share files keep the exact format `age-keygen` emits, so `age -d -i <share>`
  works with a stock `age` install and no plugin, if this tool is ever lost.
- `vault.json` is plain JSON; `recipients.yaml` is a handful of lines of YAML.
  Both are readable without any of this code.
- The real dependency risk is `age-plugin-sss`, a smaller project than `age`. Its
  recipient and identity encodings are what actually gate recovery. Keeping a
  copy of the plugin binary, or of its source, alongside the vault is worthwhile
  for a document you expect to matter in twenty years.

## Reporting a problem

This is a personal project with no security team and no disclosure process. Open
an issue for anything non-sensitive. For a genuine vulnerability, contact the
repository owner directly rather than filing publicly.
