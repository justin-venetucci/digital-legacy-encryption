# Digital Legacy Encryption Suite

Encrypt a document — a password list, account inventory, letter, or anything
else — so that it can only be opened again when **several people bring their
keys together**. No single person can read it alone, and no single person losing
their key can lock everyone else out.

Built on [`age`](https://age-encryption.org) and
[`age-plugin-sss`](https://github.com/olastor/age-plugin-sss) (Shamir Secret
Sharing). The Python around them is standard-library only, so a beneficiary in
twenty years needs nothing but a Python interpreter and three small binaries.

```
                     ┌──────────────┐
   Your document ───▶│  encrypt.py  │───▶  one .age file  (safe to store openly)
                     └──────┬───────┘
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
          Key: Alice    Key: Bob     Key: Carol      any 2 of the 3 → document
```

---

## For a beneficiary: how to open the document

Someone has given you a folder or a drive containing this project. You do not
need to understand any of it.

1. Open the folder and read **`internals/encrypted/READ ME FIRST.txt`** — it
   names the keyholders and says how many keys are needed.
2. Collect that many key files from the people listed. Each is a small text file
   named `Key for Digital Legacy - <name>.yaml`.
3. Run the launcher for your computer:

   | Computer | Double-click |
   |----------|--------------|
   | Windows  | `Decrypt My Information-Windows.bat` |
   | macOS    | `Decrypt My Information-macOS.command` |
   | Linux    | `Decrypt My Information-Linux.sh` |

4. Follow the prompts. It asks for each key file in turn, tells you if one is
   the wrong file or has been damaged, and writes the document to your Desktop.

If a key file turns out to be wrong, the program says so and lets you try
another — you do not have to start over.

---

## For the owner: setting it up

### 1. Get the three binaries

They are **not** included in this repository: they are separately licensed,
platform-specific, and 8–20 MB each. Download them and put them in
`internals/binaries/`:

| File | Where from |
|------|-----------|
| `age`, `age-keygen` | <https://github.com/FiloSottile/age/releases> |
| `age-plugin-sss` | <https://github.com/olastor/age-plugin-sss/releases> |

On Windows they need the `.exe` extension (`age.exe`, `age-keygen.exe`,
`age-plugin-sss.exe`); on macOS and Linux, no extension plus
`chmod +x internals/binaries/*`.

Package managers work too — `choco install age` on Windows, `brew install age`
on macOS — but note that Chocolatey installs a *shim*, not the real executable;
copy the binary from `C:\ProgramData\chocolatey\lib\age.portable\tools\age\`.

Check it worked:

```bash
python internals/scripts/encrypt.py --doctor
```

### 2. Encrypt something

```bash
python internals/scripts/encrypt.py
```

The wizard asks for the document, how many keys should exist, how many are
needed to open it, and who holds each one. Then — and this is the part worth
knowing about — it **decrypts the file it just wrote**, using a random subset of
the new keys, and compares it against the original. It will not tell you it
succeeded until it has demonstrated that the document can be recovered.

It produces:

```
internals/encrypted/                        ← store and copy this freely
    <document> - Encrypted <date>.<ext>.age     the ciphertext
    recipients.yaml                             which keys can open it
    vault.json                                  filenames, sizes, checksums
    READ ME FIRST.txt                           instructions for beneficiaries

internals/age-keys-DISTRIBUTE-AND-DELETE/   ← hand out, then delete
    Key for Digital Legacy - Alice.yaml
    ...

internals/handoff/                          ← print, hand out, then delete
    Letter for Alice.txt                        what Alice is holding and why
    WHAT TO DO NEXT.txt                         your distribution checklist
```

### 3. Hand out the keys, then delete them

Give each keyholder their key file **and** their letter. Then delete
`age-keys-DISTRIBUTE-AND-DELETE/` and `handoff/`. While those folders exist,
every key is sitting on one computer — the exact situation the whole scheme
exists to avoid.

Copy `internals/encrypted/` (or the whole project folder) somewhere your family
will actually look: a USB stick with your will, a cloud drive, a home safe. It
is safe to store openly. Then **tell someone it exists** — a perfectly built
system nobody knows about is the most common way this fails.

### 4. When a keyholder changes

People move, fall out, die, or lose their copy. Shamir cannot add or remove a
share after the fact — the threshold is sealed into the ciphertext — so the only
way to change the arrangement is to encrypt again:

```bash
python internals/scripts/encrypt.py reseal --key K1.yaml --key K2.yaml \
       --shares 3 --threshold 2 --name Alice --name Bob --name Dad
```

It opens the document with the keys you supply, re-encrypts it for the new
keyholders, proves the result recovers, and **deletes the old encrypted file** —
because anyone holding an old key could still open that. It then names the key
files that no longer open anything, so you do not hand out a dead one. It never
deletes a key file itself: destroying a secret on a guess is not reversible.

The plaintext never leaves a scrubbed temporary folder during any of this.

### 5. Check it once a year

```bash
python internals/scripts/encrypt.py --doctor
```

Verifies the binaries still run, the key list is still valid and consistent with
the ciphertext, checksums still match, and no private keys have been left lying
around. Takes a second and catches the kind of rot — antivirus quarantine, a
mangled cloud sync, a tidied folder — that otherwise surfaces at the worst
possible moment.

---

## Choosing a threshold

| Arrangement | What it means |
|-------------|---------------|
| **2 of 3** | The usual choice. Any two of three people can open it; any one alone cannot; losing one key is survivable. |
| 3 of 5 | More redundancy, more people to convene. |
| 1 of N | Every keyholder can open it alone. Convenient, but one lost or stolen key is a full disclosure. |
| N of N | One lost key makes the document **permanently unrecoverable**. The wizard warns you. |

Think about who will still be reachable, and on speaking terms, in fifteen
years. The failure mode is rarely cryptographic.

---

## Command reference

Everything the wizards do is also available as flags, which is how the test
suite drives it.

```bash
python internals/scripts/encrypt.py                    # guided wizard
python internals/scripts/decrypt.py                    # guided wizard

# non-interactive
python internals/scripts/encrypt.py --file DOC --shares 3 --threshold 2 \
       --name Alice --name Bob --name Carol --owner "Your Name"
python internals/scripts/decrypt.py --key K1.yaml --key K2.yaml --output DIR

python internals/scripts/encrypt.py reseal --key K1.yaml --key K2.yaml \
       --shares 3 --threshold 2 --name Alice --name Bob --name Dad
python internals/scripts/encrypt.py --doctor [--deep]  # health check
python internals/scripts/encrypt.py check-key FILE     # is this key still valid?
python internals/scripts/encrypt.py inspect            # what the .age file requires
python internals/scripts/encrypt.py handoff            # reprint the letters
```

`DIGITAL_LEGACY_ROOT` points the tool at a different project folder, which is
useful when the vault lives on removable media.

---

## How it works

**Encrypting.** `age-keygen` creates one X25519 keypair per share. The public
keys go into `recipients.yaml` with a threshold; `age-plugin-sss
--generate-recipient` turns that into a single composite recipient string, and
`age -e -r <recipient>` encrypts to it. The threshold is sealed into the
ciphertext — editing `recipients.yaml` afterwards does not change a file that
has already been written.

**Decrypting.** Each key file's private key is checked against the public keys in
`recipients.yaml`, so a wrong file is reported immediately rather than as a late,
cryptic `age` failure. Once enough distinct keys are present, `age-plugin-sss
--generate-identity` combines them and `age -d -i` decrypts.

Private keys are held in a 0700 temporary directory and overwritten before
deletion. They are passed to `age-keygen` over stdin, never on the command line
where the process table would expose them.

**Durability.** Key share files keep the exact format `age-keygen` emits, with
everything else as comments. That means `age -d -i "Key for Digital Legacy -
Alice.yaml"` works directly, so a share stays usable with a bare `age` install
even if this tool is lost. See [SECURITY.md](SECURITY.md) for the threat model
and the honest list of what this does not protect against.

---

## Repository layout

```
├── Decrypt My Information-Windows.bat      launchers for beneficiaries
├── Decrypt My Information-macOS.command
├── Decrypt My Information-Linux.sh
├── Encrypt My Information-Windows.bat
├── internals/
│   ├── binaries/          age, age-keygen, age-plugin-sss (not committed)
│   ├── digital_legacy/    the package
│   ├── scripts/           encrypt.py, decrypt.py entry points
│   ├── encrypted/         the vault: ciphertext + recipients.yaml + vault.json
│   └── sample-keys/       demo shares for the committed sample document
├── tests/                 run with: python tests/run_tests.py
├── SECURITY.md
└── LICENSE
```

`internals/encrypted/` ships with a working sample: a PDF encrypted 2 of 3,
whose three shares are in `internals/sample-keys/`. It is the project's only
end-to-end example and the test suite decrypts it on every run, so it cannot
silently rot. Replace it when you encrypt something real.

## Testing

```bash
python tests/run_tests.py
```

116 tests, standard library only. The ones needing the `age` binaries skip
themselves when those are absent — so a green run on a fresh clone means
"everything checkable passed", not "everything passed".

## Requirements

Python 3.9 or newer, a working Tk for the file chooser (optional — the tool
falls back to typing a path), and the three binaries above.

The 3.9 floor is enforced by the linter's target version and a scan for newer
syntax; the suite is actually executed on 3.12 and 3.14.

## License

[MIT](LICENSE). `internals/binaries/LICENSE.txt` is the vendored
`age-plugin-sss` license, not this project's.
