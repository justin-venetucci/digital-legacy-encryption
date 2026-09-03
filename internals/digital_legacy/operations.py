"""Encrypt, decrypt, and -- the part that did not exist before -- prove it works.

The single most valuable thing a legacy tool can do is refuse to tell you it
succeeded until it has demonstrated that it did.  The old encryptor wrote a
ciphertext and printed "Encryption completed successfully!"; whether the file
could ever be opened again was left as an exercise for the bereaved, with the
README merely suggesting the owner "test the decryption process".

:func:`verify_entry` closes that gap.  After writing a file, we take a random
``threshold``-sized subset of the freshly generated shares -- a different subset
each run, so repeated use exercises different combinations -- reconstruct the
identity, decrypt to a temporary file, and compare its SHA-256 against the
plaintext we started from.  Only then is the operation reported as successful.
"""

from __future__ import annotations

import random
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable

from . import agekeys, sss
from .agekeys import KeyPair
from .errors import (
    DecryptionError,
    DigitalLegacyError,
    EncryptionError,
    VerificationError,
)
from .policy import Policy
from .toolchain import Toolchain
from .vault import Vault, VaultEntry, now_iso, sha256_file, unique_path

Progress = Callable[[str], None]
"""Optional callback so a wizard can narrate; ``None`` keeps operations silent."""


def _noop(_: str) -> None:
    return None


@dataclass
class EncryptResult:
    entry: VaultEntry
    path: Path
    policy: Policy
    verified: bool = False
    verification_detail: str = ""
    keypairs: list[KeyPair] = field(default_factory=list)


@dataclass
class VerifyResult:
    ok: bool
    detail: str
    shares_used: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# Encryption
# --------------------------------------------------------------------------


def encrypt_document(
    toolchain: Toolchain,
    source: Path,
    vault: Vault,
    policy: Policy,
    *,
    when: str | None = None,
    progress: Progress | None = None,
) -> EncryptResult:
    """Encrypt ``source`` into ``vault`` under ``policy``.

    Writes to a temporary name in the destination folder and renames on success,
    so an interrupted run cannot leave a half-written ``.age`` file that later
    looks like a real document to the decryptor.
    """
    say = progress or _noop
    source = Path(source)
    policy.validate()

    if not source.is_file():
        raise EncryptionError(
            f"There is no file to encrypt at {source}.",
            hint="Check the path and try again.",
        )
    if source.suffix.lower() == ".age":
        raise EncryptionError(
            f"{source.name} is already encrypted.",
            hint="Choose the original document instead.",
        )
    if source.stat().st_size == 0:
        raise EncryptionError(
            f"{source.name} is empty, so there is nothing to encrypt.",
        )

    vault.ensure()
    say("Reading the document")
    plaintext_sha = sha256_file(source)
    plaintext_size = source.stat().st_size

    say("Building the encryption recipient")
    recipient = sss.generate_recipient(toolchain, policy)

    stamp = when or datetime.now().strftime("%Y-%m-%d")
    destination = unique_path(
        vault.path, f"{source.stem} - Encrypted {stamp}{source.suffix}", ".age"
    )
    scratch = destination.with_name(destination.name + ".partial")

    say(f"Encrypting {source.name}")
    try:
        toolchain.run(
            toolchain.age, "-e", "-r", recipient, "-o", str(scratch), str(source)
        )
    except Exception:
        scratch.unlink(missing_ok=True)
        raise

    if not scratch.exists() or scratch.stat().st_size == 0:
        scratch.unlink(missing_ok=True)
        raise EncryptionError(
            "Encryption produced an empty file.",
            hint="Check that there is free space on this drive and try again.",
        )

    scratch.replace(destination)

    entry = VaultEntry(
        ciphertext_name=destination.name,
        original_stem=source.stem,
        original_suffix=source.suffix,
        plaintext_sha256=plaintext_sha,
        plaintext_size=plaintext_size,
        ciphertext_sha256=sha256_file(destination),
        ciphertext_size=destination.stat().st_size,
        encrypted_at=now_iso(),
        policy_threshold=policy.threshold,
        policy_total=policy.total_shares,
    )
    return EncryptResult(entry=entry, path=destination, policy=policy)


# --------------------------------------------------------------------------
# Verification -- the round-trip proof
# --------------------------------------------------------------------------


def verify_entry(
    toolchain: Toolchain,
    vault: Vault,
    entry: VaultEntry,
    keypairs: Sequence[KeyPair],
    *,
    threshold: int,
    rng: random.Random | None = None,
    progress: Progress | None = None,
) -> VerifyResult:
    """Prove ``entry`` can be recovered, using a random subset of the shares.

    Returns a result rather than raising, so a caller can report a failure in
    full instead of losing the detail in an exception. The decrypted copy never
    touches a user-visible directory: it is written inside the scrubbed temp dir
    and compared by digest.
    """
    say = progress or _noop
    picker = rng or random.SystemRandom()

    if len(keypairs) < threshold:
        return VerifyResult(
            ok=False,
            detail=(
                f"Only {len(keypairs)} keys are available but {threshold} are "
                "needed, so recovery could not be tested."
            ),
        )

    chosen = picker.sample(list(keypairs), threshold)
    labels = [k.label or k.fingerprint() for k in chosen]
    say(f"Testing recovery with {threshold} of {len(keypairs)} keys")

    ciphertext = vault.entry_path(entry)
    try:
        with sss.secure_tempdir("digital_legacy_verify_") as workdir:
            identity = sss.write_identity(
                toolchain, [k.secret_key for k in chosen], workdir / "identity.txt"
            )
            recovered = workdir / "recovered.bin"
            result = toolchain.run(
                toolchain.age,
                "-d",
                "-i",
                str(identity),
                "-o",
                str(recovered),
                str(ciphertext),
                check=False,
            )
            if not result.ok:
                return VerifyResult(
                    ok=False,
                    detail=(
                        "age could not decrypt the file it had just written: "
                        + (result.stderr.strip() or "no reason given")
                    ),
                    shares_used=labels,
                )
            if not recovered.exists():
                return VerifyResult(
                    ok=False,
                    detail="Decryption produced no output.",
                    shares_used=labels,
                )
            digest = sha256_file(recovered)
    except Exception as exc:  # surfaced as a failed proof, not a crash
        return VerifyResult(ok=False, detail=str(exc), shares_used=labels)

    if entry.plaintext_sha256 and digest != entry.plaintext_sha256:
        return VerifyResult(
            ok=False,
            detail=(
                "The recovered file does not match the original document "
                "(checksums differ)."
            ),
            shares_used=labels,
        )

    return VerifyResult(
        ok=True,
        detail=f"Recovered the original document using: {', '.join(labels)}.",
        shares_used=labels,
    )


def encrypt_and_verify(
    toolchain: Toolchain,
    source: Path,
    vault: Vault,
    policy: Policy,
    keypairs: Sequence[KeyPair],
    *,
    when: str | None = None,
    progress: Progress | None = None,
    require_verification: bool = True,
) -> EncryptResult:
    """Encrypt, then refuse to call it a success until recovery is demonstrated.

    ``require_verification=False`` exists for the case where the owner encrypted
    to an existing ``recipients.yaml`` and therefore holds no private keys on
    this machine -- there is nothing to test with, and that is expected.
    """
    result = encrypt_document(
        toolchain, source, vault, policy, when=when, progress=progress
    )

    if not keypairs:
        result.verification_detail = (
            "Recovery was not tested: this run had no private keys to test with, "
            "because it encrypted to a key list that already existed."
        )
        if require_verification:
            raise VerificationError(
                "Cannot prove this file can be opened again.",
                hint=result.verification_detail,
            )
        return result

    check = verify_entry(
        toolchain,
        vault,
        result.entry,
        keypairs,
        threshold=policy.threshold,
        progress=progress,
    )
    result.verified = check.ok
    result.verification_detail = check.detail
    result.keypairs = list(keypairs)
    if check.ok:
        result.entry.verified_at = now_iso()
    elif require_verification:
        raise VerificationError(
            "The document was encrypted, but it could NOT be decrypted again "
            "in a test. Do not rely on this file.",
            hint=check.detail
            + "\nThe encrypted file has been left in place so you can "
            "investigate, but treat it as unusable until this passes.",
        )
    return result


# --------------------------------------------------------------------------
# Decryption
# --------------------------------------------------------------------------


def decrypt_entry(
    toolchain: Toolchain,
    vault: Vault,
    entry: VaultEntry,
    secret_keys: Sequence[str],
    output_dir: Path,
    *,
    when: str | None = None,
    progress: Progress | None = None,
) -> Path:
    """Decrypt one vault entry into ``output_dir`` and return the file written."""
    say = progress or _noop
    output_dir = Path(output_dir)
    ciphertext = vault.entry_path(entry)

    if not ciphertext.exists():
        raise DecryptionError(
            f"The encrypted document is missing: {entry.ciphertext_name}"
        )

    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise DecryptionError(
            f"Could not write to {output_dir}.",
            hint="Choose a different folder, such as your Desktop.",
        ) from exc

    name = entry.output_name(when=when)
    destination = unique_path(output_dir, Path(name).stem, Path(name).suffix)

    say("Combining your keys")
    with sss.secure_tempdir("digital_legacy_decrypt_") as workdir:
        identity = sss.write_identity(
            toolchain, list(secret_keys), workdir / "identity.txt"
        )

        say("Decrypting your information")
        result = toolchain.run(
            toolchain.age,
            "-d",
            "-i",
            str(identity),
            "-o",
            str(destination),
            str(ciphertext),
            check=False,
        )

    if not result.ok:
        # age writes the output file before it discovers it cannot fill it.
        if destination.exists():
            agekeys.shred(destination)

        stderr = result.stderr.strip()
        if "no identity matched any of the recipients" in stderr:
            raise DecryptionError(
                "These keys cannot open this document.",
                hint="Every key was valid on its own, but together they do not "
                "unlock this file. The most likely explanation is that they "
                "belong to a different encrypted document.",
            )
        raise DecryptionError(
            "The document could not be decrypted.",
            hint=stderr or "age did not say why.",
        )

    if not destination.exists() or destination.stat().st_size == 0:
        destination.unlink(missing_ok=True)
        raise DecryptionError(
            "Decryption finished but produced no readable file.",
            hint="Check there is free space on this drive, then try again.",
        )

    if entry.plaintext_sha256:
        say("Checking the recovered file")
        if sha256_file(destination) != entry.plaintext_sha256:
            raise DecryptionError(
                "The recovered file does not match what was originally "
                "encrypted, so it may be damaged.",
                hint=f"The file was still written to {destination}, but check "
                "its contents carefully before relying on it.",
            )

    return destination


def default_output_dir() -> Path:
    """Where a beneficiary should find their file.

    Desktop when there is one; the home directory otherwise, since a headless
    or Linux account often has no Desktop and the old code would have written
    into a path that did not exist.
    """
    desktop = Path.home() / "Desktop"
    return desktop if desktop.is_dir() else Path.home()


# --------------------------------------------------------------------------
# Resealing -- changing who holds the keys
# --------------------------------------------------------------------------


@dataclass
class ResealResult:
    encrypt: EncryptResult
    replaced: str
    old_ciphertext_removed: bool
    warning: str = ""
    """Note: stale key files are *not* computed here.

    They can only be identified once the new share files have been written,
    because a reseal that reuses a keyholder's name overwrites their old file
    in place. Call :func:`stale_key_files` after writing them.
    """


def reseal_entry(
    toolchain: Toolchain,
    vault: Vault,
    entry: VaultEntry,
    secret_keys: Sequence[str],
    new_policy: Policy,
    new_keypairs: Sequence[KeyPair],
    *,
    remove_old: bool = True,
    when: str | None = None,
    progress: Progress | None = None,
) -> ResealResult:
    """Re-encrypt a document for a different set of keyholders.

    Over the decades a legacy document is meant to survive, the people holding
    its keys change: someone dies, moves away, falls out with the family, or
    simply loses their copy.  Shamir cannot add or remove a share after the
    fact -- the threshold is sealed into the ciphertext -- so the only way to
    change the arrangement is to decrypt and encrypt again. This does that with
    the plaintext never leaving a scrubbed temporary directory.

    **The old ciphertext must go.** If it is left in place, every removed
    keyholder can still open it with the key they already have, and the reseal
    accomplishes nothing but a false sense of security. ``remove_old=False``
    exists only for a caller who has arranged to destroy it another way; the
    result says plainly which happened.
    """
    say = progress or _noop
    new_policy.validate()
    if not secret_keys:
        raise DecryptionError("Resealing needs the current keys.")

    source_path = vault.entry_path(entry)
    if not source_path.exists():
        raise DecryptionError(
            f"The encrypted document is missing: {entry.ciphertext_name}"
        )

    with sss.secure_tempdir("digital_legacy_reseal_") as workdir:
        say("Opening the document with the current keys")
        recovered = decrypt_entry(
            toolchain,
            vault,
            entry,
            secret_keys,
            workdir,
            when=when,
            progress=progress,
        )

        # Restore the original filename so the new ciphertext, and therefore
        # every future beneficiary, keeps the document's real name rather than
        # the "[SENSITIVE] ... - Decrypted ..." working title.
        original = workdir / (entry.original_name or recovered.name)
        if original != recovered:
            recovered.rename(original)

        say("Encrypting again for the new keyholders")
        result = encrypt_and_verify(
            toolchain,
            original,
            vault,
            new_policy,
            new_keypairs,
            when=when,
            progress=progress,
            require_verification=bool(new_keypairs),
        )
        agekeys.shred(original)

    warning = ""
    removed = False
    if remove_old:
        say("Removing the previous encrypted copy")
        try:
            source_path.unlink()
            removed = True
        except OSError as exc:  # pragma: no cover - permissions, locks
            warning = (
                f"The previous encrypted file could not be deleted ({exc}). "
                "Delete it yourself: until it is gone, anyone holding an old "
                "key can still open it."
            )
    else:
        warning = (
            "The previous encrypted file was kept. Anyone holding an old key "
            "can still open it, so this reseal does not remove their access "
            "until that file is destroyed."
        )

    if removed:
        # The new file had to dodge the old one's name while both existed, so
        # it picked up a "(1)". Now that the old one is gone, take the plain
        # name back rather than leaving a counter that means nothing.
        preferred = vault.path / entry.ciphertext_name
        if not preferred.exists() and result.path != preferred:
            try:
                result.path.rename(preferred)
                result.path = preferred
                result.entry.ciphertext_name = preferred.name
            except OSError:  # pragma: no cover - defensive
                pass

    return ResealResult(
        encrypt=result,
        replaced=entry.ciphertext_name,
        old_ciphertext_removed=removed,
        warning=warning,
    )


def stale_key_files(keys_dir: Path, policy: Policy) -> list[Path]:
    """Key files that the current policy no longer recognises.

    Call this *after* writing the new shares: a reseal that keeps a
    keyholder's name overwrites their file in place, and running the check
    first would name files that are about to be replaced.

    Reported rather than deleted.  These files hold secrets, deleting one is
    irreversible, and the folder could contain a share for a different vault
    the owner keeps there -- shredding that on a guess would destroy something
    unrecoverable.  Naming them lets the owner clear them out deliberately.
    """
    keys_dir = Path(keys_dir)
    if not keys_dir.is_dir():
        return []
    stale: list[Path] = []
    for path in sorted(keys_dir.glob("*.yaml")):
        try:
            declared = agekeys.read_key_file(path).declared_public_key
        except DigitalLegacyError:
            # A file we cannot read is not evidence of a stale share; `doctor`
            # reports unreadable key files, and guessing here could name a
            # perfectly good key as dead.
            continue
        if declared and declared not in policy.shares:
            stale.append(path)
    return stale
