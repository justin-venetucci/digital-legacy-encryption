"""Wrapper around ``age-plugin-sss``: policies in, recipients and identities out.

Two directions:

* **Encrypting.**  A :class:`~digital_legacy.policy.Policy` becomes one composite
  recipient string, which ``age -e -r`` accepts like any other recipient.  The
  threshold is sealed into that string, and therefore into the ciphertext --
  editing ``recipients.yaml`` afterwards changes nothing about a file already
  written.

* **Decrypting.**  Enough private keys become one composite identity file, which
  ``age -d -i`` accepts.  This file is the reconstructed secret in the clear, so
  it lives in a 0700 temp directory for as short a time as possible and is
  overwritten before deletion.
"""

from __future__ import annotations

import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Sequence

from .agekeys import harden, shred
from .errors import DecryptionError, EncryptionError, ToolchainError
from .policy import Policy
from .toolchain import Toolchain


@contextmanager
def secure_tempdir(prefix: str = "digital_legacy_") -> Iterator[Path]:
    """A private directory that is scrubbed on the way out.

    ``mkdtemp`` already creates the directory 0700, which keeps other users out
    while we work.  What it does not do is remove the contents afterwards in a
    way that makes casual recovery hard, so every file inside is overwritten
    before the directory goes.
    """
    path = Path(tempfile.mkdtemp(prefix=prefix))
    try:
        yield path
    finally:
        try:
            for child in sorted(path.rglob("*"), reverse=True):
                if child.is_file():
                    shred(child)
                elif child.is_dir():
                    child.rmdir()
            path.rmdir()
        except OSError:  # pragma: no cover - best effort
            pass


def generate_recipient(toolchain: Toolchain, policy: Policy) -> str:
    """Turn a policy into the composite recipient string ``age`` encrypts to."""
    policy.validate()
    with secure_tempdir("digital_legacy_policy_") as workdir:
        policy_path = workdir / "policy.yaml"
        policy_path.write_text(policy.render(), encoding="utf-8", newline="\n")
        try:
            result = toolchain.run(
                toolchain.age_plugin_sss, "--generate-recipient", str(policy_path)
            )
        except ToolchainError as exc:
            raise EncryptionError(
                "The key configuration could not be turned into an encryption "
                "recipient.",
                hint=exc.hint
                or "Check that recipients.yaml lists valid age public keys.",
            ) from exc

    recipient = result.stdout.strip()
    if not recipient.startswith("age1"):
        raise EncryptionError(
            "The key configuration produced an unusable recipient.",
            hint="Check that recipients.yaml lists valid age public keys.",
        )
    return recipient


def write_identity(
    toolchain: Toolchain, secret_keys: Sequence[str], destination: Path
) -> Path:
    """Combine private keys into the identity file ``age -d -i`` reads.

    Order does not matter and neither does which subset was supplied, as long as
    there are at least ``threshold`` of them -- that is the whole point of the
    scheme.
    """
    if not secret_keys:
        raise DecryptionError("No keys were provided.")

    destination = Path(destination)
    identities_path = destination.parent / "identities.yaml"
    body = "identities:\n" + "".join(f"  - {key}\n" for key in secret_keys)
    identities_path.write_text(body, encoding="utf-8", newline="\n")
    harden(identities_path)

    try:
        result = toolchain.run(
            toolchain.age_plugin_sss, "--generate-identity", str(identities_path)
        )
    except ToolchainError as exc:
        raise DecryptionError(
            "The keys you provided could not be combined into a decryption key.",
            hint=exc.hint
            or "This usually means one of the key files belongs to a different "
            "encrypted document.",
        ) from exc
    finally:
        shred(identities_path)

    if not result.stdout.strip():
        raise DecryptionError(
            "The keys you provided could not be combined into a decryption key.",
            hint="Check that every key file belongs to this document.",
        )

    destination.write_text(result.stdout, encoding="utf-8", newline="\n")
    harden(destination)
    return destination


def inspect(toolchain: Toolchain, encrypted_file: Path) -> str:
    """Ask the plugin to describe the policy sealed into a ciphertext.

    Useful in ``doctor``: it reads the requirement from the *file* rather than
    from ``recipients.yaml``, which is the only way to catch a policy file that
    has drifted away from the document it is supposed to describe.
    """
    result = toolchain.run(
        toolchain.age_plugin_sss, "--inspect", str(encrypted_file), check=False
    )
    return (result.stdout or result.stderr).strip()
