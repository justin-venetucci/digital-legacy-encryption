"""Exception hierarchy.

Every message in this module is read by a grieving, non-technical beneficiary
at the worst possible moment.  The rules:

* ``message`` says what went wrong in one plain sentence, no jargon, no
  tracebacks, no variable names.
* ``hint`` says what to *do* about it.  It is optional but nearly always worth
  writing -- an error the reader cannot act on is just an obstacle.

Nothing in this package calls ``sys.exit`` or lets a traceback escape to the
user; helpers raise one of these and the CLI layer renders it.
"""

from __future__ import annotations


class DigitalLegacyError(Exception):
    """Base class for every error this tool reports to a human."""

    def __init__(self, message: str, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.message


class ToolchainError(DigitalLegacyError):
    """A required binary is missing, unrunnable, or misbehaving."""


class PolicyError(DigitalLegacyError):
    """`recipients.yaml` is missing, malformed, or self-contradictory."""


class VaultError(DigitalLegacyError):
    """The encrypted folder is missing files, or holds files we cannot pair up."""


class KeyFileError(DigitalLegacyError):
    """A key file could not be read, parsed, or matched to this vault."""


class EncryptionError(DigitalLegacyError):
    """Encryption did not complete."""


class DecryptionError(DigitalLegacyError):
    """Decryption did not complete."""


class VerificationError(DigitalLegacyError):
    """An encrypted file failed its round-trip proof.

    This is the loudest failure in the tool.  It means we produced a file we
    cannot prove is recoverable, which is the one outcome a legacy tool must
    never report as success.
    """


class OperationCancelled(DigitalLegacyError):
    """The user backed out on purpose.  Not a failure; do not shout about it."""

    def __init__(self, message: str = "Operation cancelled.") -> None:
        super().__init__(message)


__all__ = [
    "DigitalLegacyError",
    "ToolchainError",
    "PolicyError",
    "VaultError",
    "KeyFileError",
    "EncryptionError",
    "DecryptionError",
    "VerificationError",
    "OperationCancelled",
]
