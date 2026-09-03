"""age key material: generation, parsing, and writing key-share files.

A "key share" file is what a keyholder is given.  Its machine-readable content
is exactly what ``age-keygen`` emits -- a ``# public key:`` comment and one
``AGE-SECRET-KEY-...`` line -- so ``age`` itself can still read it directly if
this tool is ever unavailable.  Everything else in the file is comments telling
the holder what they are looking at, which age ignores.
"""

from __future__ import annotations

import contextlib
import os
import re
import secrets
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .errors import KeyFileError, ToolchainError
from .toolchain import Toolchain

# Bech32 alphabet excludes 1, b, i and o.  age emits secret keys uppercased and
# public keys lowercased; both are anchored so a key split across a line cannot
# half-match.
SECRET_KEY_RE = re.compile(r"^(AGE-SECRET-KEY-1[02-9AC-HJ-NP-Z]+)\s*$", re.MULTILINE)
PUBLIC_KEY_RE = re.compile(r"^(age1[02-9ac-hj-np-z]+)$")
PUBLIC_KEY_ANYWHERE_RE = re.compile(r"\b(age1[02-9ac-hj-np-z]{50,})\b")

KEY_FILE_PREFIX = "Key for Digital Legacy - "
KEY_FILE_SUFFIX = ".yaml"

# Windows refuses to create a file with any of these stems, extension or not.
# A keyholder called "Con" is unlikely but the failure would happen *after* the
# key had been generated, destroying the only copy of a secret.
_RESERVED_WINDOWS_NAMES = frozenset(
    ["CON", "PRN", "AUX", "NUL"]
    + [f"COM{i}" for i in range(1, 10)]
    + [f"LPT{i}" for i in range(1, 10)]
)


def key_file_name(label: str) -> str:
    """Filename for a keyholder's share, with path separators neutralised."""
    safe = sanitise_label(label)
    return f"{KEY_FILE_PREFIX}{safe}{KEY_FILE_SUFFIX}"


def sanitise_label(label: str) -> str:
    """Make a user-supplied keyholder name safe to put in a filename.

    The old script interpolated raw input straight into a path, so a name
    containing a slash silently wrote the key somewhere else -- or failed after
    the key had already been generated, losing it.
    """
    cleaned = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "-", (label or "").strip())
    # Collapse runs of dots so no ".." survives to be read as a parent
    # directory, while leaving a single dot alone ("Dr. Smith" is a name).
    cleaned = re.sub(r"\.{2,}", ".", cleaned)
    cleaned = re.sub(r"-{2,}", "-", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned)
    cleaned = cleaned.strip("-. ")
    if not cleaned or cleaned.upper() in _RESERVED_WINDOWS_NAMES:
        cleaned = "Keyholder"
    return cleaned[:60].strip("-. ") or "Keyholder"


@dataclass(frozen=True)
class KeyPair:
    """One Shamir share: an age identity plus the label of who holds it."""

    public_key: str
    secret_key: str
    label: str = ""
    created: str = ""

    def fingerprint(self) -> str:
        """Short, safe-to-print identifier for a share.

        Public keys are 62 characters of bech32 and look identical at a glance.
        Everything the tool shows a human uses this instead, so that "which key
        is this?" is answerable without comparing full strings by eye.
        """
        return public_key_fingerprint(self.public_key)


def public_key_fingerprint(public_key: str) -> str:
    """Last eight characters of a public key, grouped for reading aloud."""
    tail = public_key[-8:].upper()
    return f"{tail[:4]}-{tail[4:]}"


@dataclass(frozen=True)
class ParsedKeyFile:
    """What we could recover from a file a beneficiary handed us."""

    secret_key: str
    declared_public_key: str | None
    label: str
    path: Path


def generate(toolchain: Toolchain, label: str = "") -> KeyPair:
    """Create a fresh age identity via ``age-keygen``."""
    result = toolchain.run(toolchain.age_keygen)
    return parse_keygen_output(result.stdout, label=label)


def parse_keygen_output(text: str, *, label: str = "") -> KeyPair:
    secret = SECRET_KEY_RE.search(text)
    public = re.search(r"#\s*public key:\s*(age1\S+)", text)
    created = re.search(r"#\s*created:\s*(\S+)", text)
    if not secret:
        raise KeyFileError(
            "The key generator did not return a usable private key.",
            hint="Check that age-keygen in the binaries folder is the real "
            "program and is not blocked by antivirus software.",
        )
    if not public:
        raise KeyFileError("The key generator did not return a public key.")
    return KeyPair(
        public_key=public.group(1),
        secret_key=secret.group(1),
        label=label,
        created=created.group(1) if created else _now(),
    )


def derive_public_key(toolchain: Toolchain, secret_key: str) -> str:
    """Ask ``age-keygen -y`` for the public key matching a private key.

    The secret goes in over stdin, never on the command line: process arguments
    are readable by any other user on the machine.
    """
    try:
        result = toolchain.run(
            toolchain.age_keygen, "-y", stdin=secret_key, check=False
        )
    except ToolchainError as exc:  # timeout, missing binary, ...
        raise KeyFileError(exc.message, hint=exc.hint) from exc

    combined = f"{result.stdout}\n{result.stderr}".lower()
    if not result.ok or "malformed" in combined or "failed to parse" in combined:
        raise KeyFileError(
            "This file contains something that looks like a key, but it is not "
            "a valid one. It may have been edited or damaged in transit.",
            hint="Ask the person who gave you this file for a fresh copy, and "
            "avoid opening it in a word processor -- use a plain text editor.",
        )

    public_key = result.stdout.strip()
    if not PUBLIC_KEY_RE.match(public_key):
        raise KeyFileError(
            "Could not work out the public identity for this key file."
        )
    return public_key


def read_key_file(path: Path) -> ParsedKeyFile:
    """Extract the private key from a file the user selected.

    Deliberately tolerant about *where* in the file the key sits and what else
    surrounds it -- keyholders print these, retype them, and paste them into
    email -- but strict about the key's own shape.
    """
    path = Path(path)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise KeyFileError(
            f"Could not open {path.name}.",
            hint="Check that the file still exists and that you have permission "
            "to read it.",
        ) from exc

    if len(raw) > 1_000_000:
        raise KeyFileError(
            f"{path.name} is far too large to be a key file.",
            hint="A key file is a few lines of text. You may have selected the "
            "encrypted document by mistake.",
        )

    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise KeyFileError(
            f"{path.name} is not a text file, so it cannot be a key file.",
            hint="Key files are named "
            f"'{KEY_FILE_PREFIX}<name>{KEY_FILE_SUFFIX}'.",
        ) from None

    # Word processors and mail clients love to substitute these.
    normalised = text.replace("–", "-").replace("—", "-").replace(" ", " ")

    match = SECRET_KEY_RE.search(normalised)
    if not match:
        loose = re.search(r"AGE-SECRET-KEY-\S*", normalised, re.IGNORECASE)
        if loose:
            raise KeyFileError(
                f"{path.name} contains a private key, but it is damaged.",
                hint="The key must be on a line of its own and unchanged. If it "
                "was sent by email or retyped, ask for a fresh copy.",
            )
        raise KeyFileError(
            f"{path.name} does not contain a private key.",
            hint="Look for a file named "
            f"'{KEY_FILE_PREFIX}<name>{KEY_FILE_SUFFIX}'.",
        )

    declared = re.search(r"#\s*public key:\s*(age1\S+)", normalised)
    label = re.search(r"#\s*keyholder:\s*(.+)", normalised)
    if label:
        label_text = label.group(1).strip()
    elif path.name.startswith(KEY_FILE_PREFIX):
        label_text = path.stem[len(KEY_FILE_PREFIX) :]
    else:
        label_text = path.stem

    return ParsedKeyFile(
        secret_key=match.group(1),
        declared_public_key=declared.group(1) if declared else None,
        label=label_text,
        path=path,
    )


def render_key_file(
    keypair: KeyPair,
    *,
    threshold: int,
    total_shares: int,
    owner: str = "",
    document: str = "",
) -> str:
    """The text of a key-share file, written for whoever opens it.

    Machine-readable lines stay in the exact format ``age`` expects; every added
    line is a YAML/age comment, so this file remains usable with a bare ``age``
    install if this tool is ever lost.
    """
    holder = keypair.label or "Keyholder"
    subject = f" for {owner}" if owner else ""
    doc = f"\n#   Document:    {document}" if document else ""
    return f"""\
# =====================================================================
#  KEY SHARE{subject.upper()} -- KEEP THIS FILE SAFE AND PRIVATE
# =====================================================================
#
#  You are holding one of {total_shares} key shares. Any {threshold} of them,
#  brought together, will unlock the encrypted document. On its own
#  this file reveals nothing at all.
#
#   Keyholder:   {holder}
#   Share ID:    {keypair.fingerprint()}
#   Created:     {keypair.created}{doc}
#
#  WHAT TO DO WITH IT
#   * Store it somewhere you will still find it in ten years:
#     a password manager, a safe, or printed on paper.
#   * Do not email it, and do not store it with the encrypted
#     document -- shares and document should never travel together.
#   * You do not need to understand it. When the time comes, run the
#     "Decrypt My Information" program and select this file.
#
#  DO NOT EDIT THE LINES BELOW. Changing one character makes the key
#  unusable, and there is no way to repair it.
# ---------------------------------------------------------------------
# keyholder: {holder}
# created: {keypair.created}
# public key: {keypair.public_key}
{keypair.secret_key}
"""


def write_key_file(path: Path, content: str) -> Path:
    """Write a secret to disk as privately as the platform allows.

    Created with ``O_EXCL`` and mode 0600 so the key is never briefly readable
    by other users between creation and a later ``chmod``.  On Windows the mode
    bits only control the read-only flag -- NTFS inherits the parent folder's
    ACL -- which is why ``SECURITY.md`` tells owners to generate on a machine
    they control and move shares off it promptly.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, stat.S_IRUSR | stat.S_IWUSR)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
    except Exception:
        path.unlink(missing_ok=True)
        raise
    harden(path)
    return path


def harden(path: Path) -> bool:
    """Restrict a file to its owner.  Returns whether that could be enforced.

    POSIX mode bits do the job on macOS and Linux.  On Windows they do not:
    ``os.chmod`` there only toggles the read-only attribute, and the file still
    inherits whatever ACL its parent folder has -- which on a shared machine can
    mean every local user can read it.  So on Windows we also strip inheritance
    and grant the current account alone, via ``icacls``.
    """
    path = Path(path)
    with contextlib.suppress(OSError):  # best effort; see SECURITY.md
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)

    if os.name != "nt":
        return True

    account = os.environ.get("USERNAME")
    if not account:  # pragma: no cover - defensive
        return False
    try:  # pragma: no cover - platform specific
        import subprocess

        completed = subprocess.run(
            # icacls is resolved from PATH on purpose: it is a Windows system
            # tool whose location differs across installs, and hard-coding
            # System32 would break on a non-default SystemRoot.
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{account}:F"],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        return completed.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def shred(path: Path, passes: int = 1) -> None:
    """Overwrite a file's bytes before unlinking it.

    Not a guarantee: on SSDs, copy-on-write filesystems and journalled volumes
    the original blocks may survive.  It is still worth doing for the temporary
    files that hold reconstructed private keys, because it removes the easy
    recovery case at negligible cost.
    """
    path = Path(path)
    try:
        size = path.stat().st_size
        with open(path, "r+b") as handle:
            for _ in range(max(1, passes)):
                handle.seek(0)
                handle.write(secrets.token_bytes(size))
                handle.flush()
                os.fsync(handle.fileno())
    except OSError:
        pass
    finally:
        with contextlib.suppress(OSError):
            path.unlink(missing_ok=True)


def _now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
