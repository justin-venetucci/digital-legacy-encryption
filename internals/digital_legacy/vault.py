"""The encrypted folder: what is in it, and what we know about each file.

The old scripts held the contents of ``internals/encrypted/`` together by
convention alone -- exactly one ``*.age`` and exactly one ``*.yaml``, with more
than one of either treated as fatal.  Two things went wrong with that:

* Everything about the plaintext had to be *re-derived from the ciphertext's
  filename*.  ``Path(stem).suffix`` on ``"taxes 2024.1 - Encrypted 2025-05-26"``
  yields ``".1 - Encrypted 2025-05-26"``, so a beneficiary got a decrypted file
  with a nonsense extension that no application would open.  There was also no
  way to notice that a file had been truncated in transit.

* Running ``encrypt.py`` twice left two ``.age`` files in the folder, which
  permanently broke ``decrypt.py`` -- the tool bricked its own vault, and the
  owner would not find out until a beneficiary needed it.

``vault.json`` records what we actually knew at encryption time: the original
name and extension, sizes, and SHA-256 of both plaintext and ciphertext.  It is
plain JSON because ``json`` is in the standard library and the format will still
be readable in fifty years.  It is also strictly optional -- a vault written by
the old scripts still opens, using a *corrected* filename parser as the fallback.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import MANIFEST_VERSION, __version__
from .errors import VaultError
from .policy import Policy

MANIFEST_NAME = "vault.json"
ENCRYPTED_SUFFIX = ".age"

_ENCRYPTED_STAMP_RE = re.compile(
    r"^(?P<base>.+?) - Encrypted \d{4}-\d{2}-\d{2}(?: \(\d+\))?$"
)


def sha256_file(path: Path, *, chunk: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(chunk), b""):
            digest.update(block)
    return digest.hexdigest()


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


@dataclass
class VaultEntry:
    """One encrypted document and everything known about its plaintext.

    The plaintext name is held as *stem plus suffix, separately*, never as one
    string to be re-split later.  Re-splitting is precisely what broke the old
    decryptor: it had the right name in hand and then took it apart again with
    ``Path.suffix``, which cannot tell ``"taxes 2024.1"`` (no extension) from
    ``"report.pdf"`` (extension).  Recording the answer once removes the guess.
    """

    ciphertext_name: str
    original_stem: str = ""
    original_suffix: str = ""
    plaintext_sha256: str = ""
    plaintext_size: int = 0
    ciphertext_sha256: str = ""
    ciphertext_size: int = 0
    encrypted_at: str = ""
    verified_at: str = ""
    policy_threshold: int = 0
    policy_total: int = 0

    @property
    def original_name(self) -> str:
        return f"{self.original_stem}{self.original_suffix}"

    @property
    def display_name(self) -> str:
        return self.original_name or self.ciphertext_name

    def output_name(self, *, when: str | None = None) -> str:
        """Filename for the decrypted copy.

        Prefixed ``[SENSITIVE]`` deliberately: the beneficiary has just put a
        plaintext copy of the most private document its owner had onto their
        Desktop, and the filename is the only reminder they will get.
        """
        stamp = when or datetime.now().strftime("%Y-%m-%d")
        base = self.original_stem or Path(self.ciphertext_name).stem
        # Never stack the marker: a vault written by the old encryptor can hold
        # a ciphertext whose own name already begins with it.
        base = re.sub(r"^(\[SENSITIVE\]\s*)+", "", base).strip() or "document"
        suffix = self.original_suffix or ".bin"
        return f"[SENSITIVE] {base} - Decrypted {stamp}{suffix}"

    @classmethod
    def from_ciphertext(cls, path: Path) -> VaultEntry:
        """Best-effort metadata for a vault with no manifest.

        Used for vaults written by the pre-2.0 scripts.  The parsing is the part
        the old code got wrong: strip the exact ``" - Encrypted <date>"`` stamp
        the encryptor wrote, rather than calling ``Path.stem`` twice and hoping
        the last dot in the name marked an extension.
        """
        path = Path(path)
        name = path.name
        stem = (
            name[: -len(ENCRYPTED_SUFFIX)]
            if name.endswith(ENCRYPTED_SUFFIX)
            else path.stem
        )

        # Layout written by every version of this tool:
        #     "<original stem> - Encrypted <date>[ (n)]<original suffix>"
        # Peel the real extension off first, then the stamp.
        suffix = Path(stem).suffix
        base = stem[: -len(suffix)] if suffix else stem

        # A "suffix" containing a space, or longer than any real extension, came
        # from a dot inside the name (e.g. "taxes 2024.1"). Better to report no
        # extension than a wrong one.
        if " " in suffix or len(suffix) > 12:
            base, suffix = stem, ""

        match = _ENCRYPTED_STAMP_RE.match(base)
        if match:
            base = match.group("base")
        elif not suffix:
            # Nothing peeled: the stamp may be the whole remainder.
            match = _ENCRYPTED_STAMP_RE.match(stem)
            if match:
                base = match.group("base")

        # The old encryptor prefixed "[SENSITIVE] " onto *ciphertext* it renamed
        # to avoid a collision -- a marker that only belongs on decrypted output.
        # Drop it so the recorded stem is the document's real name.
        base = re.sub(r"^(\[SENSITIVE\]\s*)+", "", base).strip() or stem

        try:
            size = path.stat().st_size
        except OSError:  # pragma: no cover - defensive
            size = 0

        return cls(
            ciphertext_name=name,
            original_stem=base,
            original_suffix=suffix,
            ciphertext_size=size,
        )


@dataclass
class Manifest:
    """``vault.json`` -- the record of what this vault contains."""

    manifest_version: int = MANIFEST_VERSION
    tool_version: str = __version__
    created_at: str = field(default_factory=now_iso)
    updated_at: str = field(default_factory=now_iso)
    owner: str = ""
    threshold: int = 0
    keyholders: list[dict[str, str]] = field(default_factory=list)
    binaries: dict[str, str] = field(default_factory=dict)
    # How the owner hands keys out (filename prefix, shared-folder wording,
    # notes). Empty means the defaults; see handoff.HandoffContext.profile.
    handoff: dict[str, object] = field(default_factory=dict)
    entries: list[VaultEntry] = field(default_factory=list)

    def to_json(self) -> str:
        payload = asdict(self)
        payload["entries"] = [
            e if isinstance(e, dict) else asdict(e) for e in self.entries
        ]
        return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"

    @classmethod
    def from_json(cls, text: str) -> Manifest:
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise VaultError(
                f"{MANIFEST_NAME} is damaged and could not be read.",
                hint="This file only records details about the encrypted "
                "document; decryption can still proceed without it. You may "
                "delete it.",
            ) from exc
        if not isinstance(payload, dict):
            raise VaultError(f"{MANIFEST_NAME} is not in the expected format.")

        version = payload.get("manifest_version", 1)
        if version > MANIFEST_VERSION:
            raise VaultError(
                f"{MANIFEST_NAME} was written by a newer version of this tool "
                f"(format {version}; this build understands {MANIFEST_VERSION}).",
                hint="Use the newer version of the tool, or delete "
                f"{MANIFEST_NAME} to fall back to reading the folder directly.",
            )

        known = set(cls.__dataclass_fields__)
        entry_fields = set(VaultEntry.__dataclass_fields__)
        entries = [
            VaultEntry(**{k: v for k, v in raw.items() if k in entry_fields})
            for raw in payload.get("entries", [])
            if isinstance(raw, dict)
        ]
        data = {k: v for k, v in payload.items() if k in known and k != "entries"}
        return cls(**data, entries=entries)


class Vault:
    """The ``internals/encrypted`` folder, and operations over its contents."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    # -- layout -----------------------------------------------------------

    @property
    def manifest_path(self) -> Path:
        return self.path / MANIFEST_NAME

    def ensure(self) -> None:
        self.path.mkdir(parents=True, exist_ok=True)

    def ciphertext_paths(self) -> list[Path]:
        if not self.path.is_dir():
            return []
        return sorted(self.path.glob(f"*{ENCRYPTED_SUFFIX}"))

    def policy_path(self) -> Path:
        """The single ``*.yaml`` policy file, or a clear error explaining why not.

        Both scripts globbed for ``*.yaml`` and treated more than one as fatal.
        That part was right -- picking a "default" name would risk encrypting to
        the wrong set of people -- so the behaviour stays, with a message that
        says which files are in the way.
        """
        if not self.path.is_dir():
            raise VaultError(
                f"The folder holding the encrypted document is missing: {self.path}"
            )
        candidates = sorted(
            p for p in self.path.glob("*.yaml") if p.name != MANIFEST_NAME
        )
        if not candidates:
            raise VaultError(
                "There is no key configuration file with the encrypted document.",
                hint=f"A file named recipients.yaml should sit in {self.path}. "
                "Without it we cannot tell how many keys are needed.",
            )
        if len(candidates) > 1:
            names = ", ".join(p.name for p in candidates)
            raise VaultError(
                f"There is more than one key configuration file: {names}",
                hint="Leave exactly one. Guessing which applies could send the "
                "document to the wrong people.",
            )
        return candidates[0]

    def load_policy(self) -> Policy:
        return Policy.load(self.policy_path())

    # -- manifest ---------------------------------------------------------

    def load_manifest(self) -> Manifest | None:
        if not self.manifest_path.exists():
            return None
        return Manifest.from_json(self.manifest_path.read_text(encoding="utf-8-sig"))

    def save_manifest(self, manifest: Manifest) -> Path:
        self.ensure()
        manifest.updated_at = now_iso()
        manifest.tool_version = __version__
        self.manifest_path.write_bytes(manifest.to_json().encode("utf-8"))
        return self.manifest_path

    # -- entries ----------------------------------------------------------

    def entries(self) -> list[VaultEntry]:
        """Every encrypted document in the vault, manifest-backed where possible.

        A file present on disk but absent from the manifest is still returned --
        losing ``vault.json`` must never hide a document from the person who
        needs it.
        """
        present = self.ciphertext_paths()
        if not present:
            raise VaultError(
                "There is no encrypted document to open.",
                hint=f"A file ending in '.age' should be in {self.path}.",
            )

        recorded: dict[str, VaultEntry] = {}
        try:
            manifest = self.load_manifest()
        except VaultError:
            manifest = None  # A damaged manifest must not block decryption.
        if manifest:
            recorded = {e.ciphertext_name: e for e in manifest.entries}

        return [
            recorded.get(path.name) or VaultEntry.from_ciphertext(path)
            for path in present
        ]

    def entry_path(self, entry: VaultEntry) -> Path:
        return self.path / entry.ciphertext_name

    def sole_entry(self) -> VaultEntry:
        """The only entry, when there is exactly one.

        Raises when ambiguous rather than picking one -- but unlike the old
        code, the caller can catch this and *ask*, which is what the decrypt
        wizard does.  Two documents in the folder is an inconvenience, not the
        dead end it used to be.
        """
        found = self.entries()
        if len(found) > 1:
            names = ", ".join(e.ciphertext_name for e in found)
            raise VaultError(
                f"There is more than one encrypted document here: {names}",
                hint="Say which one to open, or leave only one in the folder.",
            )
        return found[0]

    # -- integrity --------------------------------------------------------

    def check_integrity(self, entry: VaultEntry) -> list[str]:
        """Compare an entry against the file on disk; return human-readable faults."""
        problems: list[str] = []
        path = self.entry_path(entry)
        if not path.exists():
            return [f"{entry.ciphertext_name} is recorded but missing from the folder."]

        size = path.stat().st_size
        if entry.ciphertext_size and size != entry.ciphertext_size:
            problems.append(
                f"{entry.ciphertext_name} is {size:,} bytes but was "
                f"{entry.ciphertext_size:,} bytes when it was created."
            )
        if entry.ciphertext_sha256:
            actual = sha256_file(path)
            if actual != entry.ciphertext_sha256:
                problems.append(
                    f"{entry.ciphertext_name} has changed since it was created "
                    "(its checksum no longer matches). It may be damaged."
                )
        return problems


def unique_path(directory: Path, stem: str, suffix: str) -> Path:
    """A free path, never overwriting and never losing the extension.

    The old encryptor's collision branch dropped the original extension and
    grew a ``[SENSITIVE]`` prefix out of nowhere, producing names the decryptor
    then mis-parsed.  Counting goes before the suffix, where it belongs.
    """
    directory = Path(directory)
    candidate = directory / f"{stem}{suffix}"
    counter = 1
    while candidate.exists():
        candidate = directory / f"{stem} ({counter}){suffix}"
        counter += 1
    return candidate
