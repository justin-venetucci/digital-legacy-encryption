"""A health check the owner can run once a year.

Encryption is a thing you do once and then depend on for decades.  Everything
around it rots: binaries get quarantined by antivirus, a cloud sync mangles a
file, someone tidies the folder, a keyholder loses their share.  None of that
announces itself, and all of it is discovered at the worst possible time unless
something goes looking.

``doctor`` goes looking.  It is read-only, it never needs a private key, and it
prints a verdict a non-expert can act on.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from . import sss
from .agekeys import read_key_file, derive_public_key, public_key_fingerprint
from .console import Console
from .errors import DigitalLegacyError
from .layout import Layout
from .policy import Policy
from .toolchain import Toolchain
from .vault import Vault, sha256_file

OK = "ok"
WARN = "warn"
FAIL = "fail"


@dataclass
class Check:
    name: str
    status: str
    detail: str = ""

    @property
    def failed(self) -> bool:
        return self.status == FAIL


@dataclass
class Report:
    checks: list[Check] = field(default_factory=list)

    def add(self, name: str, status: str, detail: str = "") -> Check:
        check = Check(name, status, detail)
        self.checks.append(check)
        return check

    @property
    def failures(self) -> list[Check]:
        return [c for c in self.checks if c.status == FAIL]

    @property
    def warnings(self) -> list[Check]:
        return [c for c in self.checks if c.status == WARN]

    @property
    def exit_code(self) -> int:
        return 1 if self.failures else 0


def run_checks(layout: Layout, *, deep: bool = False) -> Report:
    """Inspect the installation and the vault.  Never modifies anything."""
    report = Report()

    # -- binaries ---------------------------------------------------------
    toolchain: Toolchain | None = None
    try:
        toolchain = Toolchain.discover(layout.binaries_dir)
        versions = toolchain.versions()
        report.add(
            "Helper programs",
            OK,
            ", ".join(f"{name} {value}" for name, value in versions.items()),
        )
        if any(v in ("unavailable", "unknown") for v in versions.values()):
            unknown = [n for n, v in versions.items() if v in ("unavailable", "unknown")]
            report.add(
                "Version reporting",
                WARN,
                f"{', '.join(unknown)} did not report a version. Not a fault by "
                "itself -- some builds simply do not.",
            )
    except DigitalLegacyError as exc:
        report.add("Helper programs", FAIL, exc.message)

    # -- vault layout -----------------------------------------------------
    vault = Vault(layout.encrypted_dir)
    policy: Policy | None = None
    try:
        policy = vault.load_policy()
        report.add(
            "Key list",
            OK,
            f"any {policy.threshold} of {policy.total_shares} keys can decrypt",
        )
        for note in policy.advisories():
            report.add("Key arrangement", WARN, note)
    except DigitalLegacyError as exc:
        report.add("Key list", FAIL, exc.message)

    try:
        entries = vault.entries()
        report.add(
            "Encrypted documents",
            OK,
            ", ".join(e.ciphertext_name for e in entries),
        )
    except DigitalLegacyError as exc:
        report.add("Encrypted documents", FAIL, exc.message)
        entries = []

    # -- manifest and integrity -------------------------------------------
    try:
        manifest = vault.load_manifest()
    except DigitalLegacyError as exc:
        manifest = None
        report.add("Vault record", WARN, exc.message)

    if manifest is None:
        report.add(
            "Vault record",
            WARN,
            "There is no vault.json, so the original filenames and checksums "
            "are not recorded. Decryption still works; re-encrypting with this "
            "version would add it.",
        )
    else:
        report.add(
            "Vault record",
            OK,
            f"written {manifest.updated_at} by version {manifest.tool_version}",
        )
        if toolchain and manifest.binaries:
            current = toolchain.fingerprints()
            changed = [
                name
                for name, digest in manifest.binaries.items()
                if name in current and current[name] != digest
            ]
            if changed:
                report.add(
                    "Helper programs unchanged",
                    WARN,
                    f"{', '.join(changed)} differs from the copy that encrypted "
                    "this document. Usually just an upgrade; worth knowing.",
                )

    for entry in entries:
        problems = vault.check_integrity(entry)
        if problems:
            report.add(f"Integrity of {entry.ciphertext_name}", FAIL, " ".join(problems))
        elif entry.ciphertext_sha256:
            report.add(f"Integrity of {entry.ciphertext_name}", OK, "checksum matches")
        else:
            report.add(
                f"Integrity of {entry.ciphertext_name}",
                WARN,
                "no checksum was recorded, so damage cannot be detected",
            )

    # -- what the ciphertext itself says ----------------------------------
    if toolchain and entries and policy:
        for entry in entries:
            try:
                described = sss.inspect(toolchain, vault.entry_path(entry))
            except DigitalLegacyError as exc:
                report.add(f"Policy sealed in {entry.ciphertext_name}", WARN, exc.message)
                continue
            sealed = _sealed_threshold(described)
            if sealed is None:
                report.add(
                    f"Policy sealed in {entry.ciphertext_name}",
                    WARN,
                    "could not read the requirement from the file itself",
                )
            elif sealed != policy.threshold:
                report.add(
                    f"Policy sealed in {entry.ciphertext_name}",
                    FAIL,
                    f"the file itself requires {sealed} keys, but the key list "
                    f"says {policy.threshold}. The key list has drifted from "
                    "the document; trust the file.",
                )
            else:
                report.add(
                    f"Policy sealed in {entry.ciphertext_name}",
                    OK,
                    f"the file itself requires {sealed} keys, matching the key list",
                )

    # -- loose secrets ----------------------------------------------------
    if layout.keys_out_dir.is_dir():
        leftover = sorted(layout.keys_out_dir.glob("*.yaml"))
        if leftover:
            report.add(
                "Private keys on this machine",
                WARN,
                f"{len(leftover)} key file(s) are still in "
                f"{layout.keys_out_dir.name}. Until they are handed out and "
                "deleted, every key sits on this one computer -- the exact "
                "situation the scheme exists to avoid.",
            )

    # -- deep: do the shares on this machine actually match the policy? ----
    if deep and toolchain and policy:
        _check_local_keys(report, toolchain, policy, layout)

    return report


def _sealed_threshold(described: str) -> int | None:
    """Pull ``t=N`` out of ``age-plugin-sss --inspect`` output."""
    import re

    match = re.search(r"\bt\s*=\s*(\d+)", described)
    return int(match.group(1)) if match else None


def _check_local_keys(
    report: Report, toolchain: Toolchain, policy: Policy, layout: Layout
) -> None:
    """Confirm every key file we can find belongs to the current key list."""
    searched = [layout.keys_out_dir, layout.sample_keys_dir]
    found: list[Path] = []
    for directory in searched:
        if directory.is_dir():
            found.extend(sorted(directory.glob("*.yaml")))

    if not found:
        report.add(
            "Key files on this machine",
            OK,
            "none found, which is the correct state once they are distributed",
        )
        return

    matched: set[str] = set()
    for path in found:
        try:
            parsed = read_key_file(path)
            public_key = derive_public_key(toolchain, parsed.secret_key)
        except DigitalLegacyError as exc:
            report.add(f"Key file {path.name}", FAIL, exc.message)
            continue
        if public_key in policy.shares:
            matched.add(public_key)
            report.add(
                f"Key file {path.name}",
                OK,
                f"share {public_key_fingerprint(public_key)} is in the key list",
            )
        else:
            report.add(
                f"Key file {path.name}",
                WARN,
                "valid, but not one of the keys for this document (it may "
                "belong to a different vault)",
            )

    if matched and len(matched) >= policy.threshold:
        report.add(
            "Keys available here",
            WARN,
            f"This machine holds {len(matched)} keys for this document and only "
            f"{policy.threshold} are needed, so anyone with access to it can "
            "decrypt without involving the other keyholders.",
        )


def check_key_file(
    layout: Layout, path: Path
) -> tuple[bool, str]:
    """Answer 'is this file a valid key for this document?' without decrypting.

    Meant for a keyholder who wants to confirm, years later and without a
    bereavement in progress, that the file in their safe is still the right one.
    """
    toolchain = Toolchain.discover(layout.binaries_dir)
    policy = Vault(layout.encrypted_dir).load_policy()
    parsed = read_key_file(Path(path))
    public_key = derive_public_key(toolchain, parsed.secret_key)
    fingerprint = public_key_fingerprint(public_key)

    if public_key in policy.shares:
        position = policy.shares.index(public_key) + 1
        return True, (
            f"This is key {position} of {policy.total_shares} for this document "
            f"(share {fingerprint}). Any {policy.threshold} of them can open it."
        )
    return False, (
        f"This is a valid key (share {fingerprint}), but it is not one of the "
        f"{policy.total_shares} that can open the document in this folder."
    )


def render(report: Report, console: Console) -> None:
    """Print a report a non-expert can act on."""
    marks = {
        OK: ("ok  ", "green"),
        WARN: ("warn", "yellow"),
        FAIL: ("FAIL", "red"),
    }
    console.banner("Health Check", step=False)
    for check in report.checks:
        mark, colour = marks[check.status]
        console.write(f"  [{mark}] {check.name}", colour)
        if check.detail:
            for line in _wrap(check.detail, console.width - 10):
                console.write(f"         {line}", "grey" if check.status == OK else colour)

    console.blank()
    if report.failures:
        console.error(
            f"{len(report.failures)} problem(s) need attention before this "
            "vault can be relied on."
        )
    elif report.warnings:
        console.warn(
            f"No faults. {len(report.warnings)} thing(s) worth a look."
        )
    else:
        console.ok("Everything checks out.")


def _wrap(text: str, width: int) -> Iterable[str]:
    import textwrap

    return textwrap.wrap(text, width=max(30, width)) or [text]
