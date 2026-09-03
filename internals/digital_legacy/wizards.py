"""The two guided flows: encrypting a document, and opening one again.

Both used to be 500-line scripts with their own copy of the same setup, the same
banners, the same spinner, and the same path handling.  That duplication was
described as intentional self-containment, but in practice it is where the bugs
came from: the two copies drifted, and each acquired defects the other did not
have.  The property actually worth keeping -- that a beneficiary needs nothing
but a Python interpreter and the vendored binaries -- is a property of having no
third-party dependencies, not of having two copies of the code.

The decryption wizard is the one that matters.  Its reader is not the owner:
they are grieving, non-technical, and using this once.  Every message it prints
assumes that.
"""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from . import agekeys, handoff, operations
from .agekeys import KeyPair
from .console import Console
from .errors import (
    DigitalLegacyError,
    KeyFileError,
    OperationCancelled,
    PolicyError,
    VaultError,
)
from .layout import Layout
from .picker import ANY_FILE_TYPES, KEY_FILE_TYPES, choose_file
from .policy import MAX_SHARES, Policy
from .toolchain import Toolchain
from .vault import Manifest, Vault, VaultEntry, now_iso

# --------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------


def open_in_default_app(path: Path) -> None:
    """Ask the desktop to open a file.  Never raises; the caller shows the path."""
    path = Path(path)
    if os.name == "nt":
        os.startfile(str(path))  # type: ignore[attr-defined]  # noqa: S606
    elif sys.platform == "darwin":
        subprocess.run(["open", str(path)], check=False)
    else:
        subprocess.run(["xdg-open", str(path)], check=False)


def show_ascii_art(console: Console, layout: Layout) -> None:
    art = layout.ascii_art
    if art and art.exists():
        try:
            text = art.read_text(encoding="utf-8")
        except OSError:
            return
        # The banner is 100 columns of ASCII art; on a narrow terminal it turns
        # into noise, so it is simply skipped rather than wrapped.
        if max((len(line) for line in text.splitlines()), default=0) <= console.width + 24:
            console.write(text, "green")


# --------------------------------------------------------------------------
# Decryption -- the beneficiary's path
# --------------------------------------------------------------------------


@dataclass
class CollectedKey:
    path: Path
    secret_key: str
    public_key: str
    label: str


class DecryptWizard:
    """Walks a beneficiary through gathering keys and opening the document."""

    def __init__(
        self,
        layout: Layout,
        console: Console,
        *,
        output_dir: Path | None = None,
    ) -> None:
        self.layout = layout
        self.console = console
        self.output_dir = output_dir or operations.default_output_dir()
        self.toolchain: Toolchain | None = None
        self.vault = Vault(layout.encrypted_dir)
        self.attempted: dict[str, bool] = {}
        self.collected: list[CollectedKey] = []

    # -- steps ------------------------------------------------------------

    def run(self) -> int:
        console = self.console
        try:
            console.clear()
            show_ascii_art(console, self.layout)

            self.toolchain = Toolchain.discover(self.layout.binaries_dir)
            policy = self.vault.load_policy()
            entry = self.select_entry()

            console.set_steps(policy.threshold + 3)
            self.welcome(policy, entry)
            self.collect_keys(policy)
            output = self.decrypt(entry)
            self.finish(output)
            return 0

        except OperationCancelled as exc:
            console.blank()
            console.warn(exc.message)
            return 1
        except DigitalLegacyError as exc:
            console.problem(exc)
            self.console.blank()
            self.console.note(
                "Nothing has been damaged. You can close this window and try "
                "again at any time."
            )
            return 1
        except KeyboardInterrupt:
            console.blank()
            console.warn("Stopped.")
            return 130
        finally:
            console.pause("Press Enter to close this window...")

    def select_entry(self) -> VaultEntry:
        """Pick the document to open, asking when the folder holds several.

        The old script treated a second ``.age`` file as fatal -- and running
        the encryptor twice created one, so the tool could brick its own vault
        with no way forward but manual file surgery.
        """
        entries = self.vault.entries()
        if len(entries) == 1:
            return entries[0]

        self.console.banner("Choose a Document", step=False)
        self.console.info("This folder holds more than one encrypted document.")
        options = [(str(i + 1), e.display_name) for i, e in enumerate(entries)]
        choice = self.console.ask_choice("Which one would you like to open?", options)
        return entries[int(choice) - 1]

    def welcome(self, policy: Policy, entry: VaultEntry) -> None:
        console = self.console
        console.banner("Getting Started")
        console.info(
            "This tool will help you open information that was encrypted for you."
        )
        console.blank()
        console.note(
            f"You will need {policy.threshold} of the {policy.total_shares} key "
            "files to unlock it."
        )
        console.blank()
        console.info(f"Document:  {entry.display_name}")
        console.info(f"Will open to:  {self.output_dir}")
        console.blank()
        console.info(
            "You will be asked to choose each key file in turn. If a file is "
            "the wrong one, this tool will say so and let you try another."
        )
        console.pause("Press Enter to begin...")

    def collect_keys(self, policy: Policy) -> None:
        """Gather distinct, valid shares until the threshold is met.

        Every rejection path offers another attempt: a beneficiary who picks the
        wrong file should not have to restart the program, which is what the old
        flow made them do for several kinds of mistake.
        """
        console = self.console
        while len(self.collected) < policy.threshold:
            number = len(self.collected) + 1
            console.banner(f"Key {number} of {policy.threshold}")

            try:
                path = choose_file(
                    console,
                    title=f"Select key file number {number}",
                    file_types=KEY_FILE_TYPES,
                    start_dir=self.layout.key_search_dir(),
                )
            except OperationCancelled:
                if console.ask_yes_no(
                    "No file was chosen. Would you like to try again?", default=True
                ):
                    continue
                raise

            try:
                collected = self.accept_key(path)
            except KeyFileError as exc:
                console.problem(exc)
                console.blank()
                if console.ask_yes_no("Try a different file?", default=True):
                    continue
                raise OperationCancelled(
                    "Stopped before enough keys were collected."
                ) from None

            self.collected.append(collected)
            remaining = policy.threshold - len(self.collected)
            console.blank()
            console.ok(f"Key accepted, from {collected.label}.")
            if remaining:
                word = "key" if remaining == 1 else "keys"
                console.info(f"You need {remaining} more {word}.")
            else:
                console.ok("That is everything needed.")

    def accept_key(self, path: Path) -> CollectedKey:
        """Validate one key file, or explain precisely why it cannot be used."""
        console = self.console
        assert self.toolchain is not None
        resolved = str(Path(path).resolve())

        if resolved in self.attempted:
            verdict = "already accepted" if self.attempted[resolved] else "already tried"
            raise KeyFileError(
                f"That file was {verdict}.",
                hint="Each key must come from a different file. Choose one of "
                "the other key files.",
            )

        with console.task(f"Reading {Path(path).name}"):
            parsed = agekeys.read_key_file(Path(path))

        try:
            with console.task("Checking the key"):
                public_key = agekeys.derive_public_key(
                    self.toolchain, parsed.secret_key
                )
                policy = self.vault.load_policy()
                if public_key not in policy.shares:
                    raise KeyFileError(
                        "This key does not belong to this document.",
                        hint="It is a valid key, but not one of the "
                        f"{policy.total_shares} that can open this file. Check "
                        "whether it belongs to a different encrypted document.",
                    )
                if any(c.public_key == public_key for c in self.collected):
                    raise KeyFileError(
                        "This is a copy of a key you have already provided.",
                        hint="Two copies of one key still count as one. You "
                        "need a key held by a different person.",
                    )
        except KeyFileError:
            self.attempted[resolved] = False
            raise

        self.attempted[resolved] = True
        return CollectedKey(
            path=Path(path),
            secret_key=parsed.secret_key,
            public_key=public_key,
            label=parsed.label or Path(path).stem,
        )

    def decrypt(self, entry: VaultEntry) -> Path:
        console = self.console
        assert self.toolchain is not None
        console.banner("Unlocking Your Information")

        problems = self.vault.check_integrity(entry)
        for problem in problems:
            console.warn(f"Note: {problem}")

        with console.task("Unlocking the document", min_duration=0.8):
            return operations.decrypt_entry(
                self.toolchain,
                self.vault,
                entry,
                [c.secret_key for c in self.collected],
                self.output_dir,
            )

    def finish(self, output: Path) -> None:
        console = self.console
        console.banner("Finished")
        console.ok("Your information has been unlocked.")
        console.blank()
        console.info("It has been saved to:")
        console.write(f"  {output}", "bold", "white")
        console.blank()
        console.warn(
            "This file is now readable by anyone who can use this computer."
        )
        console.info("Delete it when you no longer need it.")
        console.blank()

        if console.interactive and console.ask_yes_no(
            "Would you like to open it now?", default=True
        ):
            try:
                open_in_default_app(output)
            except Exception:
                console.warn("This computer could not open the file for you.")
                console.info(f"Open it yourself from: {output}")


# --------------------------------------------------------------------------
# Encryption -- the owner's path
# --------------------------------------------------------------------------


class EncryptWizard:
    """Walks the owner through choosing a document, keys, and distribution."""

    def __init__(self, layout: Layout, console: Console) -> None:
        self.layout = layout
        self.console = console
        self.toolchain: Toolchain | None = None
        self.vault = Vault(layout.encrypted_dir)

    def run(self) -> int:
        console = self.console
        try:
            console.clear()
            show_ascii_art(console, self.layout)
            console.set_steps(6)

            self.toolchain = Toolchain.discover(self.layout.binaries_dir)
            self.vault.ensure()

            self.welcome()
            source = self.choose_source()
            policy, keypairs, owner = self.configure_keys()
            result = self.encrypt(source, policy, keypairs, owner)
            self.distribute(result, keypairs, owner)
            self.finish(result, keypairs)
            return 0

        except OperationCancelled as exc:
            console.blank()
            console.warn(exc.message)
            return 1
        except DigitalLegacyError as exc:
            console.problem(exc)
            return 1
        except KeyboardInterrupt:
            console.blank()
            console.warn("Stopped.")
            return 130
        finally:
            console.pause("Press Enter to close this window...")

    def welcome(self) -> None:
        console = self.console
        console.banner("Getting Started")
        console.info(
            "This tool encrypts a document so that it can only be opened later "
            "when several people bring their keys together."
        )
        console.blank()
        console.info("You will choose:")
        console.bullets(
            [
                "the document to protect",
                "how many keys exist, and who holds them",
                "how many of those keys it takes to open it",
            ]
        )
        console.blank()
        console.note(
            "Before finishing, this tool will test that the encrypted file can "
            "actually be opened again."
        )
        console.pause("Press Enter to begin...")

    def choose_source(self) -> Path:
        console = self.console
        console.banner("Choose the Document")
        source = choose_file(
            console,
            title="Select the document to encrypt",
            file_types=ANY_FILE_TYPES,
            start_dir=Path.home() / "Desktop",
        )
        console.info(f"Selected: {source.name}")
        return source

    def configure_keys(self) -> tuple[Policy, list[KeyPair], str]:
        console = self.console
        console.banner("Set Up the Keys")

        existing = None
        try:
            existing = self.vault.load_policy()
        except (VaultError, PolicyError):
            existing = None

        if existing:
            console.info(
                f"There is already a key list here: {existing.describe()} keys."
            )
            choice = console.ask_choice(
                "What would you like to do?",
                [
                    ("1", "Create new keys (replaces the existing list)"),
                    ("2", f"Use the existing {existing.describe()} key list"),
                ],
                default="1",
            )
            if choice == "2":
                console.blank()
                console.warn(
                    "Encrypting to an existing key list means this run holds no "
                    "private keys, so recovery cannot be tested afterwards."
                )
                if not console.ask_yes_no("Continue anyway?", default=False):
                    raise OperationCancelled()
                return existing, [], ""

        owner = console.ask(
            "Your name, for the letters given to keyholders", default=""
        ).strip()

        console.blank()
        total = console.ask_int(
            f"How many keys should exist? (2-{MAX_SHARES}, 3 is a good default)",
            minimum=1,
            maximum=MAX_SHARES,
            default=3,
        )
        threshold = console.ask_int(
            f"How many of those {total} must be brought together to open it?",
            minimum=1,
            maximum=total,
            default=min(2, total),
        )

        console.blank()
        console.info("Who will hold each key? Names appear on their letters.")
        labels: list[str] = []
        for index in range(total):
            default = f"Key{index + 1}"
            label = console.ask(f"  Name for key {index + 1}", default=default)
            labels.append(agekeys.sanitise_label(label))

        keypairs: list[KeyPair] = []
        assert self.toolchain is not None
        for label in labels:
            with self.console.task(f"Creating the key for {label}", min_duration=0.15):
                keypairs.append(agekeys.generate(self.toolchain, label=label))

        policy = Policy(
            threshold=threshold, shares=[k.public_key for k in keypairs]
        ).validate()

        for note in policy.advisories():
            console.blank()
            console.warn(f"Worth considering: {note}")
        if policy.advisories() and not console.ask_yes_no(
            "Continue with this arrangement?", default=True
        ):
            raise OperationCancelled()

        return policy, keypairs, owner

    def encrypt(
        self,
        source: Path,
        policy: Policy,
        keypairs: Sequence[KeyPair],
        owner: str,
    ) -> operations.EncryptResult:
        console = self.console
        assert self.toolchain is not None
        console.banner("Encrypting")

        steps: list[str] = []
        with console.task(f"Encrypting {source.name}", min_duration=0.8):
            result = operations.encrypt_document(
                self.toolchain,
                source,
                self.vault,
                policy,
                progress=steps.append,
            )

        if keypairs:
            with console.task("Testing that it can be opened again", min_duration=0.8):
                check = operations.verify_entry(
                    self.toolchain,
                    self.vault,
                    result.entry,
                    keypairs,
                    threshold=policy.threshold,
                )
            result.verified = check.ok
            result.verification_detail = check.detail
            if check.ok:
                result.entry.verified_at = now_iso()
                console.ok(f"  {check.detail}")
            else:
                console.blank()
                console.error("The encrypted file could NOT be opened in a test.")
                console.error(f"  {check.detail}")
                console.blank()
                console.warn(
                    "Do not rely on this file. The problem is with this tool or "
                    "the binaries in internals/binaries, not with your document."
                )
        else:
            console.warn(
                "  Skipped the recovery test: no private keys were created in "
                "this run."
            )

        policy.save(self.vault.path / "recipients.yaml")
        self.vault.save_manifest(
            Manifest(
                owner=owner,
                threshold=policy.threshold,
                keyholders=[
                    {
                        "label": k.label,
                        "public_key": k.public_key,
                        "fingerprint": k.fingerprint(),
                    }
                    for k in keypairs
                ],
                binaries=self.toolchain.fingerprints(),
                entries=[result.entry],
            )
        )
        return result

    def distribute(
        self,
        result: operations.EncryptResult,
        keypairs: Sequence[KeyPair],
        owner: str,
    ) -> None:
        console = self.console
        console.banner("Keys and Letters")

        if not keypairs:
            console.info(
                "No new keys were created, so there is nothing to hand out."
            )
            return

        context = handoff.HandoffContext(
            owner=owner,
            document=result.entry.display_name,
            policy=result.policy,
            keypairs=list(keypairs),
            created=result.entry.encrypted_at[:10] or None,
        )

        keys_dir = self.layout.keys_out_dir
        for keypair in keypairs:
            content = agekeys.render_key_file(
                keypair,
                threshold=result.policy.threshold,
                total_shares=result.policy.total_shares,
                owner=owner,
                document=result.entry.display_name,
            )
            agekeys.write_key_file(
                keys_dir / agekeys.key_file_name(keypair.label), content
            )

        with console.task("Writing the key files", min_duration=0.2):
            pass

        written = handoff.write_handoff_packet(self.layout.handoff_dir, context)
        readme = [p for p in written if p.name == "READ ME FIRST.txt"]
        if readme:
            (self.vault.path / "READ ME FIRST.txt").write_text(
                readme[0].read_text(encoding="utf-8"), encoding="utf-8", newline="\n"
            )

        with console.task("Writing the letters for each keyholder", min_duration=0.2):
            pass

        console.blank()
        console.info("Key files:")
        console.write(f"  {keys_dir}", "bold", "white")
        console.info("Letters and your checklist:")
        console.write(f"  {self.layout.handoff_dir}", "bold", "white")

    def finish(
        self, result: operations.EncryptResult, keypairs: Sequence[KeyPair]
    ) -> None:
        console = self.console
        console.banner("Done")

        if result.verified:
            console.ok("Encrypted, and proven to open again.")
        elif keypairs:
            console.error("Encrypted, but the recovery test did not pass.")
        else:
            console.warn("Encrypted. Recovery was not tested.")

        console.blank()
        console.info("The encrypted document is at:")
        console.write(f"  {result.path}", "bold", "white")

        if not keypairs:
            return

        console.blank()
        console.warn("Now, in this order:")
        console.bullets(
            [
                "Give each keyholder their key file and their letter.",
                f"Then delete {self.layout.keys_out_dir.name} and "
                f"{self.layout.handoff_dir.name} -- while they exist, every "
                "key is on this one machine.",
                "Copy the whole project folder somewhere your family will "
                "find it, and tell someone it exists.",
            ]
        )
        console.blank()
        console.note("Full checklist: " + str(self.layout.handoff_dir / "WHAT TO DO NEXT.txt"))
