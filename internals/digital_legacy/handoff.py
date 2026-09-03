"""Paperwork for the people who will actually have to use this.

The technical half of a legacy scheme is the easy half.  The hard half is that
in fifteen years someone will find a USB stick in a drawer, or a printout in a
folder, and have to work out what it is, who else has one, and what to do next --
without being able to ask the person who set it up.

The old repository shipped no answer to that: keys landed in a folder named
``age-keys-DISTRIBUTE-AND-DELETE`` and the rest was left to the owner.  These
documents are the answer.  They are plain text, wrapped to 72 columns, because
plain text prints, survives, and needs no software to read.
"""

from __future__ import annotations

import textwrap
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Sequence

from .agekeys import KeyPair, key_file_name
from .policy import Policy

WIDTH = 72


def _wrap(text: str, indent: str = "") -> str:
    return "\n".join(
        textwrap.fill(
            paragraph,
            width=WIDTH,
            initial_indent=indent,
            subsequent_indent=indent,
        )
        if paragraph.strip()
        else ""
        for paragraph in text.split("\n")
    )


def _item(number: int, text: str, indent: str = "  ") -> str:
    """A numbered paragraph whose continuation lines align under its text."""
    marker = f"{number}. "
    return textwrap.fill(
        text,
        width=WIDTH,
        initial_indent=indent + marker,
        subsequent_indent=indent + " " * len(marker),
    )


def _count(number: int, singular: str, plural: str | None = None) -> str:
    """'1 other keyholder' / '2 other keyholders' -- readable either way."""
    word = singular if number == 1 else (plural or singular + "s")
    return f"{number} {word}"


def _rule(char: str = "=") -> str:
    return char * WIDTH


@dataclass
class HandoffContext:
    """Everything the documents need to say who, what, and how many."""

    owner: str = ""
    document: str = ""
    policy: Policy | None = None
    keypairs: Sequence[KeyPair] = ()
    created: str = ""

    @property
    def threshold(self) -> int:
        return self.policy.threshold if self.policy else 0

    @property
    def total(self) -> int:
        return self.policy.total_shares if self.policy else len(self.keypairs)

    @property
    def owner_phrase(self) -> str:
        return self.owner or "the person who set this up"

    def roster(self) -> list[str]:
        """Keyholder names only -- never fingerprints of *other* people's keys."""
        return [k.label or "(unnamed)" for k in self.keypairs]


def keyholder_letter(context: HandoffContext, keypair: KeyPair) -> str:
    """The sheet that travels with one share.

    Deliberately does not contain the key.  It is meant to be printable and
    storable *separately* from the key file, and a letter that quotes the secret
    would defeat that.
    """
    holder = keypair.label or "Keyholder"
    others = [n for n in context.roster() if n != holder]
    others_line = ", ".join(others) if others else "(not recorded)"
    doc = context.document or "a document"
    when = context.created or datetime.now().strftime("%Y-%m-%d")

    body = f"""\
{_rule()}
  ABOUT THE KEY YOU ARE HOLDING
{_rule()}

  For:        {holder}
  From:       {context.owner_phrase}
  Set up on:  {when}
  Key file:   {key_file_name(holder)}
  Share ID:   {keypair.fingerprint()}

{_rule('-')}
  WHAT THIS IS
{_rule('-')}

{_wrap(f"{context.owner_phrase} has encrypted {doc} so that it can be opened later by the people they trust, together. You are one of those people.", "  ")}

{_wrap(f"There are {context.total} keys in total. Any {context.threshold} of them, brought together, will open the document. Fewer than {context.threshold} will not -- your key on its own reveals nothing at all, which is why it is safe for you to simply keep it.", "  ")}

  The other keyholders are: {others_line}

{_rule('-')}
  WHAT TO DO NOW
{_rule('-')}

{_item(1, "Put the key file somewhere you will still be able to find it in ten or twenty years. A password manager, a home safe, or a printed copy in a document folder all work. Two copies in two places is better than one.")}

{_item(2, "Keep it separate from the encrypted document itself. If the two are stored together, the arrangement protects nothing.")}

{_item(3, "Do not email it or post it. If you must move it, hand it over in person or use an encrypted messenger.")}

{_item(4, "You do not need to do anything else, and you do not need to understand how it works. Nothing expires.")}

{_rule('-')}
  WHEN THE TIME COMES
{_rule('-')}

{_wrap(f"Find the folder or drive holding the encrypted document. Open the file called READ ME FIRST.txt inside it -- it explains the rest. In short: you will contact {_count(context.threshold - 1, 'other keyholder')}, run the program named \"Decrypt My Information\", and select each key file when asked.", "  ") if context.threshold > 1 else _wrap("Find the folder or drive holding the encrypted document. Open the file called READ ME FIRST.txt inside it -- it explains the rest. Your key alone is enough to open this document; no one else is needed.", "  ")}

{_wrap(f"If a key has been lost, that is survivable, as long as at least {context.threshold} of the {context.total} still exist.", "  ")}

{_rule()}
"""
    return body


def vault_readme(context: HandoffContext) -> str:
    """``READ ME FIRST.txt`` -- what to do, for whoever finds the encrypted folder."""
    doc = context.document or "a document"
    when = context.created or datetime.now().strftime("%Y-%m-%d")
    roster = context.roster()
    roster_block = (
        "\n".join(f"    - {name}" for name in roster) if roster else "    (not recorded)"
    )

    return f"""\
{_rule()}
  READ ME FIRST
{_rule()}

{_wrap(f"This folder holds an encrypted document belonging to {context.owner_phrase}, locked on {when}. You cannot open it by double-clicking it, and no password will help. It needs keys.", "  ")}

{_rule('-')}
  WHAT YOU NEED
{_rule('-')}

{_wrap(f"There are {context.total} key files in existence, each held by a different person. Any {context.threshold} of them, brought together, will unlock {doc}. It does not matter which {context.threshold}.", "  ")}

  The keyholders are:
{roster_block}

{_wrap("Each of them was given a file named 'Key for Digital Legacy - <name>.yaml' and a letter explaining it. You need them to bring, or send you, that file.", "  ")}

{_rule('-')}
  HOW TO OPEN THE DOCUMENT
{_rule('-')}

{_item(1, "Copy this whole folder onto a computer you trust. Do not use a shared or public one -- the document will be readable on it afterwards.")}

{_item(2, f"Collect the key files. You need {_count(context.threshold, 'of them', 'of them')}, from any of the people listed above. Put them somewhere you can find them, such as the Desktop.")}

{_item(3, "Run the program in the top folder:")}

       Windows:  Decrypt My Information-Windows.bat
       macOS:    Decrypt My Information-macOS.command
       Linux:    Decrypt My Information-Linux.sh

{_item(4, "Follow the prompts. It will ask you to choose each key file in turn, and will tell you if one is the wrong file or has been damaged. When it has enough, it writes the decrypted document to your Desktop.")}

{_rule('-')}
  IF SOMETHING GOES WRONG
{_rule('-')}

{_wrap("'This tool needs age.exe...' -- the three helper programs are missing from internals/binaries. See README.md in the top folder for where to get them.", "  ")}

{_wrap("'These keys cannot open this document' -- the keys are valid but belong to a different encrypted file. Check you have the right folder.", "  ")}

{_wrap(f"Fewer than {context.threshold} keys can be found -- there is no way around this, by design. The document cannot be opened. Nobody, including the software's authors, can recover it.", "  ")}

{_rule('-')}
  AFTERWARDS
{_rule('-')}

{_wrap("The decrypted file is named starting with [SENSITIVE]. It is an ordinary, readable copy of a private document. Store it as carefully as you would the original, and delete it when you are finished.", "  ")}

{_rule()}
"""


def owner_summary(context: HandoffContext) -> str:
    """A checklist for the owner, printed after encryption.

    Written to the handoff folder rather than only to the screen, because the
    step that actually matters -- distributing the shares and then deleting the
    local copies -- happens after the program has exited.
    """
    lines = [
        _rule(),
        "  WHAT TO DO NEXT",
        _rule(),
        "",
        f"  Document:   {context.document or '(not recorded)'}",
        f"  Protection: any {context.threshold} of {context.total} keys",
        f"  Created:    {context.created or datetime.now().strftime('%Y-%m-%d')}",
        "",
        _rule("-"),
        "  1. HAND OUT THE KEYS",
        _rule("-"),
        "",
    ]
    for keypair in context.keypairs:
        holder = keypair.label or "(unnamed)"
        lines.append(f"    [ ] {holder:<24} {key_file_name(holder)}")
        lines.append(f"        share {keypair.fingerprint()} + their letter")
    lines += [
        "",
        _wrap(
            "Give each person their key file and the letter addressed to them. "
            "In person, or through an encrypted messenger. Not by email.",
            "  ",
        ),
        "",
        _rule("-"),
        "  2. DELETE THE LOCAL COPIES",
        _rule("-"),
        "",
        _wrap(
            "Once every key has been handed over, delete the folder named "
            "age-keys-DISTRIBUTE-AND-DELETE, and this handoff folder with it. "
            "While they exist, every key sits on one machine -- which is the "
            "arrangement this whole scheme is meant to avoid.",
            "  ",
        ),
        "",
        _rule("-"),
        "  3. STORE THE ENCRYPTED FOLDER WHERE IT WILL BE FOUND",
        _rule("-"),
        "",
        _wrap(
            "Copy the whole project folder somewhere your family will look: a "
            "USB stick with your will, a cloud drive they can reach, a home "
            "safe. It is safe to store openly -- without the keys it is just "
            "noise. More copies is strictly better.",
            "  ",
        ),
        "",
        _wrap(
            "Tell someone it exists. A perfectly built system nobody knows "
            "about is the most common way this fails.",
            "  ",
        ),
        "",
        _rule("-"),
        "  4. CHECK IT ONCE A YEAR",
        _rule("-"),
        "",
        _wrap(
            "Run the health check and confirm the keyholders still have their "
            "files and still know what they are for:",
            "  ",
        ),
        "",
        "      python internals/scripts/encrypt.py --doctor",
        "",
        _rule(),
        "",
    ]
    return "\n".join(lines)


def write_handoff_packet(
    directory: Path, context: HandoffContext, *, include_readme: bool = True
) -> list[Path]:
    """Write one letter per keyholder, plus the owner's checklist."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    for keypair in context.keypairs:
        holder = keypair.label or "Keyholder"
        path = directory / f"Letter for {holder}.txt"
        path.write_text(keyholder_letter(context, keypair), encoding="utf-8", newline="\n")
        written.append(path)

    summary = directory / "WHAT TO DO NEXT.txt"
    summary.write_text(owner_summary(context), encoding="utf-8", newline="\n")
    written.append(summary)

    if include_readme:
        readme = directory / "READ ME FIRST.txt"
        readme.write_text(vault_readme(context), encoding="utf-8", newline="\n")
        written.append(readme)

    return written
