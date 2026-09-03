"""Reading and writing ``recipients.yaml``, the sharing policy.

``recipients.yaml`` is the one file whose format we do not get to choose: it is
fed straight to ``age-plugin-sss --generate-recipient``, so it has to be YAML
that the plugin's Go parser accepts.  Everything else this tool writes uses JSON
instead, for exactly this reason.

The project takes no third-party dependencies, so there is no PyYAML.  The old
scripts coped by scattering ``re.search`` calls at the call sites, which had two
consequences worth fixing:

* ``re.search(r'threshold:\\s*(\\d+)')`` matched inside comments, so a file
  carrying ``# threshold: 99 (old value)`` above ``threshold: 2`` read as 99 --
  and 99 is unsatisfiable, so decryption would demand keys that do not exist.
* Nothing ever checked ``threshold <= len(shares)``, so a typo produced a vault
  that encrypted successfully and could never be opened.  For this tool that is
  the worst possible failure: silent, and only discovered when it matters.

So this module parses a small, explicit subset line by line and validates the
result, rather than pattern-matching a whole file.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .errors import PolicyError

PUBLIC_KEY_RE = re.compile(r"^age1[02-9ac-hj-np-z]{50,}$")

MAX_SHARES = 20
"""An arbitrary but deliberate ceiling.

Shamir itself is happy with far more, but a policy with twenty holders is a
policy nobody can convene.  The old script capped at 10 with no explanation;
this raises the ceiling while keeping one, and the wizard still recommends 3-5.
"""


@dataclass
class Policy:
    """Who can decrypt, and how many of them it takes."""

    threshold: int
    shares: list[str] = field(default_factory=list)

    # -- validation -------------------------------------------------------

    def validate(self) -> Policy:
        if not self.shares:
            raise PolicyError(
                "The key configuration does not list any keys.",
                hint="recipients.yaml needs a 'shares:' list with one age1... "
                "public key per line.",
            )

        duplicates = {k for k in self.shares if self.shares.count(k) > 1}
        if duplicates:
            raise PolicyError(
                "The key configuration lists the same key more than once.",
                hint="Each share must be a different key, otherwise two "
                "keyholders can hold what counts as one share.",
            )

        for key in self.shares:
            if not PUBLIC_KEY_RE.match(key):
                raise PolicyError(
                    f"'{key[:24]}...' is not a valid age public key.",
                    hint="Public keys start with 'age1' and are 62 characters "
                    "long.",
                )

        if self.threshold < 1:
            raise PolicyError(
                "The number of keys required to decrypt must be at least 1."
            )

        if self.threshold > len(self.shares):
            raise PolicyError(
                f"The configuration requires {self.threshold} keys to decrypt "
                f"but only lists {len(self.shares)}.",
                hint="This document could never be opened. Lower 'threshold' "
                f"to {len(self.shares)} or fewer, or add more keys.",
            )

        if len(self.shares) > MAX_SHARES:
            raise PolicyError(
                f"The configuration lists {len(self.shares)} keys; "
                f"{MAX_SHARES} is the most this tool supports."
            )

        return self

    # -- warnings ---------------------------------------------------------

    def advisories(self) -> list[str]:
        """Non-fatal observations worth putting in front of the owner.

        These are judgement calls about the *arrangement*, not the file, so they
        never block: it is the owner's document and the owner's family.
        """
        notes: list[str] = []
        if self.threshold == 1:
            notes.append(
                f"Any single one of the {len(self.shares)} keys can decrypt this "
                "on its own. That is convenient, but it means one lost or "
                "stolen key is a full disclosure."
            )
        if self.threshold == len(self.shares) and self.threshold > 1:
            notes.append(
                f"All {self.threshold} keys are required, so losing any single "
                "key makes the document permanently unrecoverable. Consider "
                f"{self.threshold} of {self.threshold + 1}."
            )
        if len(self.shares) - self.threshold == 0 and self.threshold > 3:
            notes.append(
                "Requiring more than three people to convene at once has "
                "defeated real estates. Fewer is usually safer."
            )
        return notes

    @property
    def total_shares(self) -> int:
        return len(self.shares)

    def describe(self) -> str:
        return f"{self.threshold} of {self.total_shares}"

    # -- serialisation ----------------------------------------------------

    def render(self) -> str:
        """Emit YAML that ``age-plugin-sss`` accepts.

        Kept minimal on purpose.  Keyholder names live in ``vault.json``, not
        here as trailing comments, so that nothing this tool adds can perturb
        the one file another program has to parse.
        """
        self.validate()
        lines = [
            "# Sharing policy for the Digital Legacy Encryption Suite.",
            "#",
            f"# Any {self.threshold} of these {self.total_shares} keys, brought "
            "together, can decrypt",
            "# the document. Keep this file with the encrypted document; it holds",
            "# public keys only and no secrets.",
            "#",
            "# Editing it will NOT change an already-encrypted file -- the",
            "# threshold is sealed into the ciphertext when it is written.",
            "",
            f"threshold: {self.threshold}",
            "shares:",
        ]
        lines.extend(f"  - {key}" for key in self.shares)
        return "\n".join(lines) + "\n"

    @classmethod
    def parse(cls, text: str) -> Policy:
        """Parse the subset of YAML this tool writes, strictly.

        Handles: comments, blank lines, ``threshold: N``, and a ``shares:``
        block of ``- age1...`` items.  Anything else is refused with a message
        naming the line, rather than being silently ignored.
        """
        threshold: int | None = None
        shares: list[str] = []
        in_shares = False

        # Notepad writes a byte-order mark when it saves as UTF-8, and owners do
        # edit this file by hand. Without this the BOM fuses onto the first key
        # name and the file is rejected for an invisible character.
        text = text.lstrip("﻿")

        for number, raw in enumerate(text.splitlines(), start=1):
            line = raw.split("#", 1)[0].rstrip()
            if not line.strip():
                continue

            stripped = line.strip()

            if stripped.startswith("-"):
                if not in_shares:
                    raise PolicyError(
                        f"Line {number} of the key configuration lists a key "
                        "before the 'shares:' heading.",
                        hint="The file should read 'threshold: N', then "
                        "'shares:', then one '  - age1...' line per key.",
                    )
                value = stripped[1:].strip()
                if not value:
                    # The old encrypt.py wrote a skeleton with empty '  - '
                    # placeholder rows; skip them rather than choke.
                    continue
                shares.append(value)
                continue

            in_shares = False

            if ":" not in stripped:
                raise PolicyError(
                    f"Line {number} of the key configuration could not be "
                    f"understood: {stripped[:40]!r}"
                )

            field_name, _, value = stripped.partition(":")
            field_name = field_name.strip().lower()
            value = value.strip()

            if field_name == "threshold":
                if not value:
                    raise PolicyError(
                        "The key configuration has a 'threshold:' with no "
                        "number after it.",
                        hint="Set it to how many keys must be brought together, "
                        "for example 'threshold: 2'.",
                    )
                if not value.isdigit():
                    raise PolicyError(
                        f"'threshold: {value}' is not a whole number."
                    )
                if threshold is not None:
                    raise PolicyError(
                        "The key configuration sets 'threshold' more than once.",
                        hint="Delete the duplicate line so there is no doubt "
                        "which value applies.",
                    )
                threshold = int(value)
            elif field_name == "shares":
                if value:
                    raise PolicyError(
                        "The 'shares:' line should be followed by one key per "
                        "line, not by a value on the same line."
                    )
                in_shares = True
            else:
                raise PolicyError(
                    f"Line {number} of the key configuration uses an unknown "
                    f"setting '{field_name}'.",
                    hint="This tool understands 'threshold' and 'shares'. "
                    "Nested share groups are supported by age-plugin-sss but "
                    "not by this wizard.",
                )

        if threshold is None:
            raise PolicyError(
                "The key configuration does not say how many keys are needed.",
                hint="Add a line reading 'threshold: 2' (or whatever number "
                "applies) at the top of recipients.yaml.",
            )

        return cls(threshold=threshold, shares=shares).validate()

    # -- files ------------------------------------------------------------

    @classmethod
    def load(cls, path: Path) -> Policy:
        path = Path(path)
        try:
            text = path.read_text(encoding="utf-8-sig")
        except FileNotFoundError:
            raise PolicyError(
                f"The key configuration file is missing: {path.name}",
                hint=f"It should sit next to the encrypted document in {path.parent}.",
            ) from None
        except OSError as exc:
            raise PolicyError(f"Could not read {path.name}: {exc}") from exc
        try:
            return cls.parse(text)
        except PolicyError as exc:
            raise PolicyError(f"{path.name}: {exc.message}", hint=exc.hint) from None

    def save(self, path: Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.render(), encoding="utf-8", newline="\n")
        return path
