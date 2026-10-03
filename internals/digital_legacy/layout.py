"""Where everything lives on disk.

One object answers every "which folder?" question, so the two wizards cannot
disagree about it -- which they previously did: the decrypt script opened its
file chooser in ``internals/keys``, a directory that has never existed in this
repository, so every beneficiary started at an empty location while the demo
shares sat in ``internals/sample-keys``.

Paths are resolved from this file's own location rather than the working
directory, so the tool behaves the same whether it is launched by double-click,
from a shell in the repository root, or by a wrapper script from somewhere else.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT_ENV_VAR = "DIGITAL_LEGACY_ROOT"
"""Point the tool at a different project folder.

Useful for keeping a vault on a USB stick or an external drive while running
the code from a checkout, and it is what the test suite uses so a test run can
never touch the real vault.
"""


def _compiled_program_dir() -> Path | None:
    """The folder holding the standalone executable, when running as one.

    The copy handed to beneficiaries is compiled so they need no Python. Inside
    that build ``__file__`` points into the unpacked program folder rather than
    at ``internals/digital_legacy``, so counting parents from it lands on the
    wrong directory -- and the wizard then reports the binaries and the
    encrypted document as missing.
    """
    # Nuitka supplies this name at compile time. It is not an entry in
    # globals(), so it has to be referenced directly to be seen at all.
    try:
        compiled = __compiled__  # type: ignore[name-defined]  # noqa: F821
    except NameError:
        compiled = None
    # sys.executable, not __compiled__.containing_dir: in a standalone build
    # that attribute names the folder *above* the program folder. resolve()
    # matters too -- Windows can hand back 8.3 short names ("INTERN~1"), and
    # the caller checks the folder's name.
    if compiled is not None or getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return None


@dataclass(frozen=True)
class Layout:
    """The project's folders, all derived from the package's own location."""

    root: Path

    @classmethod
    def discover(cls, start: Path | None = None) -> Layout:
        """Find the project root from the installed package location.

        ``internals/digital_legacy/layout.py`` -> root is two levels up.  When
        the package has been pip-installed elsewhere, fall back to the current
        directory so a developer checkout still works.
        """
        override = os.environ.get(ROOT_ENV_VAR)
        if override:
            return cls(root=Path(override).expanduser().resolve())

        if start is None:
            frozen = _compiled_program_dir()
            # internals/program/decrypt.exe -> root is two levels up. The check
            # on the folder name keeps a stray copy of the exe from inventing a
            # project root out of wherever it happens to sit.
            if frozen and frozen.parent.name == "internals":
                return cls(root=frozen.parent.parent)

        here = Path(start or __file__).resolve()
        internals = here.parent.parent
        root = internals.parent
        if (internals / "binaries").is_dir() or internals.name == "internals":
            return cls(root=root)
        return cls(root=Path.cwd())

    # -- folders ----------------------------------------------------------

    @property
    def internals_dir(self) -> Path:
        return self.root / "internals"

    @property
    def binaries_dir(self) -> Path:
        return self.internals_dir / "binaries"

    @property
    def encrypted_dir(self) -> Path:
        return self.internals_dir / "encrypted"

    @property
    def sample_keys_dir(self) -> Path:
        return self.internals_dir / "sample-keys"

    @property
    def keys_out_dir(self) -> Path:
        """Where freshly generated private keys land.

        The name is the instruction.  These files are the only copies of the
        secrets, and they are meant to leave this machine.
        """
        return self.internals_dir / "age-keys-DISTRIBUTE-AND-DELETE"

    @property
    def handoff_dir(self) -> Path:
        return self.internals_dir / "handoff"

    @property
    def ascii_art(self) -> Path:
        return self.internals_dir / "scripts" / "resources" / "ascii.txt"

    # -- lookups ----------------------------------------------------------

    def key_search_dir(self) -> Path:
        """Where a beneficiary's key files most plausibly are.

        Checked in order of likelihood, and every candidate is tested before it
        is offered -- unlike the old hard-coded path to a folder that did not
        exist.
        """
        candidates = [
            self.keys_out_dir,
            Path.home() / "Desktop",
            Path.home() / "Downloads",
            self.sample_keys_dir,
            Path.home(),
        ]
        for candidate in candidates:
            if candidate.is_dir():
                return candidate
        return self.root
