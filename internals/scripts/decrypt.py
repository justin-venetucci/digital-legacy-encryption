#!/usr/bin/env python3
"""Open an encrypted document.  Run this, or the wrapper in the folder above.

This file stays at the path the shipped wrappers and every existing set of
instructions already point at.  The logic lives in the `digital_legacy` package
beside it, so that both wizards share one implementation instead of the two
hand-copied scripts that used to drift apart.

Nothing here needs installing: the package directory is added to the import
path, so a beneficiary needs only a Python interpreter.
"""

import sys
from pathlib import Path

INTERNALS = Path(__file__).resolve().parent.parent
if str(INTERNALS) not in sys.path:
    sys.path.insert(0, str(INTERNALS))


def main() -> int:
    if sys.version_info < (3, 9):
        print(
            "This tool needs Python 3.9 or newer. "
            f"This computer has {sys.version.split()[0]}.\n"
            "Install a current version from python.org and run this again."
        )
        return 1

    from digital_legacy.cli import main as cli_main

    argv = sys.argv[1:]
    # Bare invocation is the beneficiary's case: run the wizard.
    if not argv:
        argv = ["decrypt"]
    elif argv[0].startswith("-") and argv[0] not in ("-h", "--help", "--version"):
        argv = ["decrypt", *argv]
    return cli_main(argv)


if __name__ == "__main__":
    sys.exit(main())
