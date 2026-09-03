#!/usr/bin/env python3
"""Encrypt a document and produce the keys and letters that go with it.

Kept at its original path so existing instructions keep working; the logic
lives in the `digital_legacy` package beside it.

Useful flags:

    python internals/scripts/encrypt.py                 guided wizard
    python internals/scripts/encrypt.py --doctor        annual health check
    python internals/scripts/encrypt.py --help          everything else
"""

import sys
from pathlib import Path

INTERNALS = Path(__file__).resolve().parent.parent
if str(INTERNALS) not in sys.path:
    sys.path.insert(0, str(INTERNALS))


def main() -> int:
    if sys.version_info < (3, 9):  # noqa: UP036 - deliberate floor check
        print(
            "This tool needs Python 3.9 or newer. "
            f"This computer has {sys.version.split()[0]}.\n"
            "Install a current version from python.org and run this again."
        )
        return 1

    from digital_legacy.cli import main as cli_main

    argv = sys.argv[1:]
    if "--doctor" in argv:
        # Advertised in the owner's checklist as the yearly check, so it works
        # wherever it appears and alongside the global flags.
        argv = ["doctor"] + [a for a in argv if a != "--doctor"]
    elif not argv:
        argv = ["encrypt"]
    elif argv[0].startswith("-") and argv[0] not in ("-h", "--help", "--version"):
        argv = ["encrypt", *argv]
    return cli_main(argv)


if __name__ == "__main__":
    sys.exit(main())
