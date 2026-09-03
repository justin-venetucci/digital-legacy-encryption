#!/usr/bin/env python3
"""Run the whole suite: ``python tests/run_tests.py``.

Uses :mod:`unittest` from the standard library, so the suite has the same
dependency footprint as the shipped code: none.  Tests that need the vendored
``age`` binaries skip themselves when those are absent, which is the state of a
fresh clone -- so a green run there means "everything checkable passed", not
"everything passed".
"""

import sys
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
sys.path.insert(0, str(TESTS.parent / "internals"))


def main() -> int:
    suite = unittest.defaultTestLoader.discover(str(TESTS), pattern="test_*.py")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.skipped:
        print(f"\n{len(result.skipped)} test(s) skipped:")
        for case, reason in result.skipped:
            print(f"  - {case}: {reason}")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
