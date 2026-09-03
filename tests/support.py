"""Shared test scaffolding.

Two layers, deliberately:

* Most tests use :class:`FakeToolchain`, which answers like the real binaries
  without needing them.  These run anywhere, in milliseconds, and cover the
  parsing, validation, naming and error-handling that carried the original
  bugs.
* :func:`real_toolchain` returns the genuine binaries when they are present, and
  the integration tests skip themselves when they are not.  Cryptographic
  round-trips are only meaningful against the real thing.

The suite uses :mod:`unittest` rather than pytest so it runs with nothing
installed, which is the same constraint the shipped code lives under.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
ROOT = TESTS_DIR.parent
INTERNALS = ROOT / "internals"
if str(INTERNALS) not in sys.path:
    sys.path.insert(0, str(INTERNALS))

from digital_legacy.errors import ToolchainError  # noqa: E402
from digital_legacy.layout import Layout  # noqa: E402
from digital_legacy.toolchain import ToolResult, Toolchain  # noqa: E402

# A handful of syntactically valid age keys, fixed so tests are deterministic.
# Bech32 alphabet: no 1, b, i or o after the separator.
PUBLIC_KEYS = [
    "age1e22387y6esp6r8edp8arw5f5d4t4z7ukzx47g4wm26ahhuj7lefsjsy7fj",
    "age1wz0h95zkrc66dq0w5hmquu4a6q5ap7xuefda85l304hk7ff55eyszzhjx8",
    "age1w5h3lvt6xzx6vl948ywkgejey09xuh742740gyzxyur6pr29tysqtran88",
    "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqzzzz",
]
SECRET_KEYS = [
    "AGE-SECRET-KEY-1TTZ4A6QGRSC9JNSAL85CVKX37EU6W3ULHHGAVH2XPLSC399SFWYQ20J4UT",
    "AGE-SECRET-KEY-17WC6CFVLW7GSQVAY9QLJU4KU0RA6UH585WG954RKA2LQ3L7CA8DQFP0PRW",
    "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQZZZZ",
    "AGE-SECRET-KEY-1ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZQQQQ",
]


class FakeToolchain(Toolchain):
    """Stands in for the three binaries, with a real toolchain's interface.

    It models just enough behaviour to exercise the callers: keygen returns the
    next fixed pair, ``-y`` maps secret to public through a dictionary, and the
    plugin echoes recognisable strings.  Anything a caller depends on beyond
    that is a sign the caller is reaching too far into the binaries.
    """

    def __init__(self) -> None:
        super().__init__(
            age=Path("age"),
            age_keygen=Path("age-keygen"),
            age_plugin_sss=Path("age-plugin-sss"),
            env={},
        )
        self.pairs = list(zip(PUBLIC_KEYS, SECRET_KEYS))
        self.issued = 0
        self.calls: list[tuple[str, ...]] = []
        self.mapping = dict(zip(SECRET_KEYS, PUBLIC_KEYS))
        self.fail_on: str | None = None

    def run(self, executable, *args, stdin=None, check=True, timeout=None) -> ToolResult:
        name = Path(executable).name
        self.calls.append((name, *args))

        if self.fail_on and self.fail_on in name:
            result = ToolResult((name,), 1, "", "simulated failure")
            if check:
                raise ToolchainError(f"{name} reported an error.", hint="simulated failure")
            return result

        if name.startswith("age-keygen"):
            return self._keygen(args, stdin)
        if name.startswith("age-plugin-sss"):
            return self._plugin(args)
        return self._age(args)

    # -- individual binaries ---------------------------------------------

    def _keygen(self, args, stdin) -> ToolResult:
        if "-y" in args:
            public = self.mapping.get((stdin or "").strip())
            if not public:
                return ToolResult(("age-keygen", "-y"), 1, "", "malformed secret key")
            return ToolResult(("age-keygen", "-y"), 0, public + "\n", "")
        if "--version" in args:
            return ToolResult(("age-keygen",), 0, "v1.1.0\n", "")

        public, secret = self.pairs[self.issued % len(self.pairs)]
        self.issued += 1
        return ToolResult(
            ("age-keygen",),
            0,
            f"# created: 2026-01-01T00:00:00Z\n# public key: {public}\n{secret}\n",
            "",
        )

    def _plugin(self, args) -> ToolResult:
        if "--generate-recipient" in args:
            return ToolResult(args, 0, "age1sss1fakerecipient\n", "")
        if "--generate-identity" in args:
            return ToolResult(args, 0, "AGE-PLUGIN-SSS-1FAKEIDENTITY\n", "")
        if "--inspect" in args:
            return ToolResult(args, 0, "sss (t=2)\n", "")
        return ToolResult(args, 0, "Usage:\n", "")

    def _age(self, args) -> ToolResult:
        """Model encryption as a copy, so round-trip tests still mean something."""
        argv = list(args)
        output = argv[argv.index("-o") + 1] if "-o" in argv else None
        source = Path(argv[-1])
        if not output:
            return ToolResult(tuple(argv), 0, "", "")
        Path(output).write_bytes(
            source.read_bytes() if source.exists() else b"ciphertext"
        )
        return ToolResult(tuple(argv), 0, "", "")


def real_toolchain() -> Toolchain | None:
    """The genuine binaries, or ``None`` when they are not installed."""
    try:
        return Toolchain.discover(INTERNALS / "binaries")
    except ToolchainError:
        return None


def requires_binaries(test):
    """Skip a test when the vendored binaries are absent (the fresh-clone state)."""
    return unittest.skipIf(
        real_toolchain() is None,
        "needs age, age-keygen and age-plugin-sss in internals/binaries",
    )(test)


class RealVaultTouched(AssertionError):
    """Raised when a test is about to write into the checked-out repository."""


def guard_not_the_real_repo(layout: Layout) -> None:
    """Refuse to proceed if a test layout points at the working copy.

    Learned the hard way: an early version of the wizard tests let the CLI
    discover its own layout, so the suite encrypted into internals/encrypted and
    overwrote the committed sample vault. Tests now pass a layout explicitly,
    and this asserts they actually did.
    """
    if layout.root.resolve() == ROOT.resolve():
        raise RealVaultTouched(
            "This test is pointed at the real repository. Build a Layout with "
            "make_layout(tmpdir) and pass it explicitly."
        )


def make_layout(root: Path) -> Layout:
    """A Layout rooted at a temporary directory, with the real binaries linked in."""
    (root / "internals").mkdir(parents=True, exist_ok=True)
    (root / "internals" / "encrypted").mkdir(exist_ok=True)
    binaries = INTERNALS / "binaries"
    target = root / "internals" / "binaries"
    if binaries.is_dir() and not target.exists():
        target.mkdir()
        for item in binaries.iterdir():
            if item.is_file() and not item.name.endswith(".placeholder"):
                target.joinpath(item.name).write_bytes(item.read_bytes())
    layout = Layout(root=root)
    guard_not_the_real_repo(layout)
    return layout


def strip_ansi(text: str) -> str:
    return re.sub(r"\033\[[0-9;]*m", "", text)
