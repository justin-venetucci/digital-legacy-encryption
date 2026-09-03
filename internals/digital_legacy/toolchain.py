"""Discovery of, and every call into, the three vendored binaries.

`age` locates its plugins by looking up ``age-plugin-<name>`` on ``PATH``.  That
is why every subprocess call has to run with the binaries directory prepended to
``PATH``: without it, ``age`` reports that it cannot find ``age-plugin-sss`` even
though the file is sitting right next to it.  The old scripts got this right but
re-derived the environment in two places and relied on every future call site
remembering to pass ``env=self.env``.  Here there is exactly one way to run a
binary -- :meth:`Toolchain.run` -- and it cannot forget.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .errors import ToolchainError

DEFAULT_TIMEOUT = 120
"""Seconds.  Encryption of a large document is the slow case; a hung binary
should surface as a readable error rather than an interface that never returns.
"""

BINARY_NAMES = ("age", "age-keygen", "age-plugin-sss")


@dataclass(frozen=True)
class ToolResult:
    """Outcome of one binary invocation."""

    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


@dataclass
class Toolchain:
    """Resolved paths to the three binaries plus the environment to run them in.

    Construct with :meth:`discover` in normal use.  Tests build one directly
    (or substitute a stand-in with the same ``run`` signature), which is what
    makes the rest of the package exercisable without the real executables.
    """

    age: Path
    age_keygen: Path
    age_plugin_sss: Path
    env: dict[str, str] = field(default_factory=dict)
    timeout: int = DEFAULT_TIMEOUT

    # -- construction -----------------------------------------------------

    @staticmethod
    def executable_name(stem: str) -> str:
        return f"{stem}.exe" if os.name == "nt" else stem

    @classmethod
    def discover(
        cls, binaries_dir: Path, *, allow_path_fallback: bool = False
    ) -> Toolchain:
        """Resolve the three binaries or explain, in one message, what is missing.

        Reporting every missing file at once matters: a beneficiary who fixes
        them one error at a time gives up faster than one handed a checklist.
        """
        # Absolute, always. `age` locates its plugin through Go's exec.LookPath,
        # which refuses any hit that resolves inside the current directory:
        #     "age-plugin-sss resolves to executable in current directory"
        # A relative entry on PATH triggers exactly that and breaks decryption.
        # The old scripts escaped it only because Path(__file__) is absolute in
        # Python 3.9+; nothing made it true on purpose.
        binaries_dir = Path(binaries_dir).resolve()
        resolved: dict[str, Path] = {}
        missing: list[str] = []

        for stem in BINARY_NAMES:
            candidate = binaries_dir / cls.executable_name(stem)
            if candidate.exists():
                resolved[stem] = candidate
                continue
            found = shutil.which(stem) if allow_path_fallback else None
            if found:
                resolved[stem] = Path(found)
            else:
                missing.append(candidate.name)

        if missing:
            raise ToolchainError(
                "This tool needs "
                + ", ".join(missing)
                + f" in the folder {binaries_dir}, but "
                + ("they are" if len(missing) > 1 else "it is")
                + " not there.",
                hint=(
                    "Download the 'age' release for this computer and the\n"
                    "age-plugin-sss release, then copy these files in:\n"
                    + "\n".join(f"  - {name}" for name in missing)
                    + "\nOn macOS or Linux also run: chmod +x "
                    f"{binaries_dir}/*"
                ),
            )

        return cls(
            age=resolved["age"],
            age_keygen=resolved["age-keygen"],
            age_plugin_sss=resolved["age-plugin-sss"],
            env=cls.build_env(binaries_dir),
        )

    @staticmethod
    def build_env(binaries_dir: Path) -> dict[str, str]:
        """A copy of the environment with the binaries directory first on PATH.

        Absolute, for the exec.LookPath reason described in :meth:`discover`.
        """
        env = os.environ.copy()
        env["PATH"] = (
            str(Path(binaries_dir).resolve()) + os.pathsep + env.get("PATH", "")
        )
        return env

    # -- execution --------------------------------------------------------

    def run(
        self,
        executable: Path,
        *args: str,
        stdin: str | None = None,
        check: bool = True,
        timeout: int | None = None,
    ) -> ToolResult:
        """Run one binary and return its result.

        ``stdin`` is never echoed anywhere, because for ``age-keygen -y`` it is a
        private key.  Neither is it passed on the command line, where it would be
        visible to every other process on the machine via the process table.
        """
        argv = [str(executable), *args]
        try:
            completed = subprocess.run(
                argv,
                input=stdin,
                capture_output=True,
                text=True,
                env=self.env,
                timeout=timeout or self.timeout,
                check=False,
            )
        except FileNotFoundError as exc:
            raise ToolchainError(
                f"Could not run {Path(executable).name}: the file is missing.",
                hint=f"Expected it at: {executable}",
            ) from exc
        except PermissionError as exc:
            raise ToolchainError(
                f"Could not run {Path(executable).name}: permission denied.",
                hint=f"On macOS or Linux run: chmod +x {executable}",
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise ToolchainError(
                f"{Path(executable).name} did not finish within "
                f"{timeout or self.timeout} seconds and was stopped.",
                hint="If the document is very large, try again on a faster machine.",
            ) from exc
        except OSError as exc:  # pragma: no cover - platform specific
            raise ToolchainError(
                f"Could not run {Path(executable).name}: {exc}"
            ) from exc

        result = ToolResult(
            args=tuple(argv),
            returncode=completed.returncode,
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
        )
        if check and not result.ok:
            raise ToolchainError(
                f"{Path(executable).name} reported an error.",
                hint=(result.stderr or result.stdout).strip() or None,
            )
        return result

    # -- diagnostics ------------------------------------------------------

    def versions(self) -> dict[str, str]:
        """Version string per binary, for ``doctor`` output and the manifest.

        Not every build cooperates: ``age-plugin-sss`` v0.4.0 documents
        ``--version`` but prints its usage text for it, so a usage banner is
        treated as "no version reported" rather than being recorded as one.
        """
        probes = {
            "age": (self.age, "--version"),
            "age-keygen": (self.age_keygen, "--version"),
            "age-plugin-sss": (self.age_plugin_sss, "--version"),
        }
        out: dict[str, str] = {}
        for name, (executable, flag) in probes.items():
            try:
                result = self.run(executable, flag, check=False, timeout=15)
            except ToolchainError:
                out[name] = "unavailable"
                continue
            text = (result.stdout or result.stderr).strip()
            first = text.splitlines()[0].strip() if text else ""
            unhelpful = (
                not first
                or len(first) >= 60
                or first.lower().startswith(("usage", "flag provided"))
            )
            out[name] = "unknown" if unhelpful else first
        return out

    def fingerprints(self) -> dict[str, str]:
        """SHA-256 of each binary, truncated for display.

        Recorded at encryption time so ``doctor`` can tell the owner whether the
        binaries in the folder are still the ones that produced the ciphertext.
        A silently swapped ``age.exe`` is the kind of thing worth noticing on a
        tool whose whole job is to still work in twenty years.
        """
        import hashlib

        out: dict[str, str] = {}
        for name, path in (
            ("age", self.age),
            ("age-keygen", self.age_keygen),
            ("age-plugin-sss", self.age_plugin_sss),
        ):
            try:
                digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
                out[name] = digest[:16]
            except OSError:  # pragma: no cover - defensive
                out[name] = "unreadable"
        return out
