#!/usr/bin/env python3
"""Build the folder a beneficiary is actually given, and zip it.

The repository is the owner's workshop: it carries tests, a sample vault, and
launchers that expect a Python interpreter. The people who will one day open
the document have none of that and should need none of it. This script turns a
*production root* -- a folder holding the real ``internals/encrypted`` and the
real ``internals/binaries`` -- into a self-contained package:

    <name>-<date>-UNZIP-ME.zip
        Decrypt My Information-Windows.bat
        internals/program/      standalone decrypt.exe, no Python needed
        internals/binaries/     age, age-keygen, age-plugin-sss
        internals/encrypted/    the ciphertext, recipients.yaml, vault.json
        internals/scripts/, internals/digital_legacy/    the Python fallback

It refuses to package anything that looks like a private key or a decrypted
document, and it runs the health check against the staged copy -- through the
compiled program too -- before writing the zip, so a package that cannot find
its own vault never leaves this machine.

Compiling needs Nuitka (``pip install nuitka``). That is a build-time tool for
the owner; nothing it produces adds a dependency for anyone else. Standard
library only otherwise, like the rest of the project.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
INTERNALS = REPO / "internals"
if str(INTERNALS) not in sys.path:
    sys.path.insert(0, str(INTERNALS))

LAUNCHER = "Decrypt My Information-Windows.bat"
DEFAULT_NAME = "digital-legacy-decryption-program"

# Whole keys only. The age binaries and this project's own source both contain
# the bare "AGE-SECRET-KEY-" prefix, which is not a secret.
SECRET_RE = re.compile(rb"AGE-(?:SECRET-KEY|PLUGIN-SSS)-1[02-9AC-HJ-NP-Z]{40,}")

# Folders that must never travel with the encrypted document.
FORBIDDEN_DIRS = {"age-keys-DISTRIBUTE-AND-DELETE", "handoff", "sample-keys"}

# Compiled code: large, and legitimately full of key-format constants.
UNSCANNED = ("internals/program/", "internals/binaries/")


class BuildError(Exception):
    """Something is wrong with the inputs or the result; the message says what."""


# --------------------------------------------------------------------------
# Compile
# --------------------------------------------------------------------------


def compile_program(build_dir: Path) -> Path:
    """Compile the decrypt entry point to a standalone folder; return it."""
    build_dir.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    # decrypt.py adds internals/ to sys.path at run time, which a compiler
    # cannot see. Without this the package is silently left out of the build.
    env["PYTHONPATH"] = str(INTERNALS) + os.pathsep + env.get("PYTHONPATH", "")
    command = [
        sys.executable,
        "-m",
        "nuitka",
        "--standalone",
        "--enable-plugin=tk-inter",
        "--include-package=digital_legacy",
        "--windows-console-mode=force",
        "--assume-yes-for-downloads",
        f"--output-dir={build_dir}",
        "--output-filename=decrypt.exe",
        str(INTERNALS / "scripts" / "decrypt.py"),
    ]
    try:
        completed = subprocess.run(command, env=env, cwd=REPO, check=False)
    except OSError as exc:
        raise BuildError(f"Could not start the compiler: {exc}") from exc
    if completed.returncode != 0:
        raise BuildError(
            "Nuitka did not finish. If it is not installed, run "
            "'python -m pip install nuitka' and try again."
        )
    dist = build_dir / "decrypt.dist"
    if not (dist / "decrypt.exe").is_file():
        raise BuildError(f"The compiler produced no decrypt.exe in {dist}.")
    return dist


# --------------------------------------------------------------------------
# Stage
# --------------------------------------------------------------------------


def stage(production_root: Path, stage_dir: Path, program: Path | None) -> None:
    """Assemble the package in ``stage_dir`` from the repo and the production root."""
    source = production_root / "internals"
    vault = source / "encrypted"
    binaries = source / "binaries"
    if not any(vault.glob("*.age")):
        raise BuildError(f"There is no encrypted document in {vault}.")
    if not binaries.is_dir():
        raise BuildError(f"There is no binaries folder at {binaries}.")

    if stage_dir.exists():
        shutil.rmtree(stage_dir)
    target = stage_dir / "internals"
    target.mkdir(parents=True)

    # Batch files must be CRLF: cmd.exe mis-parses labels in an LF-only file,
    # and this launcher has one.
    text = (REPO / LAUNCHER).read_bytes().replace(b"\r\n", b"\n")
    (stage_dir / LAUNCHER).write_bytes(text.replace(b"\n", b"\r\n"))
    for name in ("README.md", "LICENSE"):
        if (REPO / name).is_file():
            shutil.copy2(REPO / name, stage_dir / name)

    shutil.copytree(vault, target / "encrypted")

    (target / "binaries").mkdir()
    for item in sorted(binaries.iterdir()):
        if item.is_file() and not item.name.endswith(".placeholder"):
            shutil.copy2(item, target / "binaries" / item.name)

    # The Python fallback: used when the compiled program cannot run, and by
    # anyone in the future who would rather read the code than trust an exe.
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc")
    shutil.copytree(INTERNALS / "digital_legacy", target / "digital_legacy", ignore=ignore)
    shutil.copytree(INTERNALS / "scripts", target / "scripts", ignore=ignore)

    if program is not None:
        shutil.copytree(program, target / "program")


def find_secrets(stage_dir: Path) -> list[str]:
    """Anything in the staged tree that must not be handed out, as messages."""
    stage_dir = Path(stage_dir)
    problems: list[str] = []
    for path in sorted(stage_dir.rglob("*")):
        relative = path.relative_to(stage_dir).as_posix()
        if path.is_dir():
            if path.name in FORBIDDEN_DIRS:
                problems.append(f"{relative}/ holds key material or paperwork")
            continue
        if "[SENSITIVE]" in path.name:
            problems.append(f"{relative} looks like a decrypted document")
            continue
        if relative.startswith(UNSCANNED):
            continue
        try:
            data = path.read_bytes()
        except OSError as exc:
            problems.append(f"{relative} could not be read ({exc})")
            continue
        if SECRET_RE.search(data):
            problems.append(f"{relative} contains a private key")
    return problems


# --------------------------------------------------------------------------
# Check
# --------------------------------------------------------------------------


def health_check(stage_dir: Path) -> list[str]:
    """Run ``doctor`` on the staged copy; return its failures."""
    from digital_legacy import doctor
    from digital_legacy.layout import Layout

    report = doctor.run_checks(Layout(root=stage_dir))
    return [f"{check.name}: {check.detail}" for check in report.failures]


def compiled_program_finds_vault(stage_dir: Path) -> str:
    """Run the staged exe's own health check; return its output.

    This is the check that matters for a compiled build: it proves the program
    locates the vault from where it sits, with no environment variable helping.
    """
    env = {k: v for k, v in os.environ.items() if k != "DIGITAL_LEGACY_ROOT"}
    exe = stage_dir / "internals" / "program" / "decrypt.exe"
    try:
        completed = subprocess.run(
            [str(exe), "doctor", "--no-colour"],
            env=env,
            cwd=stage_dir.anchor,  # deliberately not the package folder
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BuildError(f"The compiled program could not be run: {exc}") from exc
    output = completed.stdout + completed.stderr
    if completed.returncode != 0 or "[FAIL]" in output:
        raise BuildError(
            "The compiled program's health check did not pass:\n" + output.strip()
        )
    return output


# --------------------------------------------------------------------------
# Zip
# --------------------------------------------------------------------------


def write_zip(stage_dir: Path, destination: Path) -> Path:
    """Zip the staged files with no top-level folder.

    Windows' "Extract all" already creates a folder named after the zip; a
    second one inside it is one more place for a beneficiary to get lost.
    """
    scratch = destination.with_name(destination.name + ".partial")
    with zipfile.ZipFile(scratch, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(stage_dir.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(stage_dir).as_posix())
    scratch.replace(destination)
    return destination


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--root",
        type=Path,
        required=True,
        help="production folder holding internals/encrypted and internals/binaries",
    )
    parser.add_argument(
        "--output", type=Path, help="where to write the package (default: ROOT/release)"
    )
    parser.add_argument(
        "--name", default=DEFAULT_NAME, help=f"package name (default: {DEFAULT_NAME})"
    )
    parser.add_argument(
        "--no-compile",
        action="store_true",
        help="package the Python fallback only; beneficiaries will need Python",
    )
    parser.add_argument(
        "--reuse-build",
        action="store_true",
        help="use the program already compiled in build/ instead of recompiling",
    )
    args = parser.parse_args(argv)

    root = args.root.expanduser().resolve()
    if root == REPO:
        print("Refusing to package the repository itself: it holds the sample vault.")
        return 1
    output = (args.output or root / "release").expanduser().resolve()
    package = f"{args.name}-{datetime.now():%Y%m%d}-UNZIP-ME"
    stage_dir = output / package

    try:
        program = None
        if not args.no_compile:
            dist = REPO / "build" / "decrypt.dist"
            if args.reuse_build and (dist / "decrypt.exe").is_file():
                program = dist
            else:
                print("Compiling the standalone program (this takes a few minutes)...")
                program = compile_program(REPO / "build")

        print(f"Staging into {stage_dir}")
        output.mkdir(parents=True, exist_ok=True)
        stage(root, stage_dir, program)

        problems = find_secrets(stage_dir)
        if problems:
            shutil.rmtree(stage_dir, ignore_errors=True)
            raise BuildError(
                "Refusing to build a package containing secrets:\n  "
                + "\n  ".join(problems)
            )

        failures = health_check(stage_dir)
        if failures:
            raise BuildError("The staged copy is not healthy:\n  " + "\n  ".join(failures))
        print("Health check passed on the staged copy.")

        if program is not None:
            compiled_program_finds_vault(stage_dir)
            print("The compiled program found its vault and passed its own check.")

        archive = write_zip(stage_dir, output / f"{package}.zip")
    except BuildError as exc:
        print(f"\nNot built. {exc}")
        return 1

    print(f"\nPackage: {archive}  ({archive.stat().st_size / 1_048_576:.1f} MB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
