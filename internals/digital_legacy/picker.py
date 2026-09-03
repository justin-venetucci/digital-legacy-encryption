"""Choosing a file, with a graceful path back to typing one.

The old scripts imported ``tkinter`` at module scope, so a Python built without
Tk -- common on Linux, where it is a separate ``python3-tk`` package, and on
minimal macOS installs -- crashed on import with ``ModuleNotFoundError`` before
printing a single word of explanation.  For a beneficiary that is a dead end.

Here Tk is imported lazily inside a try, and when it is unavailable or fails to
open a display the tool asks for a typed path instead.  Paths pasted from a file
manager arrive wrapped in quotes and, on Windows, sometimes with a ``&`` prefix
from PowerShell's copy-as-path; both are stripped.

The old decrypt script also opened its dialog in ``internals/keys`` -- a folder
that has never existed in this repository -- so every beneficiary began at an
empty location.  Start directories here are checked before being used.
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from .console import Console
from .errors import OperationCancelled

FileTypes = Sequence[tuple[str, str]]

KEY_FILE_TYPES: FileTypes = (("Key files", "*.yaml"), ("All files", "*.*"))
ANY_FILE_TYPES: FileTypes = (("All files", "*.*"),)


def tk_available() -> bool:
    try:  # pragma: no cover - depends on the interpreter build
        import tkinter  # noqa: F401
    except Exception:
        return False
    return True


def _first_existing(*candidates: Path | None) -> Path | None:
    for candidate in candidates:
        if candidate and Path(candidate).is_dir():
            return Path(candidate)
    return None


def clean_typed_path(raw: str) -> str:
    """Undo what file managers and shells add when a path is copied.

    Explorer's "Copy as path" wraps in double quotes; the macOS Finder and most
    Linux terminals produce a drag-and-dropped path with escaped spaces or
    single quotes; PowerShell 7 prefixes ``&``.
    """
    text = raw.strip()
    if text.startswith("&"):
        text = text[1:].strip()
    for quote in ('"', "'"):
        if len(text) >= 2 and text.startswith(quote) and text.endswith(quote):
            text = text[1:-1]
            break
    return text.replace("\\ ", " ").strip()


def choose_file(
    console: Console,
    *,
    title: str,
    file_types: FileTypes = ANY_FILE_TYPES,
    start_dir: Path | None = None,
    prompt: str = "Press Enter to open the file chooser",
) -> Path:
    """Return a path the user selected, by dialog or by typing.

    Raises :class:`OperationCancelled` when they decline, which callers treat as
    "back out of this step" rather than as a failure.
    """
    initial = _first_existing(start_dir, Path.home() / "Desktop", Path.home())

    if tk_available():
        console.info(prompt + ", or type a file path here.")
        typed = console.ask("Path (or Enter for the chooser)", default="")
        if typed.strip():
            return _validate(clean_typed_path(typed))
        selected = _tk_dialog(title, file_types, initial)
        if selected is None:
            console.warn(
                "The file chooser could not be opened on this computer."
            )
            return _ask_for_path(console, title, initial)
        if not selected:
            raise OperationCancelled("No file was selected.")
        return _validate(selected)

    return _ask_for_path(console, title, initial)


def _tk_dialog(
    title: str, file_types: FileTypes, initial: Path | None
) -> str | None:
    """Open a native chooser.  ``None`` means Tk failed; ``""`` means cancelled."""
    try:  # pragma: no cover - requires a display
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        try:
            root.withdraw()
            root.attributes("-topmost", True)
            # Without this the dialog can open behind the terminal on Windows,
            # leaving the beneficiary staring at a window that appears frozen.
            root.update()
            return filedialog.askopenfilename(
                title=title,
                filetypes=list(file_types),
                initialdir=str(initial) if initial else None,
                parent=root,
            )
        finally:
            root.destroy()
    except Exception:
        return None


def _ask_for_path(console: Console, title: str, initial: Path | None) -> Path:
    console.blank()
    console.info(title)
    if initial:
        console.note(f"Tip: your files are probably in {initial}")
    console.note(
        "Type or paste the full path to the file, then press Enter. "
        "You can also drag the file into this window."
    )
    while True:
        raw = console.ask("File path")
        try:
            return _validate(clean_typed_path(raw))
        except OperationCancelled:
            raise
        except FileNotFoundError:
            console.error("There is no file at that path. Please try again.")
        except IsADirectoryError:
            console.error("That is a folder, not a file. Please try again.")


def _validate(candidate: str) -> Path:
    if not candidate:
        raise OperationCancelled("No file was selected.")
    path = Path(candidate).expanduser()
    if path.is_dir():
        raise IsADirectoryError(str(path))
    if not path.is_file():
        raise FileNotFoundError(str(path))
    return path
