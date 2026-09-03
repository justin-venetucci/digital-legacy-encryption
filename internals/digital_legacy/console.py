"""Terminal presentation: colour, banners, honest progress, and prompts.

This module replaces the two hand-copied UI blocks that used to live inside
``encrypt.py`` and ``decrypt.py``.  Three things changed on the way in:

1. **Colour actually works on Windows.**  The old scripts emitted raw ANSI
   escapes, which ``cmd.exe`` -- the thing the shipped ``.bat`` wrapper opens --
   prints literally unless virtual-terminal processing has been turned on.
   :func:`enable_ansi` turns it on, and we fall back to plain text when it
   cannot be.

2. **Progress does not lie.**  The old ``show_processing_step`` took a
   ``success=True`` argument and slept; every call site passed ``True``, and the
   encrypt script printed "Encrypting ... Done" *before* running ``age``.
   :meth:`Console.task` is a context manager: it reports Done or Failed based on
   whether the wrapped block actually raised.

3. **It is testable.**  Everything writes to an injected stream and reads from
   an injected input function, so the wizards can be driven end to end by the
   test suite instead of being un-runnable outside a real terminal.
"""

from __future__ import annotations

import itertools
import os
import shutil
import sys
import threading
import time
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from typing import Callable

from .errors import OperationCancelled

# --------------------------------------------------------------------------
# Colour
# --------------------------------------------------------------------------

RESET = "\033[0m"

STYLES = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "blue": "\033[94m",
    "magenta": "\033[95m",
    "cyan": "\033[96m",
    "white": "\033[97m",
    "dark_yellow": "\033[33m",
    "dark_cyan": "\033[36m",
    "grey": "\033[90m",
}


def enable_ansi(stream=None) -> bool:
    """Best-effort enable of ANSI escapes; return whether they are usable.

    On Windows 10+ the console understands ANSI but does not process it until
    ENABLE_VIRTUAL_TERMINAL_PROCESSING is set on the handle.  Without this call
    the beneficiary sees escape codes interleaved with every line.
    """
    stream = stream if stream is not None else sys.stdout
    if os.name != "nt":
        return True
    try:  # pragma: no cover - platform specific
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        if handle in (0, -1):
            return False
        mode = wintypes.DWORD()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        enable_vt = 0x0004
        if mode.value & enable_vt:
            return True
        return bool(kernel32.SetConsoleMode(handle, mode.value | enable_vt))
    except Exception:
        return False


def _supports_colour(stream) -> bool:
    # no-color.org: any non-empty value disables colour.
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if not hasattr(stream, "isatty") or not stream.isatty():
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return enable_ansi(stream)


def _supports_unicode(stream) -> bool:
    """Whether box-drawing characters will survive the stream's encoding.

    A Windows console still on code page 437 raises UnicodeEncodeError on the
    box-drawing characters, which would crash the wizard on its first banner.
    """
    encoding = getattr(stream, "encoding", None) or "ascii"
    try:
        "╔═╗║╚╝•".encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


# --------------------------------------------------------------------------
# Console
# --------------------------------------------------------------------------

BOX_UNICODE = {
    "tl": "╔", "tr": "╗", "bl": "╚",
    "br": "╝", "h": "═", "v": "║",
}
BOX_ASCII = {"tl": "+", "tr": "+", "bl": "+", "br": "+", "h": "=", "v": "|"}

SPINNER_UNICODE = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
SPINNER_ASCII = "|/-" + chr(92)

BANNER_WIDTH = 78
"""Fits an 80-column terminal.

The old scripts hard-coded 100, which wraps and shreds the box on a default
Windows console (80 columns) or any half-screen terminal.
"""


class Console:
    """All terminal output and input for the wizards.

    Parameters mirror what tests need to disable: ``interactive`` turns prompts
    into errors rather than blocking on stdin, and ``animate=False`` removes
    every sleep so the suite runs in milliseconds.
    """

    def __init__(
        self,
        stream=None,
        *,
        colour: bool | None = None,
        unicode: bool | None = None,
        animate: bool | None = None,
        interactive: bool | None = None,
        input_func: Callable[[str], str] | None = None,
        width: int | None = None,
    ) -> None:
        self.stream = stream if stream is not None else sys.stdout
        self.colour = _supports_colour(self.stream) if colour is None else colour
        self.unicode = _supports_unicode(self.stream) if unicode is None else unicode
        self._input = input_func or input
        if interactive is None:
            interactive = input_func is not None or (
                hasattr(sys.stdin, "isatty") and sys.stdin.isatty()
            )
        self.interactive = bool(interactive)
        if animate is None:
            animate = self.colour and self.interactive
        self.animate = bool(animate)
        self.width = width or self._detect_width()
        self.box = BOX_UNICODE if self.unicode else BOX_ASCII
        self.bullet = "•" if self.unicode else "*"
        self._step = 0
        self._total_steps = 0

    def _detect_width(self) -> int:
        try:
            columns = shutil.get_terminal_size(fallback=(BANNER_WIDTH + 2, 24)).columns
        except Exception:  # pragma: no cover - defensive
            columns = BANNER_WIDTH + 2
        return max(40, min(BANNER_WIDTH, columns - 2))

    # -- primitives -------------------------------------------------------

    def style(self, text: str, *styles: str) -> str:
        if not self.colour or not styles:
            return text
        codes = "".join(STYLES.get(s, "") for s in styles)
        return f"{codes}{text}{RESET}" if codes else text

    def write(self, text: str = "", *styles: str, end: str = "\n") -> None:
        self.stream.write(self.style(text, *styles) + end)
        self.stream.flush()

    def blank(self, count: int = 1) -> None:
        for _ in range(count):
            self.write()

    def rule(self, *styles: str) -> None:
        self.write(self.box["h"] * self.width, *(styles or ("grey",)))

    def clear(self) -> None:
        """Clear the screen without shelling out.

        The old code ran ``os.system('cls')``, spawning a process that can fail
        noisily in front of the user on a machine with an unusual PATH.
        """
        if not self.animate:
            return
        self.stream.write("\033[2J\033[H" if self.colour else "\n" * 4)
        self.stream.flush()

    # -- structure --------------------------------------------------------

    def set_steps(self, total: int) -> None:
        self._total_steps = total
        self._step = 0

    def banner(self, title: str, *, step: bool = True, style: str = "cyan") -> None:
        """Draw a boxed heading, optionally numbered.

        Step numbering lives here rather than in the wizards, because the old
        scripts each tracked ``current_step`` by hand and the encrypt wizard
        drifted: it advertised five steps and finished on "[Step 6 of 5]".
        """
        if step and self._total_steps:
            self._step += 1
            text = f"[Step {self._step} of {self._total_steps}] {title}"
        else:
            text = title

        inner = self.width
        if len(text) > inner - 2:
            text = text[: inner - 5] + "..."
        pad = inner - len(text)
        left = pad // 2
        right = pad - left
        b = self.box

        self.blank()
        self.write(b["tl"] + b["h"] * inner + b["tr"], style)
        self.write(b["v"] + " " * left + text + " " * right + b["v"], style)
        self.write(b["bl"] + b["h"] * inner + b["br"], style)
        self.blank()

    def heading(self, text: str) -> None:
        self.blank()
        self.write(text, "bold", "white")
        self.write("-" * min(len(text), self.width), "grey")

    def info(self, text: str = "") -> None:
        self.write(text, "white")

    def note(self, text: str) -> None:
        self.write(text, "dark_cyan")

    def ok(self, text: str) -> None:
        self.write(text, "green")

    def warn(self, text: str) -> None:
        self.write(text, "yellow")

    def error(self, text: str) -> None:
        self.write(text, "red")

    def bullets(self, items: Iterable[str], style: str = "white") -> None:
        for item in items:
            self.write(f"  {self.bullet} {item}", style)

    def problem(self, exc: Exception) -> None:
        """Render an error the way a beneficiary should meet it."""
        self.blank()
        message = getattr(exc, "message", None) or str(exc)
        self.error(f"Problem: {message}")
        hint = getattr(exc, "hint", None)
        if hint:
            for line in hint.splitlines():
                self.write(f"         {line}", "dark_yellow")

    # -- progress ---------------------------------------------------------

    @contextmanager
    def task(self, message: str, *, min_duration: float = 0.35) -> Iterator[None]:
        """Run a block while showing a spinner; report its real outcome.

        ``min_duration`` keeps a very fast operation on screen long enough to
        read, which is what the original script's fixed sleeps were reaching for
        -- but here the delay pads the work rather than standing in for it.
        """
        stop = threading.Event()
        started = time.monotonic()
        thread: threading.Thread | None = None

        if self.animate:
            frames = SPINNER_UNICODE if self.unicode else SPINNER_ASCII

            def spin() -> None:
                for frame in itertools.cycle(frames):
                    if stop.is_set():
                        break
                    self.stream.write(f"\r  {frame} {message}...")
                    self.stream.flush()
                    time.sleep(0.08)

            thread = threading.Thread(target=spin, daemon=True)
            thread.start()

        outcome = "Done"
        try:
            yield
        except BaseException:
            outcome = "Failed"
            raise
        finally:
            elapsed = time.monotonic() - started
            if self.animate and outcome == "Done" and elapsed < min_duration:
                time.sleep(min_duration - elapsed)
            stop.set()
            if thread is not None:
                thread.join(timeout=1.0)
                self.stream.write("\r" + " " * (len(message) + 24) + "\r")
            tick = ("✓" if self.unicode else "+") if outcome == "Done" else "x"
            self.write(
                f"  {tick} {message}... {outcome}",
                "green" if outcome == "Done" else "red",
            )

    def pause(self, prompt: str = "Press Enter to continue...") -> None:
        if not self.interactive:
            return
        self.blank()
        self._read(self.style(prompt, "magenta"))

    # -- input ------------------------------------------------------------

    def _read(self, prompt: str) -> str:
        if not self.interactive:
            raise OperationCancelled(
                "This step needs an answer, but the tool is not running "
                "interactively."
            )
        try:
            return self._input(prompt)
        except (EOFError, KeyboardInterrupt):
            raise OperationCancelled() from None

    def ask(self, prompt: str, *, default: str | None = None) -> str:
        suffix = f" [{default}]" if default else ""
        while True:
            answer = self._read(self.style(f"{prompt}{suffix}: ", "magenta")).strip()
            if answer:
                return answer
            if default is not None:
                return default
            self.error("Please type an answer.")

    def ask_yes_no(self, prompt: str, *, default: bool | None = None) -> bool:
        hint = {True: " (Y/n)", False: " (y/N)", None: " (y/n)"}[default]
        while True:
            raw = self._read(self.style(f"{prompt}{hint}: ", "magenta"))
            answer = raw.strip().lower()
            if not answer and default is not None:
                return default
            if answer in ("y", "yes"):
                return True
            if answer in ("n", "no"):
                return False
            self.error("Please answer yes or no.")

    def ask_int(
        self, prompt: str, *, minimum: int, maximum: int, default: int | None = None
    ) -> int:
        while True:
            raw = self.ask(
                prompt, default=str(default) if default is not None else None
            )
            try:
                value = int(raw.strip())
            except ValueError:
                self.error("Please enter a whole number.")
                continue
            if minimum <= value <= maximum:
                return value
            self.error(f"Please enter a number between {minimum} and {maximum}.")

    def ask_choice(
        self,
        prompt: str,
        options: Sequence[tuple[str, str]],
        *,
        default: str | None = None,
    ) -> str:
        """Present ``(key, description)`` options and return the chosen key."""
        self.blank()
        for key, description in options:
            self.write(f"  {key}) {description}", "white")
        valid = {key.lower() for key, _ in options}
        while True:
            answer = self.ask(prompt, default=default).strip().lower()
            if answer in valid:
                return answer
            self.error(f"Please choose one of: {', '.join(k for k, _ in options)}.")


def plain_console() -> Console:
    """A Console suitable for scripted, non-interactive use."""
    return Console(colour=False, unicode=False, animate=False, interactive=False)
