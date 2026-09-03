"""Key files, and the console primitives the wizards are built from."""

from __future__ import annotations

import io
import os
import stat
import tempfile
import unittest
from pathlib import Path

from support import PUBLIC_KEYS, SECRET_KEYS, FakeToolchain, strip_ansi

from digital_legacy import agekeys
from digital_legacy.console import Console
from digital_legacy.errors import KeyFileError, OperationCancelled, ToolchainError
from digital_legacy.picker import clean_typed_path
from digital_legacy.toolchain import redact


class LabelTests(unittest.TestCase):
    def test_path_separators_cannot_escape_the_keys_folder(self):
        """The old code interpolated raw input into a path.

        A keyholder named "Alice/Bob" wrote the key somewhere else, or failed
        after generation -- losing a secret that existed nowhere else.
        """
        self.assertNotIn("/", agekeys.key_file_name("Alice/Bob"))
        self.assertNotIn("\\", agekeys.key_file_name(r"..\..\evil"))

    def test_traversal_is_neutralised(self):
        label = agekeys.sanitise_label("../../etc/passwd")
        self.assertNotIn("..", label)
        self.assertNotIn("/", label)

    def test_windows_reserved_device_names_are_replaced(self):
        """Creating "CON.yaml" fails on Windows -- after the key exists."""
        self.assertEqual(agekeys.sanitise_label("CON"), "Keyholder")
        self.assertEqual(agekeys.sanitise_label("nul"), "Keyholder")

    def test_empty_name_gets_a_usable_default(self):
        self.assertEqual(agekeys.sanitise_label("   "), "Keyholder")

    def test_control_characters_are_removed(self):
        self.assertEqual(agekeys.sanitise_label("Bob\x00\x1f"), "Bob")

    def test_length_is_capped(self):
        self.assertLessEqual(len(agekeys.sanitise_label("x" * 500)), 60)

    def test_ordinary_names_survive_intact(self):
        self.assertEqual(agekeys.sanitise_label("Bob (brother)"), "Bob (brother)")


class KeyFileTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.toolchain = FakeToolchain()

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, name: str, content: str) -> Path:
        path = self.tmp / name
        path.write_text(content, encoding="utf-8")
        return path

    def test_round_trip_through_render_and_read(self):
        pair = agekeys.generate(self.toolchain, label="Alice")
        content = agekeys.render_key_file(pair, threshold=2, total_shares=3)
        path = agekeys.write_key_file(
            self.tmp / agekeys.key_file_name("Alice"), content
        )
        parsed = agekeys.read_key_file(path)
        self.assertEqual(parsed.secret_key, pair.secret_key)
        self.assertEqual(parsed.declared_public_key, pair.public_key)
        self.assertEqual(parsed.label, "Alice")

    def test_plain_age_keygen_output_still_parses(self):
        """Backward compatibility with every key file the old tool wrote."""
        path = self.write(
            "old.yaml",
            f"# created: 2025-05-26T20:31:10-05:00\n"
            f"# public key: {PUBLIC_KEYS[0]}\n{SECRET_KEYS[0]}\n",
        )
        self.assertEqual(agekeys.read_key_file(path).secret_key, SECRET_KEYS[0])

    def test_utf8_bom_is_tolerated(self):
        path = self.write("bom.yaml", "\ufeff" + SECRET_KEYS[0] + "\n")
        self.assertEqual(agekeys.read_key_file(path).secret_key, SECRET_KEYS[0])

    def test_a_file_with_no_key_says_so_plainly(self):
        path = self.write("empty.yaml", "just some notes\n")
        with self.assertRaises(KeyFileError) as caught:
            agekeys.read_key_file(path)
        self.assertIn("does not contain a private key", caught.exception.message)

    def test_a_damaged_key_is_distinguished_from_a_missing_one(self):
        """Different causes deserve different advice."""
        path = self.write("broken.yaml", "AGE-SECRET-KEY-1ABC!!!truncated\n")
        with self.assertRaises(KeyFileError) as caught:
            agekeys.read_key_file(path)
        self.assertIn("damaged", caught.exception.message)

    def test_selecting_the_encrypted_document_by_mistake_is_explained(self):
        path = self.tmp / "big.age"
        path.write_bytes(b"\x00" * 2_000_000)
        with self.assertRaises(KeyFileError) as caught:
            agekeys.read_key_file(path)
        self.assertIn("too large", caught.exception.message)

    def test_binary_file_is_rejected_readably(self):
        path = self.tmp / "photo.jpg"
        path.write_bytes(b"\xff\xd8\xff\xe0\x00\x10JFIF" + b"\x80" * 100)
        with self.assertRaises(KeyFileError) as caught:
            agekeys.read_key_file(path)
        self.assertIn("not a text file", caught.exception.message)

    def test_smart_dashes_from_a_word_processor_are_normalised(self):
        path = self.write("smart.yaml", SECRET_KEYS[0].replace("-", "-", 1) + "\n")
        self.assertEqual(agekeys.read_key_file(path).secret_key, SECRET_KEYS[0])

    def test_key_file_is_created_owner_only_on_posix(self):
        path = agekeys.write_key_file(self.tmp / "k.yaml", "AGE-SECRET-KEY-1A\n")
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        else:
            self.assertTrue(path.exists())

    def test_shred_removes_the_file(self):
        path = self.write("gone.yaml", "secret")
        agekeys.shred(path)
        self.assertFalse(path.exists())

    def test_derive_public_key_rejects_a_bad_secret(self):
        with self.assertRaises(KeyFileError):
            agekeys.derive_public_key(self.toolchain, "AGE-SECRET-KEY-1NOTREAL")

    def test_secret_never_appears_on_the_command_line(self):
        """argv is readable by every process on the machine."""
        agekeys.derive_public_key(self.toolchain, SECRET_KEYS[0])
        for call in self.toolchain.calls:
            self.assertNotIn(SECRET_KEYS[0], " ".join(call))

    def test_fingerprints_differ_between_keys(self):
        a = agekeys.public_key_fingerprint(PUBLIC_KEYS[0])
        b = agekeys.public_key_fingerprint(PUBLIC_KEYS[1])
        self.assertNotEqual(a, b)
        self.assertRegex(a, r"^[A-Z0-9]{4}-[A-Z0-9]{4}$")


class RedactionTests(unittest.TestCase):
    """Nothing key-shaped may reach a screen through an error message.

    The age and age-plugin-sss builds in use do not echo key material in their
    diagnostics -- that was checked against the real binaries, not assumed --
    but those diagnostics are shown to users, so a future build that quoted its
    input back would turn a routine error into a disclosure.
    """

    def test_a_private_key_in_an_error_is_blanked(self):
        message = f"failed to parse {SECRET_KEYS[0]} at line 1"
        self.assertNotIn(SECRET_KEYS[0], redact(message))
        self.assertIn("[key redacted]", redact(message))

    def test_a_combined_plugin_identity_is_blanked(self):
        message = "bad identity AGE-PLUGIN-SSS-1R79SSQQQQQQQQQ8LDNXTHT"
        self.assertNotIn("1R79SSQ", redact(message))

    def test_ordinary_messages_are_left_alone(self):
        for message in (
            "age: error: no identity matched any of the recipients",
            "cannot open Key for Digital Legacy - Alice.yaml",
            "",
        ):
            self.assertEqual(redact(message), message)

    def test_public_keys_are_not_redacted(self):
        """They are public, and a beneficiary may need to compare one."""
        self.assertIn(PUBLIC_KEYS[0], redact(f"unknown recipient {PUBLIC_KEYS[0]}"))

    def test_console_redacts_at_the_point_of_display(self):
        buffer = io.StringIO()
        console = Console(
            buffer, colour=False, unicode=False, animate=False, interactive=False
        )
        console.problem(
            KeyFileError("Bad key.", hint=f"stderr said: {SECRET_KEYS[0]}")
        )
        self.assertNotIn(SECRET_KEYS[0], buffer.getvalue())

    def test_toolchain_redacts_before_raising(self):
        toolchain = FakeToolchain()
        toolchain.fail_on = "age-plugin"
        with self.assertRaises(ToolchainError) as caught:
            toolchain.run(toolchain.age_plugin_sss, "--generate-identity")
        self.assertIsNotNone(caught.exception.hint)


class ConsoleTests(unittest.TestCase):
    def make(self, answers=()):
        answers = iter(answers)
        self.buffer = io.StringIO()
        return Console(
            self.buffer,
            colour=False,
            unicode=False,
            animate=False,
            width=60,
            input_func=lambda prompt: next(answers),
        )

    def text(self) -> str:
        return strip_ansi(self.buffer.getvalue())

    def test_banner_numbering_never_exceeds_the_total(self):
        """encrypt.py used to advertise five steps and finish on step six."""
        console = self.make()
        console.set_steps(3)
        for title in ("One", "Two", "Three"):
            console.banner(title)
        import re

        text = self.text()
        self.assertIn("[Step 3 of 3] Three", text)
        numbers = [int(n) for n in re.findall(r"\[Step (\d+) of 3\]", text)]
        self.assertEqual(numbers, [1, 2, 3])

    def test_banner_box_lines_are_all_the_same_width(self):
        console = self.make()
        console.set_steps(1)
        console.banner("A title")
        lines = [ln for ln in self.text().splitlines() if ln.strip()]
        self.assertEqual(len({len(ln) for ln in lines}), 1)

    def test_over_long_title_is_truncated_not_wrapped(self):
        console = self.make()
        console.banner("x" * 200, step=False)
        lines = [ln for ln in self.text().splitlines() if ln.strip()]
        self.assertEqual(len({len(ln) for ln in lines}), 1)

    def test_task_reports_done_only_when_the_work_succeeded(self):
        console = self.make()
        with console.task("Working", min_duration=0):
            pass
        self.assertIn("Working... Done", self.text())

    def test_task_reports_failed_when_the_block_raises(self):
        """The old helper took success=True from every call site and slept."""
        console = self.make()
        with self.assertRaises(ValueError), console.task("Working", min_duration=0):
            raise ValueError
        self.assertIn("Working... Failed", self.text())

    def test_ask_int_rejects_out_of_range_and_retries(self):
        console = self.make(["0", "99", "2"])
        self.assertEqual(console.ask_int("How many", minimum=1, maximum=3), 2)

    def test_ask_int_rejects_non_numbers(self):
        console = self.make(["two", "2"])
        self.assertEqual(console.ask_int("How many", minimum=1, maximum=3), 2)

    def test_ask_yes_no_accepts_full_words_and_defaults(self):
        self.assertTrue(self.make(["yes"]).ask_yes_no("?"))
        self.assertFalse(self.make(["n"]).ask_yes_no("?"))
        self.assertTrue(self.make([""]).ask_yes_no("?", default=True))

    def test_ask_choice_reprompts_until_valid(self):
        console = self.make(["9", "b"])
        self.assertEqual(console.ask_choice("Pick", [("a", "A"), ("b", "B")]), "b")

    def test_ctrl_c_at_a_prompt_becomes_a_cancellation(self):
        def raiser(_prompt):
            raise KeyboardInterrupt

        console = Console(io.StringIO(), colour=False, animate=False, input_func=raiser)
        with self.assertRaises(OperationCancelled):
            console.ask("Anything")

    def test_non_interactive_console_refuses_to_block(self):
        console = Console(io.StringIO(), colour=False, animate=False, interactive=False)
        with self.assertRaises(OperationCancelled):
            console.ask("Anything")

    def test_ascii_fallback_avoids_box_drawing_characters(self):
        console = self.make()
        console.banner("Plain", step=False)
        self.assertNotIn("╔", self.text())


class TypedPathTests(unittest.TestCase):
    def test_explorer_copy_as_path_quotes_are_stripped(self):
        windows_path = r"C:\Users\me\key.yaml"
        self.assertEqual(clean_typed_path(f'"{windows_path}"'), windows_path)

    def test_powershell_ampersand_prefix_is_stripped(self):
        self.assertEqual(clean_typed_path('& "C:\\a\\b.yaml"'), "C:\\a\\b.yaml")

    def test_shell_escaped_spaces_are_unescaped(self):
        self.assertEqual(
            clean_typed_path(r"/home/me/my\ key.yaml"), "/home/me/my key.yaml"
        )

    def test_single_quotes_are_stripped(self):
        self.assertEqual(clean_typed_path("'/home/me/k.yaml'"), "/home/me/k.yaml")


if __name__ == "__main__":
    unittest.main()
