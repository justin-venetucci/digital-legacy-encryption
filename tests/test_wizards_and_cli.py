"""The guided flows and the command line, driven end to end.

Neither of these could be tested before: both scripts blocked on ``input()`` and
opened Tk dialogs, so the only way to exercise them was for a person to sit at a
terminal and click.  That is why an off-by-one in the step counter and a
filename parser that produced unopenable files both shipped.

Here the console reads from a scripted list of answers and the file chooser is
told to accept typed paths, so the real wizard code runs unattended.
"""

from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from support import (
    guard_not_the_real_repo,
    make_layout,
    real_toolchain,
    requires_binaries,
    strip_ansi,
)

from digital_legacy import agekeys
from digital_legacy.cli import main as cli_main
from digital_legacy.console import Console
from digital_legacy.vault import Vault
from digital_legacy.wizards import DecryptWizard, EncryptWizard


class ScriptedConsole(Console):
    """A Console that answers from a list, and records what it was asked."""

    def __init__(self, answers):
        self.buffer = io.StringIO()
        self.answers = list(answers)
        self.prompts: list[str] = []
        super().__init__(
            self.buffer,
            colour=False,
            unicode=False,
            animate=False,
            width=70,
            input_func=self._answer,
        )

    def _answer(self, prompt: str) -> str:
        self.prompts.append(strip_ansi(prompt))
        if not self.answers:
            raise EOFError("the wizard asked more questions than the test scripted")
        return self.answers.pop(0)

    @property
    def text(self) -> str:
        return strip_ansi(self.buffer.getvalue())


@requires_binaries
class EncryptWizardTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.layout = make_layout(self.root)
        guard_not_the_real_repo(self.layout)
        self.source = self.root / "Passwords.v2.txt"
        self.source.write_bytes(b"secret material\n" * 100)

    def tearDown(self):
        self._tmp.cleanup()

    def run_wizard(self, answers):
        console = ScriptedConsole(answers)
        code = EncryptWizard(self.layout, console).run()
        return code, console

    def test_full_wizard_produces_a_verified_vault_and_letters(self):
        code, console = self.run_wizard(
            [
                "",                       # press Enter to begin
                str(self.source),         # typed path instead of the chooser
                "Justin",                 # owner name
                "3",                      # how many keys
                "2",                      # threshold
                "Alice", "Bob", "Carol",  # keyholder names
                "",                       # press Enter to close
            ]
        )
        self.assertEqual(code, 0, console.text)
        self.assertIn("proven to open again", console.text)

        vault = Vault(self.layout.encrypted_dir)
        entry = vault.sole_entry()
        self.assertEqual(entry.original_suffix, ".txt")
        self.assertTrue(entry.verified_at)

        keys = sorted(p.name for p in self.layout.keys_out_dir.glob("*.yaml"))
        self.assertEqual(len(keys), 3)
        self.assertIn("Key for Digital Legacy - Alice.yaml", keys)

        letters = sorted(p.name for p in self.layout.handoff_dir.glob("*.txt"))
        self.assertIn("Letter for Bob.txt", letters)
        self.assertIn("WHAT TO DO NEXT.txt", letters)
        self.assertTrue((self.layout.encrypted_dir / "READ ME FIRST.txt").exists())

    def test_step_numbers_never_exceed_the_advertised_total(self):
        """encrypt.py used to finish on "[Step 6 of 5]"."""
        import re

        _, console = self.run_wizard(
            ["", str(self.source), "Justin", "2", "2", "A", "B", "", ""]
        )
        pairs = re.findall(r"\[Step (\d+) of (\d+)\]", console.text)
        self.assertTrue(pairs)
        for current, total in pairs:
            self.assertLessEqual(int(current), int(total))

    def test_a_fragile_arrangement_is_flagged_and_can_be_declined(self):
        code, console = self.run_wizard(
            [
                "", str(self.source), "Justin",
                "2", "2",          # 2 of 2: losing either key loses everything
                "A", "B",
                "n",               # decline the arrangement
                "",
            ]
        )
        self.assertEqual(code, 1)
        self.assertIn("permanently unrecoverable", console.text)
        self.assertFalse(list(self.layout.encrypted_dir.glob("*.age")))

    def test_keyholder_name_with_a_slash_cannot_escape_the_folder(self):
        self.run_wizard(
            ["", str(self.source), "Justin", "1", "1", "Alice/Bob", "y", ""]
        )
        names = [p.name for p in self.layout.keys_out_dir.glob("*.yaml")]
        self.assertEqual(names, ["Key for Digital Legacy - Alice-Bob.yaml"])


@requires_binaries
class DecryptWizardTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.layout = make_layout(self.root)
        guard_not_the_real_repo(self.layout)
        self.source = self.root / "Will.pdf"
        self.source.write_bytes(b"%PDF-1.6 pretend document\n" * 50)
        with contextlib.redirect_stdout(io.StringIO()):
            code = cli_main(
                [
                    "encrypt", "--no-colour", "--quiet",
                    "--file", str(self.source),
                    "--shares", "3", "--threshold", "2",
                    "--name", "Alice", "--name", "Bob", "--name", "Carol",
                    "--owner", "Justin",
                ],
                layout=self.layout,
            )
        assert code == 0
        self.keys = {
            p.stem.split(" - ")[-1]: p
            for p in self.layout.keys_out_dir.glob("*.yaml")
        }

    def tearDown(self):
        self._tmp.cleanup()

    def run_wizard(self, answers, output=None):
        console = ScriptedConsole(answers)
        wizard = DecryptWizard(
            self.layout, console, output_dir=output or (self.root / "desktop")
        )
        return wizard.run(), console

    def test_beneficiary_flow_recovers_the_document(self):
        code, console = self.run_wizard(
            [
                "",                            # begin
                str(self.keys["Alice"]),       # key 1
                str(self.keys["Carol"]),       # key 2
                "n",                           # do not open the file
                "",                            # close
            ]
        )
        self.assertEqual(code, 0, console.text)
        written = list((self.root / "desktop").glob("*"))
        self.assertEqual(len(written), 1)
        self.assertEqual(written[0].read_bytes(), self.source.read_bytes())
        self.assertTrue(written[0].name.startswith("[SENSITIVE]"))
        self.assertEqual(written[0].suffix, ".pdf")

    def test_the_same_key_twice_is_rejected_and_recoverable(self):
        code, console = self.run_wizard(
            [
                "",
                str(self.keys["Alice"]),
                str(self.keys["Alice"]),   # duplicate
                "y",                       # try a different file
                str(self.keys["Bob"]),
                "n",
                "",
            ]
        )
        self.assertEqual(code, 0, console.text)
        self.assertIn("already accepted", console.text)

    def test_step_numbers_survive_repeated_mistakes(self):
        """A retry must redraw its step, not consume a new one.

        The first fix for "[Step 6 of 5]" only covered the encrypt wizard. The
        decrypt wizard reintroduced it by the back door: every rejected file
        drew a fresh banner, so a beneficiary who fumbled twice finished on
        "[Step 7 of 5]" -- and fumbling is the expected case here.
        """
        import re

        junk = self.root / "junk.txt"
        junk.write_text("not a key")
        code, console = self.run_wizard(
            [
                "",
                "no-such-file.yaml",         # a path that does not exist
                str(junk),                   # a file with no key in it
                "y",                         # try again
                str(self.keys["Alice"]),
                str(self.keys["Alice"]),     # a duplicate
                "y",
                str(self.keys["Bob"]),
                "n", "",
            ]
        )
        self.assertEqual(code, 0, console.text)
        pairs = re.findall(r"\[Step (\d+) of (\d+)\]", console.text)
        self.assertTrue(pairs)
        for current, total in pairs:
            self.assertLessEqual(
                int(current), int(total), f"step {current} exceeds {total}"
            )

    def test_a_typed_path_that_does_not_exist_does_not_crash(self):
        """This escaped as a raw FileNotFoundError traceback."""
        code, console = self.run_wizard(
            [
                "", "definitely-not-here.yaml",
                str(self.keys["Alice"]), str(self.keys["Bob"]),
                "n", "",
            ]
        )
        self.assertEqual(code, 0, console.text)
        self.assertIn("no file at that path", console.text.lower())
        self.assertNotIn("Traceback", console.text)

    def test_a_key_from_another_vault_is_named_as_such(self):
        stranger = agekeys.generate(real_toolchain(), label="Stranger")
        path = agekeys.write_key_file(
            self.root / "stranger.yaml",
            agekeys.render_key_file(stranger, threshold=1, total_shares=1),
        )
        code, console = self.run_wizard(
            [
                "", str(path),
                "y",                       # try another
                str(self.keys["Alice"]),
                str(self.keys["Bob"]),
                "n", "",
            ]
        )
        self.assertEqual(code, 0, console.text)
        self.assertIn("does not belong to this document", console.text)

    def test_a_garbage_file_is_rejected_without_crashing(self):
        junk = self.root / "holiday.jpg"
        junk.write_bytes(b"\xff\xd8\xff" + b"\x91" * 500)
        code, console = self.run_wizard(
            [
                "", str(junk),
                "y",
                str(self.keys["Alice"]),
                str(self.keys["Bob"]),
                "n", "",
            ]
        )
        self.assertEqual(code, 0, console.text)
        self.assertIn("not a text file", console.text)

    def test_giving_up_exits_cleanly_rather_than_looping(self):
        junk = self.root / "junk.txt"
        junk.write_text("nothing useful")
        code, console = self.run_wizard(["", str(junk), "n", ""])
        self.assertEqual(code, 1)
        self.assertNotIn("Traceback", console.text)

    def test_two_documents_prompt_a_choice_instead_of_failing(self):
        """Running the old encryptor twice bricked the vault outright."""
        second = self.root / "Letter.txt"
        second.write_text("second document")
        with contextlib.redirect_stdout(io.StringIO()):
            cli_main(
                [
                    "encrypt", "--no-colour", "--quiet", "--file", str(second),
                    "--use-existing-keys", "--allow-unverified",
                ],
                layout=self.layout,
            )
        entries = Vault(self.layout.encrypted_dir).entries()
        self.assertEqual(len(entries), 2)

        code, console = self.run_wizard(
            [
                "1",                       # choose the first document
                "",                        # begin
                str(self.keys["Alice"]),
                str(self.keys["Bob"]),
                "n", "",
            ]
        )
        self.assertEqual(code, 0, console.text)
        self.assertIn("more than one encrypted document", console.text.lower())


@requires_binaries
class CommandLineTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.layout = make_layout(self.root)
        guard_not_the_real_repo(self.layout)
        self.source = self.root / "doc.txt"
        self.source.write_text("hello legacy", encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    def cli(self, argv):
        """Every CLI call is pinned to this test's temporary project folder.

        An earlier version of this file relied on cli_main discovering the
        layout for itself, which meant the suite encrypted into the real
        repository and overwrote the committed sample vault. Passing the layout
        explicitly makes that impossible rather than merely unlikely.
        """
        self.output = io.StringIO()
        with contextlib.redirect_stdout(self.output):
            return cli_main(argv, layout=self.layout)

    def test_encrypt_then_decrypt_via_flags(self):
        self.assertEqual(
            self.cli(
                ["encrypt", "--no-colour", "--quiet", "--file", str(self.source),
                 "--shares", "3", "--threshold", "2"]
            ),
            0,
        )
        keys = sorted(self.layout.keys_out_dir.glob("*.yaml"))
        out = self.root / "out"
        self.assertEqual(
            self.cli(
                ["decrypt", "--no-colour", "--quiet",
                 "--key", str(keys[0]), "--key", str(keys[1]),
                 "--output", str(out)]
            ),
            0,
        )
        written = list(out.glob("*"))
        self.assertEqual(written[0].read_text(encoding="utf-8"), "hello legacy")

    def test_too_few_keys_is_refused_with_a_readable_message(self):
        self.cli(["encrypt", "--no-colour", "--quiet", "--file", str(self.source),
                  "--shares", "3", "--threshold", "2"])
        keys = sorted(self.layout.keys_out_dir.glob("*.yaml"))
        self.assertEqual(
            self.cli(["decrypt", "--no-colour", "--quiet", "--key", str(keys[0]),
                      "--output", str(self.root / "out")]),
            1,
        )

    def test_share_and_name_count_must_agree(self):
        code = self.cli(
            ["encrypt", "--no-colour", "--quiet", "--file", str(self.source),
             "--shares", "3", "--name", "OnlyOne"]
        )
        self.assertEqual(code, 1)

    def test_doctor_passes_on_a_freshly_written_vault(self):
        self.cli(["encrypt", "--no-colour", "--quiet", "--file", str(self.source),
                  "--shares", "3", "--threshold", "2"])
        self.assertEqual(self.cli(["doctor", "--no-colour"]), 0)

    def test_doctor_fails_when_the_ciphertext_has_been_damaged(self):
        self.cli(["encrypt", "--no-colour", "--quiet", "--file", str(self.source),
                  "--shares", "3", "--threshold", "2"])
        target = next(self.layout.encrypted_dir.glob("*.age"))
        target.write_bytes(target.read_bytes() + b"tampered")
        self.assertEqual(self.cli(["doctor", "--no-colour"]), 1)

    def test_check_key_distinguishes_belonging_from_valid(self):
        self.cli(["encrypt", "--no-colour", "--quiet", "--file", str(self.source),
                  "--shares", "2", "--threshold", "2"])
        mine = sorted(self.layout.keys_out_dir.glob("*.yaml"))[0]
        self.assertEqual(self.cli(["check-key", "--no-colour", str(mine)]), 0)

        stranger = agekeys.generate(real_toolchain(), label="Stranger")
        other = agekeys.write_key_file(
            self.root / "other.yaml",
            agekeys.render_key_file(stranger, threshold=1, total_shares=1),
        )
        self.assertEqual(self.cli(["check-key", "--no-colour", str(other)]), 1)

    def test_handoff_can_be_regenerated_from_the_vault_alone(self):
        self.cli(["encrypt", "--no-colour", "--quiet", "--file", str(self.source),
                  "--shares", "2", "--threshold", "2", "--name", "Alice",
                  "--name", "Bob", "--owner", "Justin"])
        destination = self.root / "reprinted"
        self.assertEqual(
            self.cli(["handoff", "--no-colour", "--output", str(destination)]), 0
        )
        names = sorted(p.name for p in destination.glob("*.txt"))
        self.assertIn("Letter for Alice.txt", names)

    def test_global_flag_works_before_and_after_the_subcommand(self):
        self.cli(["encrypt", "--no-colour", "--quiet", "--file", str(self.source),
                  "--shares", "2", "--threshold", "2"])
        self.assertEqual(self.cli(["--no-colour", "doctor"]), 0)
        self.assertEqual(self.cli(["doctor", "--no-colour"]), 0)

    def test_inspect_reports_what_the_file_itself_requires(self):
        self.cli(["encrypt", "--no-colour", "--quiet", "--file", str(self.source),
                  "--shares", "3", "--threshold", "2"])
        self.assertEqual(self.cli(["inspect", "--no-colour"]), 0)


if __name__ == "__main__":
    unittest.main()


@requires_binaries
class ResealTests(unittest.TestCase):
    """Replacing the keyholders on a document that already exists.

    Shamir cannot add or remove a share after the fact, so the only way to
    change who can open a document is to decrypt and encrypt again. Over the
    decades this tool is meant to cover, that will be needed.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.layout = make_layout(self.root)
        guard_not_the_real_repo(self.layout)
        self.source = self.root / "Will.txt"
        self.source.write_text("the estate passes to", encoding="utf-8")
        self.cli(
            ["encrypt", "--no-colour", "--quiet", "--file", str(self.source),
             "--shares", "3", "--threshold", "2",
             "--name", "Alice", "--name", "Bob", "--name", "Carol"]
        )
        self.keys = self.current_keys()
        self.carol_old = self.root / "carol-old.yaml"
        self.carol_old.write_bytes(self.keys["Carol"].read_bytes())

    def tearDown(self):
        self._tmp.cleanup()

    def cli(self, argv):
        self.output = io.StringIO()
        with contextlib.redirect_stdout(self.output):
            return cli_main(argv, layout=self.layout)

    def current_keys(self):
        return {
            p.stem.split(" - ")[-1]: p
            for p in self.layout.keys_out_dir.glob("*.yaml")
        }

    def reseal(self, *extra):
        return self.cli(
            ["reseal", "--no-colour", "--quiet",
             "--key", str(self.keys["Alice"]), "--key", str(self.keys["Bob"]),
             "--shares", "3", "--threshold", "2",
             "--name", "Alice", "--name", "Bob", "--name", "Dad", *extra]
        )

    def test_reseal_replaces_the_keyholders(self):
        self.assertEqual(self.reseal(), 0, self.output.getvalue())
        new_keys = self.current_keys()
        self.assertIn("Dad", new_keys)

        out = self.root / "out"
        self.assertEqual(
            self.cli(["decrypt", "--no-colour", "--quiet",
                      "--key", str(new_keys["Dad"]), "--key", str(new_keys["Bob"]),
                      "--output", str(out)]),
            0,
            self.output.getvalue(),
        )
        written = list(out.glob("*"))
        self.assertEqual(written[0].read_text(encoding="utf-8"), "the estate passes to")

    def test_the_removed_keyholder_can_no_longer_open_it(self):
        """The whole point. If this fails the reseal achieved nothing."""
        self.reseal()
        self.assertEqual(
            self.cli(["check-key", "--no-colour", str(self.carol_old)]), 1
        )
        self.assertEqual(
            self.cli(["decrypt", "--no-colour", "--quiet",
                      "--key", str(self.carol_old),
                      "--key", str(self.current_keys()["Bob"]),
                      "--output", str(self.root / "nope")]),
            1,
        )

    def test_the_old_ciphertext_is_deleted(self):
        """Left in place, every old key still opens it and nothing changed."""
        before = {p.name for p in self.layout.encrypted_dir.glob("*.age")}
        self.reseal()
        after = {p.name for p in self.layout.encrypted_dir.glob("*.age")}
        self.assertEqual(len(after), 1)
        self.assertEqual(after, before, "the plain filename should be reclaimed")

    def test_keeping_the_old_file_is_reported_as_leaving_access_open(self):
        self.reseal("--keep-old-file")
        self.assertEqual(len(list(self.layout.encrypted_dir.glob("*.age"))), 2)
        self.assertIn("can still open it", self.output.getvalue())

    def test_stale_key_files_are_named_but_not_deleted(self):
        """Deleting a secret on a guess is irreversible; naming it is not."""
        self.reseal()
        text = self.output.getvalue()
        self.assertIn("Key for Digital Legacy - Carol.yaml", text)
        self.assertNotIn("Key for Digital Legacy - Alice.yaml", text)
        self.assertTrue(self.keys["Carol"].exists(), "must not delete key files")

    def test_reseal_without_enough_keys_is_refused(self):
        code = self.cli(
            ["reseal", "--no-colour", "--quiet", "--key", str(self.keys["Alice"]),
             "--shares", "2", "--threshold", "2", "--name", "A", "--name", "B"]
        )
        self.assertEqual(code, 1)
        self.assertIn("2 keys are needed", self.output.getvalue())

    def test_reseal_with_no_keys_at_all_explains_what_is_needed(self):
        self.assertEqual(self.cli(["reseal", "--no-colour", "--quiet"]), 1)
        self.assertIn("needs the current keys", self.output.getvalue())

    def test_reseal_can_change_the_threshold(self):
        code = self.cli(
            ["reseal", "--no-colour", "--quiet",
             "--key", str(self.keys["Alice"]), "--key", str(self.keys["Bob"]),
             "--shares", "4", "--threshold", "3",
             "--name", "A", "--name", "B", "--name", "C", "--name", "D"]
        )
        self.assertEqual(code, 0, self.output.getvalue())
        from digital_legacy.policy import Policy

        policy = Policy.load(self.layout.encrypted_dir / "recipients.yaml")
        self.assertEqual((policy.threshold, policy.total_shares), (3, 4))
