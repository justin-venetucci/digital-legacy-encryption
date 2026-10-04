"""What changes when the tool is packaged for a real family.

The repository's defaults describe one way of handing keys out: on paper or a
USB stick, kept apart from the document. An owner who keeps each share in a
cloud folder, shared only with its holder, needs the files and the paperwork to
say that instead -- and needs a package that runs on a computer with no Python.
These tests cover the pieces that make that possible.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from support import (
    PUBLIC_KEYS,
    ROOT,
    SECRET_KEYS,
    guard_not_the_real_repo,
    make_layout,
    requires_binaries,
)

from digital_legacy import agekeys, handoff, layout, operations
from digital_legacy.agekeys import KeyPair
from digital_legacy.cli import main as cli_main
from digital_legacy.layout import Layout
from digital_legacy.policy import Policy
from digital_legacy.vault import Manifest, Vault

PREFIX = "SENSITIVE - Key for Family Legacy - "


def load_builder():
    spec = importlib.util.spec_from_file_location(
        "build_release", ROOT / "tools" / "build_release.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CompiledLayoutTests(unittest.TestCase):
    """A compiled program must find the project from where the exe sits."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name).resolve()
        self.program = self.root / "internals" / "program"
        self.program.mkdir(parents=True)

    def tearDown(self):
        self._tmp.cleanup()

    def discover(self, program_dir):
        with mock.patch.dict("os.environ", {}, clear=False) as env:
            env.pop(layout.ROOT_ENV_VAR, None)
            with mock.patch.object(
                layout, "_compiled_program_dir", return_value=program_dir
            ):
                return Layout.discover()

    def test_root_is_two_levels_above_the_program_folder(self):
        self.assertEqual(self.discover(self.program).root, self.root)

    def test_an_exe_copied_elsewhere_does_not_invent_a_root(self):
        stray = self.root / "Downloads"
        stray.mkdir()
        self.assertNotEqual(self.discover(stray).root, self.root.parent)
        self.assertNotEqual(self.discover(stray).root, stray.parent.parent)

    def test_the_environment_variable_still_wins(self):
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir()
        with mock.patch.dict(
            "os.environ", {layout.ROOT_ENV_VAR: str(elsewhere)}
        ), mock.patch.object(
            layout, "_compiled_program_dir", return_value=self.program
        ):
            self.assertEqual(Layout.discover().root, elsewhere)

    def test_an_ordinary_run_is_not_treated_as_compiled(self):
        self.assertIsNone(layout._compiled_program_dir())


class DesktopTests(unittest.TestCase):
    """The Desktop a person sees is not always ``~/Desktop``."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.home = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def resolve(self, *, shell=None, windows=True):
        with mock.patch.object(operations.Path, "home", return_value=self.home), \
             mock.patch.object(operations.os, "name", "nt" if windows else "posix"), \
             mock.patch.object(
                 operations, "_windows_shell_desktop", return_value=shell
             ):
            return operations.default_output_dir()

    def test_onedrive_desktop_is_preferred_over_an_empty_leftover(self):
        (self.home / "Desktop").mkdir()
        (self.home / "OneDrive" / "Desktop").mkdir(parents=True)
        self.assertEqual(self.resolve(), self.home / "OneDrive" / "Desktop")

    def test_a_named_onedrive_folder_is_found(self):
        (self.home / "OneDrive - Personal" / "Desktop").mkdir(parents=True)
        self.assertEqual(self.resolve(), self.home / "OneDrive - Personal" / "Desktop")

    def test_what_windows_reports_wins(self):
        (self.home / "OneDrive" / "Desktop").mkdir(parents=True)
        moved = self.home / "Elsewhere"
        moved.mkdir()
        self.assertEqual(self.resolve(shell=moved), moved)

    def test_a_reported_folder_that_does_not_exist_is_skipped(self):
        (self.home / "Desktop").mkdir()
        self.assertEqual(self.resolve(shell=self.home / "gone"), self.home / "Desktop")

    def test_no_desktop_anywhere_falls_back_to_home(self):
        self.assertEqual(self.resolve(), self.home)

    def test_onedrive_is_not_consulted_off_windows(self):
        (self.home / "OneDrive" / "Desktop").mkdir(parents=True)
        (self.home / "Desktop").mkdir()
        self.assertEqual(self.resolve(windows=False), self.home / "Desktop")


class HandoffProfileTests(unittest.TestCase):
    def setUp(self):
        self.pairs = [
            KeyPair(public_key=p, secret_key=s, label=n, created="2026-01-01")
            for p, s, n in zip(PUBLIC_KEYS, SECRET_KEYS, ["Alice", "Bob", "Carol"])
        ]
        self.policy = Policy(threshold=2, shares=[k.public_key for k in self.pairs])

    def context(self, **profile):
        return handoff.HandoffContext(
            owner="Sam",
            document="Plan.pdf",
            policy=self.policy,
            keypairs=self.pairs,
            created="2026-01-01",
            **profile,
        )

    def test_defaults_are_unchanged(self):
        self.assertEqual(
            agekeys.key_file_name("Alice"), "Key for Digital Legacy - Alice.yaml"
        )
        text = agekeys.render_key_file(self.pairs[0], threshold=2, total_shares=3)
        self.assertIn("Do not email it", text)
        self.assertTrue(text.rstrip().endswith(self.pairs[0].secret_key))
        self.assertEqual(self.context().profile(), {})

    def test_prefix_names_the_key_file_and_cannot_escape_the_folder(self):
        self.assertEqual(agekeys.key_file_name("Bob", PREFIX), f"{PREFIX}Bob.yaml")
        hostile = agekeys.key_file_name("Bob", "..\\..\\x/")
        self.assertNotIn("\\", hostile)
        self.assertNotIn("/", hostile)

    def test_shared_folder_key_file_drops_the_contradicting_advice(self):
        text = agekeys.render_key_file(
            self.pairs[0], threshold=2, total_shares=3, shared_folder=True
        )
        self.assertNotIn("Do not email it", text)
        self.assertNotIn("do not store it with", text)
        self.assertIn("Leave it where it was shared with you", text)

    def test_notes_are_comments_and_the_file_still_parses(self):
        notes = (
            "keywords:\n  - digital legacy plan\n\n"
            "# already a comment\nAGE-SECRET-KEY-1NOTAKEY"
        )
        text = agekeys.render_key_file(
            self.pairs[0], threshold=2, total_shares=3, notes=notes
        )
        tail = text.split(self.pairs[0].secret_key, 1)[1]
        for line in tail.splitlines():
            self.assertTrue(not line or line.startswith("#"), line)
        self.assertIn("#   - digital legacy plan", tail)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / agekeys.key_file_name("Alice", PREFIX)
            path.write_text(text, encoding="utf-8")
            parsed = agekeys.read_key_file(path)
        self.assertEqual(parsed.secret_key, self.pairs[0].secret_key)
        self.assertEqual(parsed.label, "Alice")

    def test_readme_names_the_real_key_files_and_how_to_get_them(self):
        context = self.context(key_prefix=PREFIX, shared_folder=True)
        readme = handoff.vault_readme(context)
        flat = " ".join(readme.split())
        self.assertIn(f"{PREFIX}<name>.yaml", flat)
        self.assertIn("Request access", flat)
        self.assertNotIn("Key for Digital Legacy -", flat)

        default = " ".join(handoff.vault_readme(self.context()).split())
        self.assertIn("Key for Digital Legacy - <name>.yaml", default)
        self.assertNotIn("Request access", default)

    def test_profile_round_trips_through_the_manifest(self):
        context = self.context(key_prefix=PREFIX, shared_folder=True, key_notes="a\nb")
        manifest = Manifest.from_json(Manifest(handoff=context.profile()).to_json())
        self.assertEqual(
            handoff.stored_profile(manifest),
            {"key_prefix": PREFIX, "shared_folder": True, "key_notes": "a\nb"},
        )

    def test_a_manifest_from_before_profiles_existed_still_loads(self):
        manifest = Manifest.from_json('{"manifest_version": 1, "owner": "J"}')
        self.assertEqual(manifest.handoff, {})
        self.assertEqual(
            handoff.stored_profile(manifest),
            {"key_prefix": "", "shared_folder": False, "key_notes": ""},
        )
        self.assertEqual(handoff.stored_profile(None), {})

    def test_a_damaged_profile_falls_back_to_defaults(self):
        manifest = Manifest.from_json('{"handoff": ["not", "a", "dict"]}')
        self.assertEqual(handoff.stored_profile(manifest), {})


@requires_binaries
class ProfileThroughTheCliTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.layout = make_layout(self.root)
        guard_not_the_real_repo(self.layout)
        self.source = self.root / "Plan.pdf"
        self.source.write_bytes(b"%PDF-1.4 the plan\n" * 50)
        self.notes = self.root / "keywords.txt"
        self.notes.write_text("keywords:\n  - family legacy plan\n", encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    def run_cli(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = cli_main(["--no-colour", *argv], layout=self.layout)
        return code, out.getvalue()

    def key(self, name):
        return self.layout.keys_out_dir / f"{PREFIX}{name}.yaml"

    def test_encrypt_then_reseal_keeps_the_owners_naming(self):
        code, out = self.run_cli(
            "encrypt", "--file", str(self.source), "--shares", "3", "--threshold", "2",
            "--name", "Alice", "--name", "Bob", "--name", "Carol", "--owner", "Sam",
            "--key-prefix", PREFIX, "--shared-folder", "--key-notes", str(self.notes),
        )  # fmt: skip
        self.assertEqual(code, 0, out)
        self.assertTrue(self.key("Alice").exists(), out)
        text = self.key("Alice").read_text(encoding="utf-8")
        self.assertIn("#   - family legacy plan", text)
        self.assertNotIn("Do not email it", text)

        manifest = Vault(self.layout.encrypted_dir).load_manifest()
        self.assertEqual(manifest.handoff["key_prefix"], PREFIX)

        # No profile flags this time: the vault remembers.
        code, out = self.run_cli(
            "reseal", "--key", str(self.key("Alice")), "--key", str(self.key("Bob")),
            "--shares", "3", "--threshold", "2",
            "--name", "Alice", "--name", "Bob", "--name", "Dad", "--owner", "Sam",
        )  # fmt: skip
        self.assertEqual(code, 0, out)
        self.assertTrue(self.key("Dad").exists(), out)
        self.assertIn("family legacy plan", self.key("Dad").read_text(encoding="utf-8"))
        readme = (self.layout.encrypted_dir / "READ ME FIRST.txt").read_text("utf-8")
        self.assertIn("Request access", readme)

        # And the new keys open the resealed document.
        output = self.root / "out"
        code, out = self.run_cli(
            "decrypt", "--key", str(self.key("Bob")), "--key", str(self.key("Dad")),
            "--output", str(output),
        )  # fmt: skip
        self.assertEqual(code, 0, out)
        recovered = list(output.iterdir())
        self.assertEqual(len(recovered), 1)
        self.assertEqual(recovered[0].read_bytes(), self.source.read_bytes())

    def test_a_missing_notes_file_is_a_plain_error(self):
        code, out = self.run_cli(
            "encrypt", "--file", str(self.source), "--shares", "2", "--threshold", "2",
            "--name", "A", "--name", "B", "--key-notes", str(self.root / "nope.txt"),
        )  # fmt: skip
        self.assertEqual(code, 1)
        self.assertIn("key notes", out)
        self.assertNotIn("Traceback", out)


class ReleaseBuilderTests(unittest.TestCase):
    """The packager must never ship a secret, whatever folder it is pointed at."""

    @classmethod
    def setUpClass(cls):
        cls.builder = load_builder()

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.stage = Path(self._tmp.name)
        (self.stage / "internals" / "encrypted").mkdir(parents=True)
        (self.stage / "internals" / "encrypted" / "doc.pdf.age").write_bytes(b"age-")

    def tearDown(self):
        self._tmp.cleanup()

    def test_a_production_root_can_carry_its_own_banner(self):
        root = self.stage / "root"
        shutil.copytree(self.stage / "internals", root / "internals")
        (root / "internals" / "binaries").mkdir()
        resources = root / "internals" / "scripts" / "resources"
        resources.mkdir(parents=True)
        (resources / "ascii.txt").write_text("Our Family\n", encoding="utf-8")

        staged = self.stage / "staged"
        self.builder.stage(root, staged, None)

        banner = staged / "internals" / "scripts" / "resources" / "ascii.txt"
        self.assertEqual(banner.read_text(encoding="utf-8"), "Our Family\n")
        self.assertTrue((staged / "internals" / "scripts" / "decrypt.py").is_file())

    def test_a_clean_tree_passes(self):
        self.assertEqual(self.builder.find_secrets(self.stage), [])

    def test_a_private_key_anywhere_is_refused(self):
        stray = self.stage / "internals" / "encrypted" / "notes.txt"
        stray.write_text(f"oops\n{SECRET_KEYS[0]}\n", encoding="utf-8")
        problems = self.builder.find_secrets(self.stage)
        self.assertEqual(len(problems), 1)
        self.assertIn("private key", problems[0])
        self.assertNotIn(SECRET_KEYS[0], problems[0])

    def test_a_reconstructed_identity_is_refused(self):
        stray = self.stage / "identity.txt"
        stray.write_text("AGE-PLUGIN-SSS-1" + "Q" * 60, encoding="utf-8")
        self.assertTrue(self.builder.find_secrets(self.stage))

    def test_key_and_letter_folders_are_refused(self):
        for name in ("age-keys-DISTRIBUTE-AND-DELETE", "handoff", "sample-keys"):
            (self.stage / "internals" / name).mkdir()
        self.assertEqual(len(self.builder.find_secrets(self.stage)), 3)

    def test_a_decrypted_document_is_refused(self):
        (self.stage / "[SENSITIVE] Plan - Decrypted 2026-01-01.pdf").write_bytes(b"x")
        self.assertIn("decrypted document", self.builder.find_secrets(self.stage)[0])

    def test_the_bare_prefix_in_source_code_is_not_a_secret(self):
        (self.stage / "internals" / "agekeys.py").write_text(
            'SECRET_KEY_RE = re.compile(r"^(AGE-SECRET-KEY-1[02-9AC-HJ-NP-Z]+)")',
            encoding="utf-8",
        )
        self.assertEqual(self.builder.find_secrets(self.stage), [])

    def test_the_repository_itself_is_never_packaged(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = self.builder.main(["--root", str(ROOT), "--no-compile"])
        self.assertEqual(code, 1)
        self.assertIn("Refusing", out.getvalue())

    def test_the_zip_has_no_top_level_folder(self):
        import zipfile

        archive = self.builder.write_zip(self.stage, self.stage.parent / "p.zip")
        try:
            with zipfile.ZipFile(archive) as handle:
                self.assertIn("internals/encrypted/doc.pdf.age", handle.namelist())
        finally:
            archive.unlink()


if __name__ == "__main__":
    unittest.main()
