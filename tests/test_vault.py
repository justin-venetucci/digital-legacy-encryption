"""Vault layout, manifest, and the filename parsing the old decryptor got wrong."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from digital_legacy.errors import VaultError
from digital_legacy.policy import Policy
from digital_legacy.vault import (
    MANIFEST_NAME,
    Manifest,
    Vault,
    VaultEntry,
    unique_path,
)
from support import PUBLIC_KEYS


class FilenameTests(unittest.TestCase):
    """The concrete cases the old ``Path(stem).suffix`` approach mangled."""

    def check(self, ciphertext: str, stem: str, suffix: str):
        entry = VaultEntry.from_ciphertext(Path(ciphertext))
        self.assertEqual((entry.original_stem, entry.original_suffix), (stem, suffix))

    def test_ordinary_name(self):
        self.check("Passwords - Encrypted 2025-05-26.pdf.age", "Passwords", ".pdf")

    def test_dot_inside_the_name_is_not_an_extension(self):
        """``Path("taxes 2024.1 - Encrypted 2025-05-26").suffix`` returned
        ``".1 - Encrypted 2025-05-26"``, so the beneficiary got a file no
        application would open."""
        self.check("taxes 2024.1 - Encrypted 2025-05-26.age", "taxes 2024.1", "")

    def test_dotted_stem_with_a_real_extension(self):
        self.check(
            "weird.name.with.dots - Encrypted 2025-05-26.txt.age",
            "weird.name.with.dots",
            ".txt",
        )

    def test_collision_counter_is_stripped(self):
        self.check("My Will - Encrypted 2030-01-01 (2).docx.age", "My Will", ".docx")

    def test_stray_sensitive_prefix_is_dropped(self):
        """The old encryptor added this marker to ciphertext on collision."""
        self.check(
            "[SENSITIVE] Passwords - Encrypted 2025-05-26 (1).age", "Passwords", ""
        )

    def test_name_with_no_stamp_at_all(self):
        self.check("something.pdf.age", "something", ".pdf")

    def test_no_extension_falls_back_to_bin(self):
        entry = VaultEntry.from_ciphertext(Path("notes - Encrypted 2025-05-26.age"))
        self.assertTrue(entry.output_name(when="2026-01-01").endswith(".bin"))

    def test_output_name_never_stacks_the_marker(self):
        entry = VaultEntry(ciphertext_name="x.age", original_stem="[SENSITIVE] Report",
                           original_suffix=".pdf")
        name = entry.output_name(when="2026-01-01")
        self.assertEqual(name.count("[SENSITIVE]"), 1)

    def test_manifest_suffix_wins_over_re_derivation(self):
        """Recorded metadata is authoritative; nothing re-splits the name."""
        entry = VaultEntry(
            ciphertext_name="x.age", original_stem="taxes 2024.1", original_suffix=""
        )
        self.assertEqual(
            entry.output_name(when="2026-01-01"),
            "[SENSITIVE] taxes 2024.1 - Decrypted 2026-01-01.bin",
        )


class UniquePathTests(unittest.TestCase):
    def test_counter_goes_before_the_suffix(self):
        """The old collision branch dropped the extension entirely."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            names = []
            for _ in range(3):
                path = unique_path(root, "Doc - Encrypted 2026-01-01.pdf", ".age")
                path.write_text("x")
                names.append(path.name)
        self.assertEqual(
            names,
            [
                "Doc - Encrypted 2026-01-01.pdf.age",
                "Doc - Encrypted 2026-01-01.pdf (1).age",
                "Doc - Encrypted 2026-01-01.pdf (2).age",
            ],
        )


class VaultTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.vault = Vault(self.root)
        self.vault.ensure()
        Policy(threshold=2, shares=PUBLIC_KEYS[:3]).save(self.root / "recipients.yaml")

    def tearDown(self):
        self._tmp.cleanup()

    def add_ciphertext(self, name: str) -> Path:
        path = self.root / name
        path.write_bytes(b"age-encrypted-bytes")
        return path

    def test_missing_ciphertext_is_reported_readably(self):
        with self.assertRaises(VaultError) as caught:
            self.vault.entries()
        self.assertIn("no encrypted document", caught.exception.message)

    def test_two_policies_refuse_to_guess(self):
        Policy(threshold=1, shares=PUBLIC_KEYS[:2]).save(self.root / "other.yaml")
        with self.assertRaises(VaultError) as caught:
            self.vault.policy_path()
        self.assertIn("more than one", caught.exception.message)

    def test_manifest_is_not_mistaken_for_a_policy(self):
        self.vault.save_manifest(Manifest())
        self.assertEqual(self.vault.policy_path().name, "recipients.yaml")

    def test_multiple_documents_are_listed_not_fatal(self):
        """Running the old encryptor twice bricked the vault permanently."""
        self.add_ciphertext("A - Encrypted 2026-01-01.pdf.age")
        self.add_ciphertext("B - Encrypted 2026-01-02.txt.age")
        self.assertEqual(len(self.vault.entries()), 2)
        with self.assertRaises(VaultError):
            self.vault.sole_entry()

    def test_manifest_round_trip(self):
        entry = VaultEntry(
            ciphertext_name="A.age", original_stem="A", original_suffix=".pdf"
        )
        self.vault.save_manifest(Manifest(owner="Justin", threshold=2, entries=[entry]))
        loaded = self.vault.load_manifest()
        self.assertEqual(loaded.owner, "Justin")
        self.assertEqual(loaded.entries[0].original_suffix, ".pdf")

    def test_unknown_manifest_fields_are_ignored(self):
        """Forward compatibility: a newer minor version must not break an older."""
        payload = {"manifest_version": 1, "owner": "x", "entries": [], "future": 1}
        (self.root / MANIFEST_NAME).write_text(json.dumps(payload), encoding="utf-8")
        self.assertEqual(self.vault.load_manifest().owner, "x")

    def test_manifest_from_a_newer_format_is_refused_clearly(self):
        payload = {"manifest_version": 99, "entries": []}
        (self.root / MANIFEST_NAME).write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaises(VaultError) as caught:
            self.vault.load_manifest()
        self.assertIn("newer version", caught.exception.message)

    def test_a_damaged_manifest_never_blocks_decryption(self):
        self.add_ciphertext("A - Encrypted 2026-01-01.pdf.age")
        (self.root / MANIFEST_NAME).write_text("{ not json", encoding="utf-8")
        entries = self.vault.entries()
        self.assertEqual(entries[0].original_suffix, ".pdf")

    def test_a_file_missing_from_the_manifest_is_still_offered(self):
        """Losing vault.json must never hide a document from whoever needs it."""
        self.add_ciphertext("A - Encrypted 2026-01-01.pdf.age")
        self.add_ciphertext("B - Encrypted 2026-01-02.txt.age")
        self.vault.save_manifest(
            Manifest(
                entries=[
                    VaultEntry(ciphertext_name="A - Encrypted 2026-01-01.pdf.age")
                ]
            )
        )
        names = {e.ciphertext_name for e in self.vault.entries()}
        self.assertIn("B - Encrypted 2026-01-02.txt.age", names)

    def test_integrity_notices_a_changed_file(self):
        path = self.add_ciphertext("A - Encrypted 2026-01-01.pdf.age")
        entry = VaultEntry(
            ciphertext_name=path.name,
            ciphertext_sha256="0" * 64,
            ciphertext_size=path.stat().st_size,
        )
        problems = self.vault.check_integrity(entry)
        self.assertTrue(any("checksum" in p for p in problems))

    def test_integrity_notices_a_truncated_file(self):
        path = self.add_ciphertext("A - Encrypted 2026-01-01.pdf.age")
        entry = VaultEntry(ciphertext_name=path.name, ciphertext_size=99999)
        self.assertTrue(any("bytes" in p for p in self.vault.check_integrity(entry)))


if __name__ == "__main__":
    unittest.main()
