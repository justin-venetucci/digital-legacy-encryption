"""Encryption, verification and decryption.

Split in two: the logic that can be checked with a stand-in toolchain, and the
cryptographic round-trips that only mean something against the real binaries and
so skip themselves when those are absent -- which is the state of a fresh clone.
"""

from __future__ import annotations

import random
import tempfile
import unittest
from pathlib import Path

from support import FakeToolchain, real_toolchain, requires_binaries

from digital_legacy import agekeys, operations
from digital_legacy.errors import EncryptionError, VerificationError
from digital_legacy.policy import Policy
from digital_legacy.vault import Vault, sha256_file


class EncryptGuardTests(unittest.TestCase):
    """Refusals that should happen before any work is done."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.vault = Vault(self.root / "encrypted")
        self.toolchain = FakeToolchain()
        self.keypairs = [agekeys.generate(self.toolchain, label=n) for n in "ABC"]
        self.policy = Policy(
            threshold=2, shares=[k.public_key for k in self.keypairs]
        )

    def tearDown(self):
        self._tmp.cleanup()

    def source(self, name: str = "doc.txt", content: bytes = b"hello") -> Path:
        path = self.root / name
        path.write_bytes(content)
        return path

    def test_missing_source_is_refused(self):
        with self.assertRaises(EncryptionError):
            operations.encrypt_document(
                self.toolchain, self.root / "nope.txt", self.vault, self.policy
            )

    def test_empty_source_is_refused(self):
        with self.assertRaises(EncryptionError) as caught:
            operations.encrypt_document(
                self.toolchain, self.source(content=b""), self.vault, self.policy
            )
        self.assertIn("empty", caught.exception.message)

    def test_already_encrypted_file_is_refused(self):
        with self.assertRaises(EncryptionError) as caught:
            operations.encrypt_document(
                self.toolchain, self.source("doc.age"), self.vault, self.policy
            )
        self.assertIn("already encrypted", caught.exception.message)

    def test_invalid_policy_is_refused_before_encrypting(self):
        bad = Policy(threshold=9, shares=self.policy.shares)
        with self.assertRaises(Exception):
            operations.encrypt_document(self.toolchain, self.source(), self.vault, bad)
        self.assertEqual(list(self.vault.path.glob("*.age")), [])

    def test_metadata_records_the_extension_rather_than_re_deriving_it(self):
        result = operations.encrypt_document(
            self.toolchain,
            self.source("taxes 2024.1.txt"),
            self.vault,
            self.policy,
            when="2026-01-01",
        )
        self.assertEqual(result.entry.original_stem, "taxes 2024.1")
        self.assertEqual(result.entry.original_suffix, ".txt")
        self.assertTrue(result.entry.plaintext_sha256)

    def test_no_partial_file_survives_a_failed_encryption(self):
        self.toolchain.fail_on = "age"
        with self.assertRaises(Exception):
            operations.encrypt_document(
                self.toolchain, self.source(), self.vault, self.policy
            )
        leftovers = list(self.vault.path.glob("*"))
        self.assertEqual(leftovers, [], f"left behind: {leftovers}")

    def test_verification_is_required_by_default_when_no_keys_exist(self):
        """Encrypting to an existing key list leaves nothing to test with."""
        with self.assertRaises(VerificationError):
            operations.encrypt_and_verify(
                self.toolchain, self.source(), self.vault, self.policy, []
            )

    def test_verification_can_be_waived_explicitly(self):
        result = operations.encrypt_and_verify(
            self.toolchain,
            self.source(),
            self.vault,
            self.policy,
            [],
            require_verification=False,
        )
        self.assertFalse(result.verified)
        self.assertIn("not tested", result.verification_detail)

    def test_verification_reports_rather_than_raises_with_too_few_keys(self):
        result = operations.encrypt_document(
            self.toolchain, self.source(), self.vault, self.policy
        )
        check = operations.verify_entry(
            self.toolchain, self.vault, result.entry, self.keypairs[:1], threshold=2
        )
        self.assertFalse(check.ok)
        self.assertIn("could not be tested", check.detail)


@requires_binaries
class RoundTripTests(unittest.TestCase):
    """The real thing: age, age-keygen and age-plugin-sss."""

    def setUp(self):
        self.toolchain = real_toolchain()
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.vault = Vault(self.root / "encrypted")

    def tearDown(self):
        self._tmp.cleanup()

    def build(self, total: int = 3, threshold: int = 2):
        keypairs = [
            agekeys.generate(self.toolchain, label=f"Holder{i + 1}")
            for i in range(total)
        ]
        policy = Policy(threshold=threshold, shares=[k.public_key for k in keypairs])
        return keypairs, policy

    def source(self, name="My Passwords.v2.txt") -> Path:
        path = self.root / name
        path.write_bytes(b"bank: 1234\npassword: hunter2\n" * 500)
        return path

    def test_encrypt_verify_decrypt_round_trip(self):
        keypairs, policy = self.build()
        source = self.source()
        result = operations.encrypt_and_verify(
            self.toolchain, source, self.vault, policy, keypairs
        )
        self.assertTrue(result.verified, result.verification_detail)

        out = self.root / "out"
        written = operations.decrypt_entry(
            self.toolchain,
            self.vault,
            result.entry,
            [keypairs[0].secret_key, keypairs[2].secret_key],
            out,
        )
        self.assertEqual(written.read_bytes(), source.read_bytes())
        self.assertEqual(written.suffix, ".txt")

    def test_every_threshold_sized_subset_can_decrypt(self):
        """Shamir's promise, checked rather than assumed."""
        import itertools

        keypairs, policy = self.build(total=4, threshold=2)
        result = operations.encrypt_document(
            self.toolchain, self.source(), self.vault, policy
        )
        for combo in itertools.combinations(range(4), 2):
            check = operations.verify_entry(
                self.toolchain,
                self.vault,
                result.entry,
                [keypairs[i] for i in combo],
                threshold=2,
                rng=random.Random(0),
            )
            self.assertTrue(check.ok, f"{combo} failed: {check.detail}")

    def test_below_threshold_cannot_decrypt(self):
        keypairs, policy = self.build(total=3, threshold=3)
        result = operations.encrypt_document(
            self.toolchain, self.source(), self.vault, policy
        )
        from digital_legacy.errors import DecryptionError

        with self.assertRaises(DecryptionError):
            operations.decrypt_entry(
                self.toolchain,
                self.vault,
                result.entry,
                [keypairs[0].secret_key, keypairs[1].secret_key],
                self.root / "out",
            )

    def test_keys_from_another_vault_are_refused(self):
        keypairs, policy = self.build()
        result = operations.encrypt_document(
            self.toolchain, self.source(), self.vault, policy
        )
        strangers = [agekeys.generate(self.toolchain) for _ in range(2)]
        from digital_legacy.errors import DecryptionError

        with self.assertRaises(DecryptionError) as caught:
            operations.decrypt_entry(
                self.toolchain,
                self.vault,
                result.entry,
                [k.secret_key for k in strangers],
                self.root / "out",
            )
        self.assertIn("cannot open this document", caught.exception.message)

    def test_no_empty_output_file_is_left_after_a_failed_decryption(self):
        keypairs, policy = self.build()
        result = operations.encrypt_document(
            self.toolchain, self.source(), self.vault, policy
        )
        out = self.root / "out"
        strangers = [agekeys.generate(self.toolchain) for _ in range(2)]
        with self.assertRaises(Exception):
            operations.decrypt_entry(
                self.toolchain,
                self.vault,
                result.entry,
                [k.secret_key for k in strangers],
                out,
            )
        self.assertEqual(list(out.glob("*")) if out.exists() else [], [])

    def test_verification_catches_a_corrupted_ciphertext(self):
        keypairs, policy = self.build()
        result = operations.encrypt_document(
            self.toolchain, self.source(), self.vault, policy
        )
        result.path.write_bytes(result.path.read_bytes()[:-40])
        check = operations.verify_entry(
            self.toolchain, self.vault, result.entry, keypairs, threshold=2
        )
        self.assertFalse(check.ok)

    def test_one_of_one_share_works(self):
        keypairs, policy = self.build(total=1, threshold=1)
        result = operations.encrypt_and_verify(
            self.toolchain, self.source(), self.vault, policy, keypairs
        )
        self.assertTrue(result.verified)

    def test_binary_document_survives_the_round_trip(self):
        keypairs, policy = self.build()
        source = self.root / "photo.jpg"
        source.write_bytes(bytes(range(256)) * 400)
        result = operations.encrypt_and_verify(
            self.toolchain, source, self.vault, policy, keypairs
        )
        written = operations.decrypt_entry(
            self.toolchain,
            self.vault,
            result.entry,
            [k.secret_key for k in keypairs[:2]],
            self.root / "out",
        )
        self.assertEqual(sha256_file(written), sha256_file(source))

    def test_the_committed_sample_vault_still_opens(self):
        """The repository's only worked example must never silently rot."""
        from support import INTERNALS

        vault = Vault(INTERNALS / "encrypted")
        entry = vault.sole_entry()
        secrets = [
            agekeys.read_key_file(p).secret_key
            for p in sorted((INTERNALS / "sample-keys").glob("*.yaml"))[:2]
        ]
        written = operations.decrypt_entry(
            self.toolchain, vault, entry, secrets, self.root / "sample-out"
        )
        self.assertTrue(written.read_bytes().startswith(b"%PDF"))
        self.assertEqual(written.suffix, ".pdf")


if __name__ == "__main__":
    unittest.main()
