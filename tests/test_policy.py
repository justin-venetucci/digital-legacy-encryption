"""Policy parsing and validation.

Each test here corresponds to a way the original scattered-regex approach could
misread a file, or a way an invalid arrangement used to sail through.
"""

from __future__ import annotations

import unittest

from digital_legacy.errors import PolicyError
from digital_legacy.policy import Policy
from support import PUBLIC_KEYS


def build(threshold: int = 2, count: int = 3) -> str:
    body = "".join(f"  - {key}\n" for key in PUBLIC_KEYS[:count])
    return f"threshold: {threshold}\nshares:\n{body}"


class ParseTests(unittest.TestCase):
    def test_parses_the_shape_this_tool_writes(self):
        policy = Policy.parse(build())
        self.assertEqual(policy.threshold, 2)
        self.assertEqual(policy.shares, PUBLIC_KEYS[:3])

    def test_threshold_in_a_comment_is_ignored(self):
        """The original bug: re.search matched inside comments.

        A file carrying a stale "# threshold: 99" above the real value parsed as
        99, an unsatisfiable requirement that would demand keys nobody holds.
        """
        text = "# threshold: 99 (old value)\n" + build(threshold=2)
        self.assertEqual(Policy.parse(text).threshold, 2)

    def test_trailing_comments_are_ignored(self):
        text = build().replace("threshold: 2", "threshold: 2  # two of three")
        self.assertEqual(Policy.parse(text).threshold, 2)

    def test_blank_lines_and_leading_comments_are_fine(self):
        text = "# a header\n\n" + build() + "\n\n# trailing note\n"
        self.assertEqual(Policy.parse(text).total_shares, 3)

    def test_utf8_bom_is_tolerated(self):
        """Notepad on Windows writes one, and owners do edit this file."""
        self.assertEqual(Policy.parse("﻿" + build()).threshold, 2)


class ValidationTests(unittest.TestCase):
    def test_threshold_above_share_count_is_refused(self):
        """The worst original failure: silent, and only found when it mattered."""
        with self.assertRaises(PolicyError) as caught:
            Policy.parse(build(threshold=5, count=3))
        self.assertIn("could never be opened", caught.exception.hint)

    def test_missing_threshold_is_refused(self):
        with self.assertRaises(PolicyError):
            Policy.parse("shares:\n  - " + PUBLIC_KEYS[0] + "\n")

    def test_empty_threshold_is_refused(self):
        """The skeleton the old encrypt.py wrote when no config existed."""
        text = "threshold: \nshares: \n  - \n  - \n# created blank config\n"
        with self.assertRaises(PolicyError) as caught:
            Policy.parse(text)
        self.assertIn("no number after it", caught.exception.message)

    def test_duplicate_shares_are_refused(self):
        text = f"threshold: 1\nshares:\n  - {PUBLIC_KEYS[0]}\n  - {PUBLIC_KEYS[0]}\n"
        with self.assertRaises(PolicyError):
            Policy.parse(text)

    def test_repeated_threshold_is_refused(self):
        with self.assertRaises(PolicyError):
            Policy.parse("threshold: 1\n" + build(threshold=2))

    def test_malformed_public_key_is_refused(self):
        with self.assertRaises(PolicyError):
            Policy.parse("threshold: 1\nshares:\n  - not-a-key\n")

    def test_bech32_excluded_characters_are_refused(self):
        # 'b', 'i' and 'o' are not in the bech32 alphabet.
        bad = "age1bbbiiiooo" + "q" * 49
        with self.assertRaises(PolicyError):
            Policy.parse(f"threshold: 1\nshares:\n  - {bad}\n")

    def test_share_before_the_shares_heading_is_refused(self):
        with self.assertRaises(PolicyError):
            Policy.parse(f"  - {PUBLIC_KEYS[0]}\nthreshold: 1\n")

    def test_unknown_setting_is_refused_rather_than_ignored(self):
        with self.assertRaises(PolicyError) as caught:
            Policy.parse("threshold: 1\nsalt: pepper\nshares:\n  - " + PUBLIC_KEYS[0])
        self.assertIn("salt", caught.exception.message)

    def test_no_shares_at_all_is_refused(self):
        with self.assertRaises(PolicyError):
            Policy.parse("threshold: 1\nshares:\n")


class AdvisoryTests(unittest.TestCase):
    def test_one_of_n_is_flagged(self):
        notes = Policy(threshold=1, shares=PUBLIC_KEYS[:3]).advisories()
        self.assertTrue(any("on its own" in n for n in notes))

    def test_n_of_n_is_flagged_as_fragile(self):
        notes = Policy(threshold=3, shares=PUBLIC_KEYS[:3]).advisories()
        self.assertTrue(any("permanently unrecoverable" in n for n in notes))

    def test_a_sensible_arrangement_is_left_alone(self):
        self.assertEqual(Policy(threshold=2, shares=PUBLIC_KEYS[:3]).advisories(), [])


class RenderTests(unittest.TestCase):
    def test_render_reparses_to_the_same_policy(self):
        policy = Policy(threshold=2, shares=PUBLIC_KEYS[:3])
        self.assertEqual(Policy.parse(policy.render()), policy)

    def test_render_refuses_an_invalid_policy(self):
        with self.assertRaises(PolicyError):
            Policy(threshold=9, shares=PUBLIC_KEYS[:2]).render()

    def test_save_and_load_round_trip(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "recipients.yaml"
            Policy(threshold=2, shares=PUBLIC_KEYS[:3]).save(path)
            self.assertEqual(Policy.load(path).threshold, 2)

    def test_load_reports_a_missing_file_readably(self):
        from pathlib import Path

        with self.assertRaises(PolicyError) as caught:
            Policy.load(Path("no") / "such" / "recipients.yaml")
        self.assertIn("missing", caught.exception.message)


if __name__ == "__main__":
    unittest.main()
