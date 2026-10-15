import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import passcheck as pc  # noqa: E402


class PoolTests(unittest.TestCase):
    def test_pool_sizes(self):
        self.assertEqual(pc.character_pool("abc")[0], 26)
        self.assertEqual(pc.character_pool("aB")[0], 52)
        self.assertEqual(pc.character_pool("aB3")[0], 62)
        self.assertEqual(pc.character_pool("aB3!")[0], 95)

    def test_space_counts_as_symbol(self):
        self.assertIn("symbols", pc.character_pool("a b")[1])


class WeaknessDetectionTests(unittest.TestCase):
    def test_exact_common_password_scores_zero(self):
        r = pc.analyse("password")
        self.assertEqual(r.entropy_bits, 0)
        self.assertEqual(r.rating, "Very weak")
        self.assertEqual(r.score, 0)

    def test_common_password_is_case_insensitive(self):
        self.assertEqual(pc.analyse("PASSWORD").entropy_bits, 0)

    def test_leetspeak_is_caught(self):
        r = pc.analyse("P@ssw0rd")
        self.assertLessEqual(r.entropy_bits, 10)
        self.assertEqual(r.rating, "Very weak")

    def test_common_word_with_suffix_is_caught(self):
        r = pc.analyse("Summer2024!")
        self.assertLessEqual(r.entropy_bits, 20)
        self.assertEqual(r.rating, "Very weak")

    def test_repeats_collapse_effective_length(self):
        r = pc.analyse("aaaaaaaaaaaa")
        self.assertEqual(r.effective_length, 1)
        self.assertEqual(r.rating, "Very weak")

    def test_sequence_and_keyboard_walk_detected(self):
        r = pc.analyse("qwerty123456")
        self.assertEqual(r.effective_length, 2)
        self.assertTrue(any("sequence" in i.lower() for i in r.issues))

    def test_descending_sequence_detected(self):
        self.assertLess(pc.analyse("zyxwvu").effective_length, 6)

    def test_year_is_flagged(self):
        r = pc.analyse("Kx9mQz2019")
        self.assertTrue(any("year" in i.lower() for i in r.issues))

    def test_short_password_never_better_than_weak(self):
        r = pc.analyse("Xk9#mQ2")  # 7 chars, high character variety
        self.assertIn(r.rating, ("Very weak", "Weak"))
        self.assertTrue(any("short" in i.lower() for i in r.issues))


class StrengthTests(unittest.TestCase):
    def test_long_random_looking_password_is_strong(self):
        self.assertIn(pc.analyse("k9#Lm2$vQxR7!tZp").rating, ("Strong", "Very strong"))

    def test_random_passphrase_scales_with_word_count(self):
        four = pc.analyse("maple river stone lantern")
        six = pc.analyse("maple river stone lantern quiet orbit")
        self.assertAlmostEqual(four.entropy_bits, 4 * pc.BITS_PER_RANDOM_WORD, delta=0.1)
        self.assertGreater(six.entropy_bits, four.entropy_bits)

    def test_passphrase_not_overstated(self):
        # Character entropy would give >150 bits; word-based estimate must win.
        self.assertLess(pc.analyse("correct horse battery staple").entropy_bits, 60)

    def test_longer_is_never_worse_for_same_style(self):
        a = pc.analyse("Kx9#mQ2z")
        b = pc.analyse("Kx9#mQ2zLp4$")
        self.assertGreater(b.entropy_bits, a.entropy_bits)


class WordlistAndFormattingTests(unittest.TestCase):
    def test_custom_wordlist_is_used(self):
        with tempfile.TemporaryDirectory() as d:
            wl = Path(d) / "words.txt"
            wl.write_text("zebrafish\n")
            common = pc.COMMON_PASSWORDS | pc.load_wordlist(wl)
        self.assertEqual(pc.analyse("Zebrafish", common).entropy_bits, 0)
        self.assertGreater(pc.analyse("Zebrafish").entropy_bits, 0)

    def test_crack_time_formatting(self):
        self.assertEqual(pc.format_crack_time(0), "instantly")
        self.assertEqual(pc.format_crack_time(20), "instantly")
        self.assertIn("year", pc.format_crack_time(70))
        self.assertIn("millions", pc.format_crack_time(200))

    def test_empty_password_rejected(self):
        with self.assertRaises(ValueError):
            pc.analyse("")

    def test_unicode_does_not_crash(self):
        self.assertGreater(pc.analyse("pässwörd-Ωmega-9").entropy_bits, 0)

    def test_render_contains_rating_and_suggestions(self):
        out = pc.render(pc.analyse("password"))
        self.assertIn("Very weak", out)
        self.assertIn("Suggestions", out)


if __name__ == "__main__":
    unittest.main()
