"""Tests for Aegis Guardian Scam Shield. Run: python3 -m unittest -v"""
import os
import unittest

import scam_shield as ss


PULSEWAY = (
    'This is the Recruiting Team sending greetings. Your impressive resume '
    'caught our attention. Daily pay falls between $200 and $400. Must be no '
    'younger than 25. Application Method: Text "JD" to 3463976885. '
    'Only 20 positions available!'
)


class VerdictTests(unittest.TestCase):
    def test_recruiter_task_scam_is_flagged(self):
        r = ss.scan(PULSEWAY)
        self.assertEqual(r.verdict, "LIKELY SCAM")
        self.assertGreaterEqual(r.score, 50)

    def test_reply_to_other_number_fires(self):
        names = {s["name"] for s in ss.scan(PULSEWAY).signals}
        self.assertIn("reply_other_number", names)

    def test_pay_range_fires(self):
        names = {s["name"] for s in ss.scan(PULSEWAY).signals}
        self.assertIn("too_good_pay", names)

    def test_crypto_fee_is_scam(self):
        r = ss.scan("Unlock your account: send a small activation fee in USDT now.")
        self.assertEqual(r.verdict, "LIKELY SCAM")

    def test_shortener_is_suspicious_or_worse(self):
        r = ss.scan("Your parcel is held. Confirm at bit.ly/track-now")
        self.assertIn(r.verdict, ("SUSPICIOUS", "LIKELY SCAM"))
        self.assertIn("shortened_link", {s["name"] for s in r.signals})

    def test_normal_dentist_text_is_safe(self):
        r = ss.scan("Hi it's Maria from the dentist, confirming your 2pm Tuesday. Reply C to confirm.")
        self.assertEqual(r.verdict, "LIKELY SAFE")

    def test_normal_casual_text_is_safe(self):
        r = ss.scan("you coming to the game tonight? starts at 7")
        self.assertEqual(r.verdict, "LIKELY SAFE")

    def test_bank_warning_not_overflagged(self):
        # A real bank notice mentions no money-ask, link, or reply-number trick.
        r = ss.scan("This is Chase Bank. We will never ask for your PIN.")
        self.assertEqual(r.verdict, "LIKELY SAFE")

    def test_score_capped_at_100(self):
        self.assertLessEqual(ss.scan(PULSEWAY + " crypto bit.ly/x").score, 100)

    def test_exit_code_maps_to_verdict(self):
        self.assertEqual(ss.scan(PULSEWAY).exit_code, 2)
        self.assertEqual(ss.scan("game tonight at 7?").exit_code, 0)

    def test_preview_truncated(self):
        r = ss.scan("x" * 200)
        self.assertTrue(r.message_preview.endswith("…"))
        self.assertLessEqual(len(r.message_preview), 81)


class NewRuleTests(unittest.TestCase):
    def _names(self, msg):
        return {s["name"] for s in ss.scan(msg).signals}

    def test_hi_mom_new_number(self):
        r = ss.scan("Hi Mom, this is my new number. Can you text me on WhatsApp?")
        self.assertEqual(r.verdict, "LIKELY SCAM")
        self.assertIn("family_impersonation", self._names("Hi mom, new number, lost my phone"))

    def test_spanish_family_impersonation(self):
        self.assertIn("family_impersonation",
                      self._names("Hola mamá, este es mi nuevo número"))

    def test_real_mom_text_is_safe(self):
        self.assertEqual(ss.scan("Mom: can you grab milk on your way home?").verdict, "LIKELY SAFE")

    def test_brand_link_needs_link_and_action(self):
        self.assertIn("brand_link", self._names("USPS: unpaid fee, pay now at https://usps-help.com"))
        self.assertNotIn("brand_link", self._names("Your Amazon order has shipped. Track it in the app."))

    def test_spanish_job_scam(self):
        r = ss.scan("Trabajo desde casa, sin experiencia, pago diario de $200 a $400. Plazas limitadas.")
        self.assertEqual(r.verdict, "LIKELY SCAM")

    def test_wrong_number_opener(self):
        self.assertIn("wrong_number_opener", self._names("Sorry, wrong number! You seem nice though."))

    def test_verification_code_is_safe(self):
        self.assertEqual(ss.scan("Your verification code is 482913. Don't share it.").verdict, "LIKELY SAFE")


class SampleFileTests(unittest.TestCase):
    def setUp(self):
        self.here = os.path.dirname(__file__)

    def _load(self, name):
        with open(os.path.join(self.here, "samples", name), encoding="utf-8") as fh:
            return [ln.strip() for ln in fh if ln.strip()]

    def test_all_sample_scams_flagged(self):
        for msg in self._load("scams.txt"):
            with self.subTest(msg=msg[:40]):
                self.assertNotEqual(ss.scan(msg).verdict, "LIKELY SAFE")

    def test_all_sample_legit_safe(self):
        for msg in self._load("legit.txt"):
            with self.subTest(msg=msg[:40]):
                self.assertEqual(ss.scan(msg).verdict, "LIKELY SAFE")


class CLITests(unittest.TestCase):
    def test_cli_returns_scam_exit_code(self):
        self.assertEqual(ss.main(["--text", PULSEWAY, "--json"]), 2)

    def test_cli_returns_safe_exit_code(self):
        self.assertEqual(ss.main(["--text", "see you at 7", "--json"]), 0)

    def test_cli_bad_file(self):
        self.assertEqual(ss.main(["--file", "/no/such/file.txt"]), 3)


if __name__ == "__main__":
    unittest.main()
