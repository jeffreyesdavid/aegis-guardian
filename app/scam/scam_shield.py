#!/usr/bin/env python3
"""
Aegis Guardian — Scam Shield (Phase 1)

A free, local, read-only scanner that flags scam text messages.
No network, no data leaves the machine, Python standard library only.

It scores a message against a set of rules drawn from real scam patterns
(fake-recruiter "task scams", reply-to-a-different-number tricks, fake
urgency, payment/crypto bait, lookalike links) and returns a verdict with
the exact signals that fired — so a person can see *why* something is risky.

Usage:
    python3 scam_shield.py --text "This is the Recruiting Team..."
    python3 scam_shield.py --file messages.txt        # one message per line
    python3 scam_shield.py --file messages.txt --json  # machine-readable

Exit codes (useful in scripts/pipelines):
    0  LIKELY SAFE
    1  SUSPICIOUS
    2  LIKELY SCAM
    3  usage / input error
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field, asdict


# --- Rules -------------------------------------------------------------------
# Each rule: a name, a weight (how strongly it points at a scam), a short
# human explanation, and a test function over the lowercased message.

@dataclass
class Signal:
    name: str
    weight: int
    why: str


SHORTENERS = (
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rb.gy", "rebrand.ly", "shorturl.at",
)

# Country calling codes commonly seen in bulk scam texts aimed at US numbers.
# Presence alone is weak; it only adds weight alongside other signals.
FOREIGN_CODES = ("+212", "+234", "+233", "+44 7", "+63", "+91", "+92", "+880")

MONEY_WORDS = (
    "crypto", "bitcoin", "usdt", "gift card", "wire transfer", "cash app",
    "cashapp", "venmo", "zelle", "deposit", "activation fee", "processing fee",
    "unlock your", "withdraw your earnings",
)

URGENCY_WORDS = (
    "only 20 positions", "limited slots", "act now", "offer expires",
    "today only", "last chance", "respond immediately", "within 24 hours",
    "hurry", "don't miss", "spots are filling",
)

JOB_BAIT = (
    "recruiting team", "part-time", "remote position", "work from home",
    "daily pay", "flexible hours", "no experience", "your resume caught",
    "your impressive resume", "online reviewing", "rating tasks",
    "optimization tasks", "app testing",
)


def _has_url(text: str) -> bool:
    return bool(re.search(r"https?://|www\.|\b[\w-]+\.(com|net|org|io|xyz|info|link|app)\b", text))


def _reply_to_other_number(text: str) -> bool:
    # "text JD to 3463976885" / "reply YES to 1-800-..." style instructions
    return bool(re.search(r"\b(text|reply|send|message)\b[^.]{0,40}?\bto\b[^.]{0,20}?(\+?\d[\d\-\s]{6,}\d)", text))


def _daily_pay_range(text: str) -> bool:
    # "$200 and $400", "$200-$400", "pay falls between $200 and $400"
    return bool(re.search(r"\$\s?\d{2,4}\s?(?:-|to|and|–|—)\s?\$?\s?\d{2,4}", text))


def _age_gate(text: str) -> bool:
    return bool(re.search(r"(no younger than|must be (?:at least|over)|aged?)\s*\d{2}", text))


def _contains_any(text: str, words: tuple) -> list:
    return [w for w in words if w in text]


RULES = []


def rule(name, weight, why):
    def deco(fn):
        RULES.append((name, weight, why, fn))
        return fn
    return deco


@rule("job_bait", 25, "Uses unsolicited-job-offer language common in task scams")
def r_job(t): return len(_contains_any(t, JOB_BAIT)) >= 1

@rule("job_bait_heavy", 15, "Multiple recruiter/task-scam phrases stacked together")
def r_job_heavy(t): return len(_contains_any(t, JOB_BAIT)) >= 2

@rule("reply_other_number", 30, "Tells you to text/reply to a different number than the sender")
def r_reply(t): return _reply_to_other_number(t)

@rule("fake_urgency", 20, "Creates false urgency ('limited spots', 'act now')")
def r_urgency(t): return len(_contains_any(t, URGENCY_WORDS)) >= 1

@rule("too_good_pay", 20, "Promises high pay for little work (e.g. $200–$400/day, few hours)")
def r_pay(t): return _daily_pay_range(t)

@rule("money_ask", 35, "Mentions crypto, gift cards, or a fee to 'unlock' or withdraw")
def r_money(t): return len(_contains_any(t, MONEY_WORDS)) >= 1

@rule("money_ask_heavy", 15, "Several payment/crypto bait phrases stacked together")
def r_money_heavy(t): return len(_contains_any(t, MONEY_WORDS)) >= 2

@rule("shortened_link", 25, "Contains a link shortener that hides the real destination")
def r_short(t): return any(s in t for s in SHORTENERS)

@rule("foreign_code", 10, "Reply/contact number uses a foreign country code")
def r_foreign(t): return any(c.lower() in t for c in FOREIGN_CODES)

@rule("age_gate", 10, "Adds an odd eligibility gate ('must be no younger than 25')")
def r_age(t): return _age_gate(t)

@rule("vague_sender", 15, "Claims to know you ('your resume') without naming you or a real company")
def r_vague(t):
    knows = ("your resume" in t or "your impressive resume" in t or "your application" in t)
    named = bool(re.search(r"\b(inc\.|llc|corp|company|team at)\b", t))
    return knows and not named


# --- Scoring -----------------------------------------------------------------

@dataclass
class Result:
    verdict: str
    score: int
    signals: list = field(default_factory=list)
    message_preview: str = ""

    @property
    def exit_code(self) -> int:
        return {"LIKELY SCAM": 2, "SUSPICIOUS": 1, "LIKELY SAFE": 0}[self.verdict]


def scan(message: str) -> Result:
    t = message.lower()
    fired = []
    score = 0
    for name, weight, why, fn in RULES:
        try:
            if fn(t):
                fired.append(Signal(name, weight, why))
                score += weight
        except re.error:
            continue
    score = min(score, 100)

    if score >= 50:
        verdict = "LIKELY SCAM"
    elif score >= 25:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LIKELY SAFE"

    preview = (message.strip().replace("\n", " "))[:80]
    if len(message.strip()) > 80:
        preview += "…"
    return Result(verdict, score, [asdict(s) for s in fired], preview)


# --- CLI ---------------------------------------------------------------------

def _emoji(verdict: str) -> str:
    return {"LIKELY SCAM": "🚨", "SUSPICIOUS": "⚠️ ", "LIKELY SAFE": "✅"}[verdict]


def _print_human(res: Result) -> None:
    print(f"{_emoji(res.verdict)} {res.verdict}  (score {res.score}/100)")
    if res.message_preview:
        print(f'   message: "{res.message_preview}"')
    if res.signals:
        print("   signals:")
        for s in res.signals:
            print(f"     • [{s['weight']:>2}] {s['why']}")
    else:
        print("   signals: none")
    print()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Aegis Guardian — Scam Shield (local scam-text scanner)")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--text", help="a single message to scan")
    src.add_argument("--file", help="a text file with one message per line")
    p.add_argument("--json", action="store_true", help="output machine-readable JSON")
    args = p.parse_args(argv)

    messages = []
    if args.text:
        messages = [args.text]
    else:
        try:
            with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
                messages = [ln.rstrip("\n") for ln in fh if ln.strip()]
        except OSError as e:
            print(f"error: could not read {args.file}: {e}", file=sys.stderr)
            return 3

    if not messages:
        print("error: no messages to scan", file=sys.stderr)
        return 3

    results = [scan(m) for m in messages]

    if args.json:
        print(json.dumps([
            {"verdict": r.verdict, "score": r.score,
             "signals": r.signals, "message_preview": r.message_preview}
            for r in results
        ], indent=2))
    else:
        for r in results:
            _print_human(r)
        if len(results) > 1:
            worst = max(r.verdict for r in results)  # alpha order happens to rank SCAM<SUSPICIOUS<SAFE badly
            counts = {}
            for r in results:
                counts[r.verdict] = counts.get(r.verdict, 0) + 1
            summary = ", ".join(f"{v}: {counts[v]}" for v in ("LIKELY SCAM", "SUSPICIOUS", "LIKELY SAFE") if v in counts)
            print(f"scanned {len(results)} messages — {summary}")

    # Exit code reflects the riskiest message found.
    return max(r.exit_code for r in results)


if __name__ == "__main__":
    raise SystemExit(main())
