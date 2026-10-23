# Scam Shield — Aegis Guardian (Phase 1)

A free, local, read-only scanner that flags scam text messages and explains **why**. No network, no data leaves your machine, Python standard library only.

Built from real scam patterns — fake-recruiter "task scams," reply-to-a-different-number tricks, fake urgency, crypto/gift-card bait, and link shorteners.

## Usage

```bash
# scan one message
python3 scam_shield.py --text "This is the Recruiting Team... text JD to 3463976885. Only 20 positions!"

# scan a file of messages (one per line)
python3 scam_shield.py --file samples/scams.txt

# machine-readable output
python3 scam_shield.py --text "..." --json
```

### Exit codes
| Code | Meaning |
|---|---|
| `0` | LIKELY SAFE |
| `1` | SUSPICIOUS |
| `2` | LIKELY SCAM |
| `3` | usage / input error |

## Example

```
🚨 LIKELY SCAM  (score 100/100)
   message: "This is Pulseway Recruiting Team. Your impressive resume caught…"
   signals:
     • [30] Tells you to text/reply to a different number than the sender
     • [25] Uses unsolicited-job-offer language common in task scams
     • [20] Promises high pay for little work ($200–$400/day, few hours)
     • [20] Creates false urgency ('limited spots', 'act now')
     • [10] Adds an odd eligibility gate ('must be no younger than 25')
```

## How it scores

Each rule carries a weight; the weights add up (capped at 100). The verdict is **LIKELY SCAM** at 50+, **SUSPICIOUS** at 25–49, **LIKELY SAFE** below 25. Every rule that fires is shown, so you see the reasoning instead of a black-box score.

The scanner is deliberately tuned to **not** over-flag normal texts — appointment reminders, delivery notices, and real bank warnings all read as safe in the test set.

## Tests

```bash
python3 -m unittest -v
```

16 tests: verdict logic, each key signal, the sample scam/legit files, and the CLI exit codes.

## Privacy

Everything runs on-device. The scanner never uploads message content; "reporting" a scam (a later phase) will share only the extracted *pattern*, never your messages.

## Roadmap

- **Now:** rule-based text scanner (this)
- **Next:** a small on-device model to catch novel phrasings
- **Later:** one-tap report that shares patterns, not content
