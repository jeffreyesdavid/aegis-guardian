# Aegis Guardian

**A free, bilingual (English / Español) AI scam shield for everyday people and their families.**

*Un escudo gratuito y bilingüe contra estafas, hecho para las familias.*

> Paste a suspicious text, email, or phone number, or upload a screenshot. Aegis tells you if it's likely a scam, shows you the red flags, and tells you what to do next, in plain English or Spanish.

Aegis is a consent-first personal safety and anti-scam agent, built so it can never become the surveillance tool it's meant to prevent. It's part of the **Guardian** security portfolio, alongside [VPN Guardian](https://github.com/jeffreyesdavid/vpn-guardian) and [Wi-Fi Guardian](https://github.com/jeffreyesdavid/wifi-guardian). Like its siblings, it's **open source and auditable**, so you can verify there's no hidden backdoor.

 **Live:** [try the scam checker](https://jeffreyesdavid.github.io/aegis-guardian/app/) in English or Spanish. AI layer powered by Meta's Muse Spark.

---

## Why this exists

Scams, not hacks, are where people lose the most money:

- **$20.9 billion** in cybercrime losses were reported to the FBI in 2025, a record, from over 1 million complaints.
- **85%** of those losses came from cyber-enabled fraud: scams, not break-ins.
- People **60 and over** lost **$7.75 billion**, up 59% in one year.
- **Phishing and spoofing** was the most reported crime type.
- AI-related complaints were counted for the first time: **22,364 complaints and $893 million lost**.

*Source: FBI IC3 2025 Internet Crime Report (April 2026).*

Data breaches make it worse. Leaked personal info lets scammers write texts that mention your real name, bank, or recent order. Existing scam checkers mostly give a yes/no answer, in English, behind a paid antivirus plan.

Aegis is different:

1. **Bilingual by default.** Spanish-speaking families are heavily targeted and underserved.
2. **Explains the *why*.** It teaches people the red flags so they get better at spotting scams on their own.
3. **Family-first.** It turns a scam into a shareable warning card you can send to your group chat.
4. **Free and open source.** No upsell, ever.

Most "family tracking" apps quietly cross the line into surveillance. Aegis is the opposite bet: a safety tool people install because it protects *them*, built transparently enough that they can trust it.

---

## How the scam scanner works

Aegis uses two layers. A fast, local rule engine (already shipped, see [`app/scam/`](app/scam/)) catches known patterns with no network at all. The AI layer reads what rules can't: screenshots, new scam scripts, and context.

```
 Screenshot / text / number
            │
            ▼
   ┌─────────────────┐
   │  Rule engine    │  local, instant, no network
   │ (scam_shield.py)│  known scam patterns + scoring
   └────────┬────────┘
            │
            ▼
   ┌─────────────────┐
   │   Muse Spark    │  reads the message or screenshot, reasons about
   │ (Meta Model API)│  red flags, searches for reports on the sender
   └────────┬────────┘
            │
            ▼
   ┌─────────────────┐
   │  Verdict card   │  🔴 Likely scam / 🟡 Suspicious / 🟢 Looks safe
   │                 │  + red flags found + what to do next (EN/ES)
   └────────┬────────┘
            │
            ▼
   ┌─────────────────┐
   │   Muse Image    │  optional "Anatomy of this scam" warning card
   └─────────────────┘  to share with family
```

### Red flags Aegis checks for

- Fake urgency ("your account will be closed in 24 hours")
- Look-alike or shortened links
- Spoofed senders (banks, USPS, toll agencies, the IRS, Amazon)
- Requests for gift cards, crypto, wire transfers, or payment apps
- Requests to text a different number or move to WhatsApp, Telegram, or another app
- Fake recruiter "task scams" and too-good-to-be-true pay
- "Wrong number" openers and investment offers
- Impersonation of family ("Hi mom, this is my new number" / "Hola mamá, este es mi nuevo número")
- Spanish-language versions of job, urgency, and payment scams

### Try it now

**In your browser:** [jeffreyesdavid.github.io/aegis-guardian/app](https://jeffreyesdavid.github.io/aegis-guardian/app/). English and Spanish, runs entirely on your device.

**From the terminal:**

```bash
python3 app/scam/scam_shield.py --file app/scam/samples/scams.txt
```

**Tests:** `cd app/scam && python3 -m unittest` (23 tests) and `node app/scam/test_parity.mjs` (checks the browser and Python engines agree).

---

## Built with

| Tool | Role in Aegis |
|---|---|
| **Python rule engine** | Local, offline first pass ([`app/scam/`](app/scam/)) |
| **Muse Spark** (Meta Model API) | AI scanner: reads text and screenshots, reasons about red flags, web-search grounding |
| **Muse Image** | Generates shareable scam warning cards |
| **SAM 3.1** | *Experimental:* "X-ray mode" to highlight suspicious parts of a screenshot |
| **Muse Code** | AI coding agent used to build the project |

---

## Roadmap

- **Phase 1 — Scam shield.** ✅ **Shipped.** A local, read-only scanner that flags scam texts and explains why. No network, Python stdlib only.
- **Phase 1.5 — AI scam shield (Oct 2026)**
  - [x] Paste text → verdict + red flags + next steps (local rules, Oct 26)
  - [x] English / Spanish output
  - [x] Clean, mobile-friendly web app
  - [x] Copy-a-warning message for family group chats
  - [x] AI layer (Muse Spark) with structured verdicts, evidence, and next steps ([`app/ai/`](app/ai/))
  - [x] Screenshot upload (AI transcribes it, then the rules run on the text too)
  - [ ] Tested against real scam and legit samples with a live key
  - [ ] *Stretch:* shareable warning cards (Muse Image)
  - [ ] *Stretch:* X-ray mode to highlight suspicious parts (SAM 3.1)
  - [ ] *Stretch:* one-tap "warn my family" message
- **Phase 2 — Safety circle.** Opt-in check-ins and trusted contacts, with E2E encryption from day one.
- **Phase 3 — Routine sense.** On-device anomaly detection and the gentle check-in prompt.
- **Later — Private mode.** Run the AI layer on open-weight models so sensitive messages never leave your control.

---

## The bigger idea: consent-first safety

A safety agent that protects the people who opt in. It flags scams, lets you share your location with people *you* choose, and reaches your trusted circle if something's wrong, without ever tracking anyone who didn't agree to it.

The hard line: **consent is the only difference between a guardian and stalkerware.** Everything here is designed around that.

| Feature | What it does | Data source |
|---|---|---|
| **Scam shield** | Flags scam texts, numbers, and screenshots and explains why | Your messages, shared by you |
| **Safety check-ins** | Share live location with contacts you pick; auto-share last location if you miss a ping | Your device, opt-in |
| **Trusted circle** | Name your emergency contacts; the right person is reached first | Your contacts, your choice |
| **Routine sense** | Notices big breaks from your normal pattern and prompts a gentle "you good?" | On-device only |

### What it will never do

- Track someone who didn't opt in
- Tap nearby phones, cameras, Bluetooth, or Wi-Fi to locate a person
- Read a location through other people's devices
- Run any "silent" mode the tracked person can't see and disable

If a feature can't be built with the tracked person's knowledge and consent, it doesn't get built.

---

## Privacy

- Aegis never asks for passwords, bank info, or account numbers.
- The local rule engine runs fully offline.
- The AI scanner sends only the message or screenshot you choose to scan to the Meta Model API. Blur personal details before uploading.
- Scans aren't stored by default.

---

## Security model

A safety app that gets hijacked becomes the worst-case tool. Security is the backbone, not a feature.

1. **End-to-end encryption.** Location and messages are encrypted on-device; the server only ever holds ciphertext it can't read.
2. **On-device by default.** Routine learning and pattern matching run locally. Data that never leaves the phone can't be stolen from a server.
3. **Hardware-backed keys.** Keys live in the secure enclave (iOS Keychain / Android Keystore), never in app files. A copied database is useless without the device.
4. **No self-escalation.** Sensitive actions (add a contact, change who gets alerts, enable sharing) require on-device user confirmation. No remote command can grant itself new access.
5. **Tamper and takeover alerts.** New-device logins, permission changes, and config edits all notify the user immediately.
6. **Open source and audited.** Public code, reproducible builds, documented threat model.

### Threat model (who we're defending against)

- **A thief with your unlocked phone** → hardware keys + confirmation on sensitive actions
- **A server breach** → E2E encryption; server holds no readable data
- **A malicious contact** → contacts see only what you shared; no hidden escalation
- **An abuser trying to flip on silent tracking** → impossible by design; all sharing is visible and user-controlled

Full details: [`docs/threat-model.md`](docs/threat-model.md)

---

## Architecture outline

```
┌─────────────────────────────────────────────┐
│                  MOBILE APP                   │
│  (iOS / Android — most logic lives here)      │
│                                               │
│  ┌───────────┐  ┌────────────┐  ┌──────────┐ │
│  │ Scam       │  │ Routine    │  │ Trusted  │ │
│  │ classifier │  │ engine     │  │ circle   │ │
│  │ (on-device)│  │ (on-device)│  │ manager  │ │
│  └───────────┘  └────────────┘  └──────────┘ │
│         │              │              │        │
│  ┌──────────────────────────────────────────┐ │
│  │  Crypto layer (secure enclave keys, E2E)  │ │
│  └──────────────────────────────────────────┘ │
└──────────────────────┬────────────────────────┘
                       │  ciphertext only
                       ▼
┌─────────────────────────────────────────────┐
│               RELAY SERVER                    │
│  Stores & forwards encrypted blobs.           │
│  Cannot read location, messages, or contacts. │
│  Handles: delivery, push triggers, auth.      │
└─────────────────────────────────────────────┘
```

### Components

**Mobile app (the core)**
- `scam/` — scam scanner: local rules today, AI layer next; reporting pipeline
- `routine/` — on-device pattern engine; learns normal behavior; flags anomalies; never leaves the device
- `circle/` — trusted-contact management; invites, consent records, revocation
- `crypto/` — key generation in the secure enclave; E2E encrypt/decrypt; key rotation
- `checkin/` — the ping → wait-window → last-location flow, with cancel

**Relay server (deliberately dumb)**
- Stores and forwards **encrypted blobs only**
- Handles auth, push-notification triggers, and delivery
- Knows *that* two users are connected, never *what* they share
- No plaintext location, messages, or contact graph ever touches it

### Emergency flow

```
Contact pings you
   → you don't respond within the set window
      → your last location is shared with your chosen circle
         → you can cancel at any point
```

---

## Repo structure

```
aegis-guardian/
├── README.md
├── docs/           # landing page + threat model
├── app/
│   ├── scam/       # scam shield (shipped) + AI layer (in progress)
│   ├── routine/
│   ├── circle/
│   ├── crypto/
│   └── checkin/
├── relay/          # store-and-forward server
└── LICENSE
```

---

## License

MIT
