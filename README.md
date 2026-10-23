# Aegis Guardian 🛡️

> A consent-first personal safety and anti-scam agent — built so it can never become the surveillance tool it's meant to prevent.

Part of the **Guardian** security portfolio, alongside [VPN Guardian](https://github.com/jeffreyesdavid/vpn-guardian) and [Wi-Fi Guardian](https://github.com/jeffreyesdavid/wifi-guardian). Like its siblings, Aegis is **open source and auditable** — the whole point is that you can verify there's no hidden backdoor.

---

## The idea

A safety agent that protects the people who opt in. It flags scams, lets you share your location with people *you* choose, and reaches your trusted circle if something's wrong — without ever tracking anyone who didn't agree to it.

The hard line: **consent is the only difference between a guardian and stalkerware.** Everything here is designed around that.

---

## What it does

| Feature | What it does | Data source |
|---|---|---|
| **Scam shield** | Flags and reports junk/scam texts and numbers; learns new patterns | Your inbox, on-device |
| **Safety check-ins** | Share live location with contacts you pick; auto-share last location if you miss a ping | Your device, opt-in |
| **Trusted circle** | Name your emergency contacts; the right person is reached first | Your contacts, your choice |
| **Routine sense** | Notices big breaks from your normal pattern and prompts a gentle "you good?" | On-device only |

---

## What it will never do

- Track someone who didn't opt in
- Tap nearby phones, cameras, Bluetooth, or Wi-Fi to locate a person
- Read a location through other people's devices
- Run any "silent" mode the tracked person can't see and disable

If a feature can't be built with the tracked person's knowledge and consent, it doesn't get built.

---

## Security model

A safety app that gets hijacked becomes the worst-case tool. Security is the backbone, not a feature.

1. **End-to-end encryption** — location and messages are encrypted on-device; the server only ever holds ciphertext it can't read.
2. **On-device by default** — routine learning and pattern matching run locally. Data that never leaves the phone can't be stolen from a server.
3. **Hardware-backed keys** — keys live in the secure enclave (iOS Keychain / Android Keystore), never in app files. A copied database is useless without the device.
4. **No self-escalation** — sensitive actions (add a contact, change who gets alerts, enable sharing) require on-device user confirmation. No remote command can grant itself new access.
5. **Tamper & takeover alerts** — new-device logins, permission changes, and config edits all notify the user immediately.
6. **Open source & audited** — public code, reproducible builds, documented threat model.

### Threat model (who we're defending against)
- **A thief with your unlocked phone** → hardware keys + confirmation on sensitive actions
- **A server breach** → E2E encryption; server holds no readable data
- **A malicious contact** → contacts see only what you shared; no hidden escalation
- **An abuser trying to flip on silent tracking** → impossible by design; all sharing is visible and user-controlled

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
- `scam/` — on-device classifier for texts & numbers; local rules + a lightweight model; reporting pipeline
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

## Suggested tech stack

> Starting points, not commitments — pick what fits your learning goals.

- **App:** React Native or Flutter (one codebase, iOS + Android)
- **Encryption:** libsignal / `tweetnacl` for E2E; OS secure-enclave APIs for keys
- **On-device ML:** Core ML (iOS) / TensorFlow Lite (Android) for the scam classifier
- **Relay:** a small Node/Go service — just store-and-forward + push
- **Push:** APNs (iOS) / FCM (Android)

---

## Roadmap

- **Phase 1 — Scam shield.** Standalone, no accounts needed. Flags and reports scam texts/numbers. Proves the idea and ships fast.
- **Phase 2 — Safety circle.** Opt-in check-ins and trusted contacts, with E2E encryption from day one.
- **Phase 3 — Routine sense.** On-device anomaly detection and the gentle check-in prompt.

---

## Repo structure

```
aegis-guardian/
├── README.md
├── docs/
│   ├── threat-model.md
│   ├── architecture.md
│   └── privacy-policy.md
├── app/            # mobile client
│   ├── scam/
│   ├── routine/
│   ├── circle/
│   ├── crypto/
│   └── checkin/
├── relay/          # store-and-forward server
└── LICENSE
```

---

## Why this exists

Most "family tracking" apps quietly cross the line into surveillance. Aegis is the opposite bet: a safety tool people install because it protects *them*, built transparently enough that they can trust it. A consent-first design isn't just the ethical choice — it's the more honest product.

---

## License

Open source (MIT or Apache-2.0 — TBD).

*Working name — rename freely.*
