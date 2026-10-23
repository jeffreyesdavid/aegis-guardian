# Aegis Guardian — Threat Model

This document defines **what Aegis protects against, what it deliberately doesn't, and who might attack it.** It's the reference every feature is checked against: if a design choice weakens one of these protections, the design is wrong, not the threat model.

Aegis is a safety tool. The single greatest risk in its category is that a safety tool gets turned *against* the person it's meant to protect. Everything here is organized around preventing that.

---

## 1. Design principles (non-negotiable)

| Principle | What it means in practice |
|---|---|
| **Consent is mandatory** | Every person tracked, pinged, or shared-with has opted in and can leave. No exceptions, no "admin override." |
| **Visible by design** | There is no silent mode. If something is being shared, the person sharing it can see that it is. |
| **On-device first** | Anything that can be computed on the phone, is. The server learns as little as possible. |
| **No self-escalation** | The app can never grant itself new access. Sensitive changes need a human tap on the device. |
| **Auditable** | Open source, documented, reproducible builds. Trust comes from verification, not promises. |

---

## 2. What we protect

- **Location data** — where you are and where you've been
- **Message content** — check-in texts, alerts, notes to your circle
- **Contact graph** — who's in your trusted circle and emergency list
- **Routine data** — the on-device model of your normal patterns
- **Identity & keys** — your account and the keys that decrypt your data

---

## 3. Adversaries & defenses

### 3.1 Thief with your (unlocked) phone
**Goal:** read your data, add themselves as a contact, enable tracking.
**Defenses:**
- Keys live in the secure enclave, released only after device auth (Face ID / PIN).
- Sensitive actions (add contact, change alert recipients, enable sharing) require a fresh on-device confirmation.
- Tamper alerts fire on any contact or permission change.

### 3.2 Server breach
**Goal:** steal location, messages, and the contact graph from the backend.
**Defenses:**
- End-to-end encryption: the server stores ciphertext it has no key for.
- The relay knows *that* two users are linked, never *what* they share.
- Minimal retention: encrypted blobs are deleted after delivery.

### 3.3 Malicious or compromised contact
**Goal:** a person in your circle tries to see more than you shared, or track you silently.
**Defenses:**
- Contacts see only what you explicitly shared, for as long as you allow it.
- Sharing is always visible to you and revocable instantly.
- No contact can enable sharing *about you* — only you can.

### 3.4 Abuser attempting covert surveillance
**Goal:** install or configure Aegis to track someone without their knowledge.
**Defenses:**
- There is no hidden/silent mode to enable — this is the core design refusal.
- The tracked person always sees active sharing and can kill it.
- Setup requires action on the tracked person's own device; you can't enroll someone remotely.

### 3.5 Network attacker (man-in-the-middle)
**Goal:** intercept or alter data in transit.
**Defenses:**
- TLS for transport, plus E2E encryption underneath, so interception yields ciphertext.
- Certificate pinning on the app's connection to the relay.

### 3.6 Malicious app update / supply chain
**Goal:** slip a backdoor into a release.
**Defenses:**
- Open source with reproducible builds, so a published binary can be matched to public source.
- Signed releases; dependency pinning and review.

### 3.7 The scam itself (the everyday threat)
**Goal:** phishing/task-scam texts trick the user into sending money or credentials.
**Defenses:**
- On-device classifier flags known scam patterns (fake recruiters, "text X to this number," urgency hooks).
- One-tap report; patterns improve over time without uploading message content.

---

## 4. Out of scope (honest limits)

Aegis does **not** defend against:
- A fully compromised OS or a jailbroken/rooted device with malware at the root level.
- A nation-state adversary with device-level zero-days.
- Physical coercion (someone forcing you to unlock and share).
- The user voluntarily sharing with someone who later misuses it (we make revocation easy, but we can't prevent the initial choice).

Naming these keeps the model honest. A security doc that claims to stop everything stops nothing.

---

## 5. Review checklist for new features

Before any feature ships, it must pass all five:

- [ ] **Consent** — does every affected person opt in and retain control?
- [ ] **Visibility** — can the tracked person always see what's being shared?
- [ ] **Least data** — does the server learn the minimum possible?
- [ ] **No escalation** — can this be abused to gain access without a human tap?
- [ ] **Revocable** — can the user shut it off instantly?

If a feature fails any box, it changes or it doesn't ship.
