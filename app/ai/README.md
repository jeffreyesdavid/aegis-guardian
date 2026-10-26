# Aegis AI scanner (Muse Spark)

The AI layer for Aegis Guardian.

It runs the local rule engine first, then asks **Muse Spark** (Meta Model API, `muse-spark-1.3`) to read the message or a screenshot and explain the red flags in English or Spanish. Results come back as structured JSON: verdict, confidence, red flags with the exact evidence, and next steps.

## Run it

1. Get a key at [dev.meta.ai](https://dev.meta.ai).
2. Copy `.env.example` to `.env` in this folder and paste your key after `MODEL_API_KEY=`. `.env` is ignored by git, so the key never gets uploaded.
3. Start the app:

```bash
python3 app/ai/aegis_ai.py
```

Open <http://localhost:8787>. The page now shows an **AI check** and a **screenshot upload**.

From the terminal:

```bash
python3 app/ai/aegis_ai.py --text "Hi Mom, this is my new number..."
python3 app/ai/aegis_ai.py --image screenshot.png --lang es
```

## How the key stays safe

- The public page on GitHub Pages never calls the API. It only runs the local rules.
- The key is read on your computer by `aegis_ai.py` and sent only to `api.meta.ai`.
- The local server listens on `127.0.0.1` only and rejects requests from other websites, so a page you visit can't spend your credits.
- Requests are sent with `store: false`, and scanned messages aren't written to logs.

## Prompt-injection defense

Scam messages are untrusted input. The model is told to treat everything inside the message or screenshot as data and never follow instructions written there, and the output is locked to a JSON schema, so a message can't change what Aegis does.
