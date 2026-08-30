# 🛡️ CyberShield AI

An AI-powered digital safety assistant that analyzes suspicious messages
and URLs, explains why they're risky in plain language, and tells you
what to do next — built with **zero third-party dependencies**.

> Built for **BYAMN Buildathon 2026** (solo submission).

---

## Problem

Phishing and scam messages are engineered to make people act fast, before
they have time to think. Most people don't have a cybersecurity
background, and by the time something "feels off," they may have already
clicked a link or shared a password.

## Solution

CyberShield AI gives anyone a fast, explainable second opinion. Paste a
suspicious message or link, and get back:

- a transparent **0–100 risk score**
- a **risk level** (LOW / MEDIUM / HIGH / CRITICAL)
- a **threat category** (e.g. Phishing, Credential Theft Attempt)
- the **specific indicators** that were detected, and how many points
  each contributed
- a **plain-language explanation** ("Explain Like I'm 15") and a
  **technical explanation**, side by side
- **recommended actions** — what to avoid, and what to do instead

## Features

- **Message Analyzer** — checks SMS, WhatsApp, email, and social-media
  text for urgency, threats, credential requests, financial requests,
  impersonation, unrealistic rewards, and suspicious instructions.
- **URL Analyzer** — inspects a link's structure (HTTPS usage, raw IP
  hosts, excessive subdomains, suspicious keywords, `@` tricks, encoded
  characters, risky TLDs) without ever visiting the link.
- **Transparent risk scoring** — every point in the score is traceable to
  a specific, labeled indicator. Nothing is randomized.
- **Explain Like I'm 15** — a simple explanation and a technical
  breakdown, switchable with one click.
- **Graceful degradation** — the contextual reasoning layer has no
  external dependency, so the system is never "down"; if a message shows
  no indicators, CyberShield AI says so plainly rather than guessing.

## Demo

_Add your 5-minute demo video link here before submission._

## How It Works

User submits content (message or URL)
↓
Security engine scans for indicators (analyzer.py / url_analyzer.py)
↓
Contextual reasoning layer interprets the combination (ai_analyzer.py)
↓
Risk engine combines every signal into one score (threat_detector.py)
↓
Explanation layer generates simple + technical text (explainer.py)
↓
Results screen: score, category, indicators, explanations, actions


The system is layered on purpose: **rules + structural analysis** always
run and always produce a defensible score; the **contextual reasoning**
layer only adds interpretation on top of what the rules already found —
it never introduces a signal the rule-based engine didn't detect. This
means the whole system keeps working even if any one layer were to be
disabled.

## Architecture

| File | Responsibility |
|---|---|
| `main.py` | HTTP server (stdlib `http.server`), routes `/api/analyze`, serves `web/` |
| `analyzer.py` | Message text analysis — detects manipulation-tactic keyword groups |
| `url_analyzer.py` | URL structure analysis — HTTPS, IP hosts, subdomains, keywords, etc. |
| `threat_detector.py` | Combines indicators into a transparent 0–100 risk score |
| `ai_analyzer.py` | Deterministic contextual reasoning layer ("AI analysis") |
| `explainer.py` | Generates simple/technical explanations and recommended actions |
| `config.py` | All keyword lists, weights, and thresholds in one auditable place |
| `web/` | Static frontend: `index.html`, `style.css`, `app.js` |
| `tests/` | Unit tests (`unittest`) for each analysis module |

## Technology

Python 3 standard library only on the backend, plain HTML/CSS/JavaScript
on the frontend. No frameworks, no SDKs, no npm packages, no CDN-hosted
scripts or fonts. See [STDLIB.md](STDLIB.md) for the full module-by-module
breakdown of what standard-library tools replace which common
dependencies.

## Installation

Requires Python 3.8 or later. No installation step is needed — there are
no packages to install.

```bash
git clone <your-repo-url>
cd CyberShield-AI
```

## One-Command Run

```bash
python main.py
```

Then open **http://localhost:8000** in your browser.

To use a different port:

```bash
PORT=9000 python main.py
```

## Usage

1. Open the app and go to **Analyzer**.
2. Choose **Message** or **URL**.
3. Paste the suspicious content.
4. Click **Analyze**.
5. Review the risk score, indicators, and recommended actions on the
   **Results** page. Switch between **Simple Explanation** and
   **Technical Analysis** as needed.

## Testing

Run all tests:

```bash
python -m unittest discover -s tests -v
```

Test coverage includes: a normal message, a phishing message, an urgent
scam, a credential-theft message, a suspicious URL, a normal URL, empty
input, a malformed URL, deterministic risk-score calculation, and score
capping at 100.

## Security

- No API keys are used or required by this build (the "AI analysis"
  layer is a local, deterministic reasoning module — see
  [STDLIB.md](STDLIB.md) and `ai_analyzer.py` for why).
- `.env.example` is included as a placeholder for any future environment
  variables; it contains no real values and should never be filled with
  real secrets in a committed file.
- Submitted messages and URLs are **not stored** anywhere — each request
  is analyzed in memory and discarded.
- All errors are caught and shown as friendly messages; internal stack
  traces and exception details are never sent to the client (see
  `main.py`'s `do_POST` error handling).
- Input length is capped (5,000 characters for messages, 2,048 for URLs,
  200 KB per request body) to prevent oversized submissions from causing
  problems.

## Responsible AI

CyberShield AI is built around one principle: **never claim certainty it
doesn't have.**

- URL verdicts always use cautious language ("potentially suspicious,"
  "high-risk indicators detected") — never "this is safe" or "this is
  definitely malicious."
- The risk score is a transparent sum of weighted, labeled indicators —
  every number can be explained.
- A LOW score or empty indicator list is explicitly described as "no
  known patterns detected," not as a safety guarantee.
- The app includes a persistent disclaimer: CyberShield AI provides risk
  assessment and educational guidance, not a verified safety
  determination. Always verify sensitive requests through official
  channels.

## Project Structure

CyberShield-AI/
├── main.py
├── analyzer.py
├── url_analyzer.py
├── threat_detector.py
├── ai_analyzer.py
├── explainer.py
├── config.py
├── web/
│ ├── index.html
│ ├── style.css
│ └── app.js
├── tests/
│ ├── test_analyzer.py
│ ├── test_url_analyzer.py
│ └── test_threat_detector.py
├── README.md
├── STDLIB.md
├── requirements.txt
├── .env.example
├── .gitignore
└── LICENSE


## Limitations

- Detection is **keyword and heuristic based**, not machine-learned — it
  will miss cleverly worded scams that avoid known phrases, and can
  occasionally flag legitimate messages that happen to use similar
  wording (e.g. a real bank asking you to "verify your account" through
  its own official app).
- The URL analyzer inspects structure only; it does not visit links, so
  it cannot detect malicious page content, redirects, or newly
  registered domains that otherwise look structurally normal.
- The screenshot/OCR analyzer described in early planning was
  **descoped**: reliable OCR requires a third-party dependency (e.g.
  Pillow + an OCR engine), which conflicts with the zero-dependency
  requirement for this build.
- The "AI analysis" layer is a deterministic rule-based reasoning module,
  not a general-purpose language model — it synthesizes explanations from
  already-detected indicators rather than reasoning freely over arbitrary
  text.

## Future Improvements

- Optional integration with a real LLM API for freer-form contextual
  analysis, if external dependencies are permitted in a future version.
- Screenshot upload with OCR, once an approved OCR dependency is
  available.
- A local, non-identifying analysis history (e.g. via `sqlite3`, still
  stdlib-only) so users can revisit past checks.
- Expanded, localized keyword sets for scam patterns common outside
  English-language messaging.

## Hackathon Disclosure

This project was developed with the assistance of Claude (Anthropic) as
an AI pair-programmer for code generation, architecture planning, and
documentation, used throughout development per BYAMN Buildathon 2026
disclosure requirements. All functional claims in this README were
verified by running the application and its test suite.

---

*CyberShield AI provides risk assessment and educational guidance. It
does not guarantee that a website, message, or sender is safe or
malicious. Always verify sensitive requests through official channels.*
