# CyberShield

A zero-dependency web application that analyzes suspicious messages and URLs for phishing, scam, and social-engineering indicators, and returns an explainable risk score together with the specific reasoning behind it.

CyberShield does not use machine learning, external threat-intelligence feeds, or any third-party runtime package. Every check is a deterministic, auditable rule implemented in Python's standard library and served through plain, browser-native HTML, CSS, and JavaScript.

Built for the **Zero Dependency | 72-Hour Hackathon** (Hackathon Raptors).

---

## Overview

Someone receiving a suspicious SMS, WhatsApp message, or email is usually asked to make a fast decision with no tooling to help them. CyberShield gives that decision a second opinion: paste the content in, and get back a transparent 0–100 risk score, the exact indicators that produced it, and a plain-language explanation of what to do next — with every part of that answer traceable to a specific rule in the source code.

## The Problem

Phishing and scam messages rely on a recurring, learnable set of tactics — urgency, impersonation, credential requests, financial requests, unrealistic rewards — often paired with a link engineered to look legitimate at a glance. Recognizing these patterns under time pressure is difficult, and most people have no fast way to check a message's structure before acting on it.

Detection tools built on opaque scoring or unexplained "AI" verdicts create a second problem on top of the first: the user still doesn't understand *why* something was flagged, so they can't build the judgment to catch the next one on their own. CyberShield is built around the opposite premise — a risk score is only useful if the reasoning behind it is visible and checkable.

## Key Features

- **Message analysis** — scans message text for known manipulation-tactic phrase groups: urgency, threatening language, credential requests, financial requests, impersonation, unrealistic rewards, and suspicious instructions (e.g. "click this link").
- **URL structural analysis** — inspects a URL's scheme, host, and path for phishing-associated structural traits: missing HTTPS, a raw IP address as host, excessive subdomains, suspicious keywords, `@`-symbol tricks, percent-encoded characters, excessive hyphens, and risky top-level domains.
- **Embedded-link detection** — if a message contains a URL, that URL is automatically run through the same structural analysis, and a suspicious link inside a message contributes to the message's overall score.
- **Transparent, additive risk scoring** — every flagged indicator contributes a fixed, documented point value to a single 0–100 score. Nothing is randomized and nothing is estimated by a model; the same input always produces the same score.
- **Threat categorization** — a simple, ordered rule set converts the combination of fired indicators into a human-readable category (e.g. "CREDENTIAL THEFT ATTEMPT", "SUSPICIOUS URL").
- **Dual explanations** — a plain-language summary and a technical summary are generated from the same underlying indicator list, so a non-technical user and a more technical one both get an answer they can use.
- **Recommended actions** — a short "avoid" / "do" list matched to the resulting risk level.
- **Input validation and safety limits** — empty input, oversized messages/URLs, and malformed URLs are rejected with a clear error rather than causing a crash or an unclear result.
- **No persistence** — submitted messages and URLs are analyzed in memory for the duration of the request and are not written to disk or a database.

## How It Works

User submits content (message or URL) via the browser UI
↓
analyzer.py — scans message text against phrase-group rules (if type = message)
url_analyzer.py — inspects URL structure (submitted directly, or extracted from a message)
↓
threat_detector.py — sums the weights of every fired indicator into one score,
derives a risk level, threat category, and confidence
↓
ai_analyzer.py — synthesizes a short contextual note describing which
combination of already-detected indicators is present
↓
explainer.py — turns the score and indicators into a simple explanation,
a technical explanation, and a recommended-action list
↓
main.py serves the combined JSON result to the browser, which renders
the risk score, indicators, explanations, and actions on the Results page


## Risk Analysis

CyberShield's score is a simple additive model, not a statistical or machine-learned confidence value:

1. Each analysis module (`analyzer.py`, `url_analyzer.py`) evaluates the input against a fixed list of independent boolean indicators (e.g. "does this message ask for a password?").
2. Each indicator that fires has a fixed point weight, defined in `config.py`.
3. `threat_detector.py` sums the weights of every fired indicator into a single total, capped at 100.
4. That total maps to a risk level — LOW, MEDIUM, HIGH, or CRITICAL — using fixed thresholds.
5. A separate, unweighted count of how many distinct indicators fired determines a confidence label (LOW/MEDIUM/HIGH) — this reflects how much evidence was found, not how certain the system is that the content is malicious.

The score, the evidence behind it, and the recommendation are kept as three distinct outputs on purpose: the **score** is a number, the **evidence** is the specific list of indicators that produced it, and the **recommendation** is a fixed action list keyed to the resulting risk level. None of the three is used to quietly justify the others.

## Example

**Input (message):**

> "URGENT: Your bank account will be blocked today. Verify your account immediately by clicking this link and confirm your password. http://192.168.1.1/secure-login"

**Resulting analysis (illustrative of the application's actual behavior, not a measured accuracy statistic):**

- Score: **100 / 100** (capped)
- Risk level: **CRITICAL**
- Category: **CREDENTIAL THEFT ATTEMPT**
- Confidence: **HIGH** (8 distinct indicators fired)
- Contributing indicators include: creates artificial urgency, uses threatening/alarming language, requests passwords/PINs/identity verification, pushes toward a link, contains a suspicious link, uses a raw IP address instead of a domain name, does not use HTTPS, contains phishing-associated keywords
- Recommended action: don't click the link, don't enter a password/PIN/OTP, verify through an official channel you already trust

## Architecture

| File | Responsibility |
|---|---|
| `main.py` | HTTP server (`http.server`, stdlib only); serves `web/` and handles `POST /api/analyze` |
| `analyzer.py` | Message text analysis — matches manipulation-tactic phrase groups, extracts embedded URLs |
| `url_analyzer.py` | URL structural analysis — HTTPS, IP-address hosts, subdomains, keywords, encoding, TLDs |
| `threat_detector.py` | Combines indicators into a single additive risk score, level, category, and confidence |
| `ai_analyzer.py` | Deterministic contextual-reasoning layer that synthesizes a short note from already-detected indicators |
| `explainer.py` | Produces the plain-language explanation, technical explanation, and recommended actions |
| `config.py` | All phrase lists, indicator weights, and thresholds, kept in one place |
| `web/` | Static frontend — `index.html`, `style.css`, `app.js` |
| `tests/` | `unittest`-based tests for the analysis and scoring modules |

## Zero-Dependency Engineering

`requirements.txt` in this repository is empty. No file in the project imports a third-party package — every backend import resolves to the Python standard library, and the frontend uses only native browser APIs with no build step, no CDN scripts, and no external fonts.

This wasn't a constraint applied after the fact — it shaped the architecture directly: `http.server` stands in for a framework like Flask, and the risk-scoring logic is deliberately kept as plain, additive arithmetic over labeled indicators rather than anything that would call for a data-science or ML library. The engineering bet here is that a large share of what a phishing-detection tool actually needs — pattern matching, URL parsing, an HTTP endpoint, and a test runner — is already fully served by the standard library, without pulling in a dependency tree to get there.

## Standard Library

| Module | Used for |
|---|---|
| `http.server`, `socketserver` | The web server itself — serving static files and handling the analysis endpoint |
| `json` | Parsing request bodies and serializing API responses |
| `urllib.parse` | Breaking a URL into scheme, host, and path for structural analysis |
| `re` | Phrase matching, embedded-URL extraction, and character-pattern checks |
| `os` | Reading the `PORT` environment variable and resolving the static-file directory |
| `unittest` | The test suite |

A full module-by-module breakdown, including which common third-party package each standard-library choice replaces, is in [STDLIB.md](STDLIB.md).

## Security Considerations

- All user input (message text and URLs) is treated as untrusted data, not executable content — it is only ever pattern-matched and parsed, never evaluated or rendered as markup on the backend.
- URLs are parsed with `urllib.parse` rather than manual string splitting, to avoid the malformed-input edge cases naive parsing introduces.
- Message length, URL length, and total request-body size are all capped; oversized or empty input is rejected with a clear error rather than being processed.
- Malformed JSON, wrong-typed fields, and unknown analysis types return a structured error response instead of a server exception.
- Any unexpected internal error is caught and returns a generic message to the client — internal exception details and stack traces are never sent over the network.
- No submitted content is stored; each request is analyzed and discarded.
- CyberShield does not visit or fetch the URLs it analyzes — only their structure is inspected, so analysis itself never contacts a potentially malicious destination.

## Limitations

- Detection is keyword- and heuristic-based, not machine-learned. It will miss scams that avoid the specific phrases in its rule set, and can flag legitimate messages that happen to use similar wording (e.g. a real bank's own app asking a user to "verify your account").
- URL analysis is structural only. It does not check domain reputation, registration age, redirect chains, or page content, none of which are available without visiting the link or querying an external service — both of which are out of scope for a zero-dependency, offline-capable tool.
- The scoring model is additive and rule-based; it is not a statistical estimate of the probability that content is malicious, and its "confidence" value reflects how much evidence was found, not certainty of intent.
- CyberShield is an assistive analysis tool, not a security guarantee. It does not certify that any message or URL is safe, and it should not replace verifying sensitive requests through an organization's official channel.

## Installation

Requires Python 3.8 or later. There is no installation step — `requirements.txt` is empty and nothing needs to be fetched with `pip`.

```bash
git clone <your-repo-url>
cd CyberShield
```

## Usage

```bash
python main.py
```

Then open **http://localhost:8000** in a browser (the port can be changed with the `PORT` environment variable). From the Analyzer page, choose Message or URL, paste the content, and click Analyze. The Results page shows the score, category, contributing indicators, both explanations, and the recommended actions.

## Testing

```bash
python -m unittest discover -s tests -v
```

The suite covers `analyzer.py`, `url_analyzer.py`, and `threat_detector.py`: normal input, a phishing-style message, an urgency-based scam, a credential-theft message, a suspicious URL, a normal URL, empty input, a malformed URL, deterministic score calculation, and score capping at 100. Coverage has not been formally measured.

## Project Structure

CyberShield/
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


## Hackathon Compliance

This project targets the Zero Dependency challenge directly:

- **Zero-Dependency Craft** — `requirements.txt` is empty; every backend import is a standard-library module (verifiable directly in each file's `import` statements), and the frontend loads no external scripts, fonts, or CDN resources.
- **Functionality & Usefulness** — the message and URL analyzers are fully working end to end, from the browser form through the API to a rendered result, covering the core phishing/scam-detection use case.
- **Code Quality & Idiom** — responsibilities are split across single-purpose modules (`analyzer.py`, `url_analyzer.py`, `threat_detector.py`, `explainer.py`), all indicator weights and thresholds live in one auditable file (`config.py`), and the test suite runs with the standard-library `unittest` runner.
- **Innovation** — rather than treating "no dependencies" as a constraint to work around, the project treats explainability itself as the feature: the scoring model is fully additive and inspectable, and the contextual-reasoning layer only ever comments on indicators the rule-based engine has already found, so the "why" behind every result is always traceable to a specific, readable rule.
- **Reproducibility** — a single `python main.py` command starts the entire application locally with no build step, package installation, or configuration required.

## Design Philosophy

CyberShield favors a small number of transparent, testable rules over a larger surface of dependencies or opaque model behavior. Every risk score can be explained by pointing at the specific line of source code that produced it, every module has one clear responsibility, and the project runs the same way on any machine with Python installed — nothing to fetch, nothing to configure, nothing hidden.

## License

MIT License — see [LICENSE](LICENSE).
