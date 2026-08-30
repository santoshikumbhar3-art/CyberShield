# CyberShield

A zero-dependency web application that analyzes suspicious messages and URLs for phishing, scam, and social-engineering indicators, and returns an explainable risk score together with the specific reasoning behind it.

CyberShield does not use machine learning, an external API, or any third-party runtime package. Every check is a deterministic, auditable rule implemented in Python's standard library and served through plain, browser-native HTML, CSS, and JavaScript.

Built for the **Zero Dependency | 72-Hour Hackathon** (Hackathon Raptors).

---

## Overview

Someone receiving a suspicious SMS, WhatsApp message, or email is usually asked to make a fast decision with no tooling to help them. CyberShield gives that decision a second opinion: paste the content in, and get back a transparent 0–100 risk score, the exact indicators that produced it, and a plain-language explanation of what to do next — with every part of the answer traceable to a specific rule in the source code.

## Why CyberShield?

Detection tools built on opaque scoring or unexplained "AI" verdicts create a problem on top of the one they're trying to solve: the user still doesn't understand *why* something was flagged, so they can't build the judgment to catch the next attempt on their own. CyberShield is built around the opposite premise — a risk score is only useful if the reasoning behind it is visible and checkable, and a security tool built for a zero-dependency constraint should treat that constraint as a design opportunity, not a handicap.

## Problem

Phishing and scam messages rely on a recurring, learnable set of tactics — urgency, impersonation, credential requests, financial requests, unrealistic rewards — often paired with a link engineered to look legitimate at a glance. Recognizing these patterns under time pressure is difficult, and most people have no fast way to check a message's structure before acting on it.

## Solution

CyberShield runs submitted content through two independent rule-based analyzers (message text and URL structure), combines whatever they find into a single additive score, and then translates that score and its supporting evidence into language a non-technical user can act on immediately — without needing an internet connection, an API key, or any installed dependency beyond Python itself.

## Key Features

- **Message analysis** — scans message text for known manipulation-tactic phrase groups: urgency, threatening language, credential requests, financial requests, impersonation, unrealistic rewards, and suspicious instructions (e.g. "click this link").
- **URL structural analysis** — inspects a URL's scheme, host, and path for phishing-associated traits: missing HTTPS, a raw IP address as host, excessive subdomains, suspicious keywords, `@`-symbol tricks, percent-encoded characters, excessive hyphens, and risky top-level domains.
- **Embedded-link detection** — a URL found inside a message is automatically run through the same structural analysis, and contributes to that message's overall score.
- **Transparent, additive risk scoring** — every flagged indicator contributes a fixed, documented point value to a single 0–100 score. Nothing is randomized and nothing is estimated by a model; the same input always produces the same score.
- **Threat categorization** — an ordered rule set converts the combination of fired indicators into a human-readable category (e.g. "CREDENTIAL THEFT ATTEMPT", "SUSPICIOUS URL").
- **Dual explanations** — a plain-language summary and a technical summary are generated from the same underlying indicator list.
- **Recommended actions** — a short "avoid" / "do" list matched to the resulting risk level.
- **Input validation and safety limits** — empty input, oversized messages/URLs, and malformed URLs are rejected with a clear error rather than causing a crash or an unclear result.
- **No persistence** — submitted messages and URLs are analyzed in memory for the duration of the request and are not written to disk or a database.

## How It Works

```

User submits content (message or URL) via the browser UI
        ↓
analyzer.py / url_analyzer.py — rule-based detection
        ↓
threat_detector.py — combines indicators into one score
        ↓
ai_analyzer.py — contextual note over already-detected indicators
        ↓
explainer.py — plain-language + technical explanation, recommended actions
        ↓
main.py returns the combined JSON result; the browser renders it
```

## Detection Pipeline

1. The browser sends `{ type: "message" | "url", content: <string> }` to `POST /api/analyze`.
2. If `type` is `"message"`, `analyzer.py` lowercases the text and checks it against seven phrase-group indicator lists defined in `config.py`. Any URL embedded in the message is extracted with a regular expression and passed to `url_analyzer.py`.
3. If `type` is `"url"` (or a URL was extracted from a message), `url_analyzer.py` parses it with `urllib.parse` and evaluates ten structural indicators against it.
4. `threat_detector.py` sums the weight of every indicator that fired (message and URL) into one score capped at 100, derives a risk level from fixed thresholds, picks the most specific matching threat category, and derives a confidence label from how many distinct indicators fired.
5. `ai_analyzer.py` looks at which indicators fired together and returns a short, pre-written contextual sentence for that combination — it does not introduce any signal the rule-based engine didn't already detect.
6. `explainer.py` turns the score, category, and indicator list into a plain-language explanation, a technical explanation, and a risk-level-appropriate recommended-action list.
7. `main.py` serializes all of this into one JSON response; `web/app.js` renders it on the Results page.

## Message Analysis

`analyzer.py` checks message text against seven independent phrase groups: urgency, threatening language, credential requests, financial requests, impersonation, unrealistic rewards, and suspicious instructions. Each group is a list of literal phrases (defined in `config.py`); if any phrase in a group appears in the lowercased message, that tactic is marked as detected exactly once, regardless of how many phrases from the group matched. The module also extracts any URL-looking substrings from the message text for downstream URL analysis.

## URL Analysis

`url_analyzer.py` normalizes a raw URL (adding a scheme if the user pasted a bare domain), parses it with `urllib.parse`, and evaluates it against ten structural checks: HTTPS usage, a raw IP address as the host, an `@` symbol in the URL, subdomain count, overall length, phishing-associated keywords, unusual characters, percent-encoded characters, excessive hyphens in the host, and known risky top-level domains. The module deliberately never visits the URL — it reasons only about structure, and never claims a link is definitively safe or malicious.

## Risk Scoring

CyberShield's score is an additive rule model, not a statistical or machine-learned confidence value:

1. Each indicator that fires has a fixed point weight, defined once in `config.py`.
2. `threat_detector.py` sums the weights of every fired indicator (from both the message and URL analyzers) into a single total, capped at 100.
3. That total maps to a risk level — LOW, MEDIUM, HIGH, or CRITICAL — using fixed thresholds.
4. A separate count of how many distinct indicators fired determines a confidence label. This reflects how much evidence was found, not how certain the system is about intent.

The score, the evidence behind it, and the recommendation are kept as three distinct outputs on purpose: the score is a number, the evidence is the specific list of indicators that produced it, and the recommendation is a fixed action list keyed to the resulting risk level.

## Explainable Results

Every result exposes its own reasoning: the `contributing_indicators` list returned by the API names each fired indicator and its exact point contribution, so nothing about the score is hidden behind a single opaque number. The plain-language explanation and the technical explanation in `explainer.py` are both generated from that same list, and the `ai_analyzer.py` note only ever comments on indicators already present in it — it cannot introduce a justification the rule-based layer didn't produce.

## Architecture

| File | Responsibility |
|---|---|
| `main.py` | HTTP server (`http.server`, stdlib only); serves `web/` and handles `POST /api/analyze` |
| `analyzer.py` | Message text analysis — matches manipulation-tactic phrase groups, extracts embedded URLs |
| `url_analyzer.py` | URL structural analysis — HTTPS, IP-address hosts, subdomains, keywords, encoding, TLDs |
| `threat_detector.py` | Combines indicators into a single additive risk score, level, category, and confidence |
| `ai_analyzer.py` | Deterministic contextual-reasoning layer that synthesizes a short note from already-detected indicators |
| `explainer.py` | Produces the plain-language explanation, technical explanation, and recommended actions |
| `config.py` | All phrase lists, indicator weights, and thresholds, kept in one auditable place |
| `web/` | Static frontend — `index.html`, `style.css`, `app.js` |
| `tests/` | `unittest`-based tests for the analysis and scoring modules |

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
│   ├── index.html
│   ├── style.css
│   └── app.js
├── tests/
│   ├── test_analyzer.py
│   ├── test_url_analyzer.py
│   └── test_threat_detector.py
├── README.md
├── STDLIB.md
├── requirements.txt
├── .env.example
├── .gitignore
└── LICENSE

## Zero-Dependency Engineering

`requirements.txt` is empty, and no file in this project imports a third-party package — every backend import resolves to the Python standard library (`http.server`, `socketserver`, `json`, `urllib.parse`, `re`, `os`, `unittest`, `sys`), and the frontend uses only native browser APIs (`fetch`, DOM methods, CSS custom properties) with no build step, no CDN scripts, and no external fonts.

The constraint shaped the architecture directly rather than being worked around: `http.server` stands in for a framework like Flask or FastAPI, `urllib.parse` replaces URL-parsing utilities a package like `requests` or `tldextract` would normally provide, and `unittest` replaces `pytest` for the test suite. The scoring logic is deliberately kept as plain, additive arithmetic over labeled indicators, which needs nothing beyond what the standard library already provides.

**`ai_analyzer.py` note:** despite the filename, this module makes no network calls, requires no API key, and imports nothing beyond what's already in the standard library. It is a deterministic function that maps combinations of already-detected indicators to a pre-written explanatory sentence — it does not call a language model, and it is not machine learning. It exists to fulfill a contextual-reasoning role while remaining fully offline and dependency-free; it is not presented here as "AI-powered" in the sense of using a trained model.

## Standard Library

| Module | Used for |
|---|---|
| `http.server`, `socketserver` | The web server — serving static files and handling the analysis endpoint |
| `json` | Parsing request bodies and serializing API responses |
| `urllib.parse` | Breaking a URL into scheme, host, and path for structural analysis |
| `re` | Phrase matching, embedded-URL extraction, and character-pattern checks |
| `os` | Reading the `PORT` environment variable and resolving the static-file directory |
| `unittest`, `sys` | The test suite and its module path setup |

A full module-by-module breakdown, including which common third-party package each standard-library choice replaces, is in [STDLIB.md](STDLIB.md).

## Security & Privacy

- All user input (message text and URLs) is treated as untrusted data, not executable content — it is only ever pattern-matched and parsed, never evaluated or rendered as markup on the backend.
- URLs are parsed with `urllib.parse` rather than manual string splitting, to avoid the malformed-input edge cases naive parsing introduces.
- Message length, URL length, and total request-body size are all capped; oversized or empty input is rejected with a clear error rather than being processed.
- Malformed JSON, wrong-typed fields, and unknown analysis types return a structured error response instead of a server exception.
- Any unexpected internal error is caught and returns a generic message to the client — internal exception details and stack traces are never sent over the network.
- No submitted content is stored; each request is analyzed and discarded.
- CyberShield does not visit or fetch the URLs it analyzes — only their structure is inspected, so running an analysis never contacts a potentially malicious destination.
- No API key, credential, or environment variable beyond an optional `PORT` is required or read anywhere in the codebase.

## Limitations

- Detection is keyword- and heuristic-based, not machine-learned. It will miss scams that avoid the specific phrases in its rule set, and can flag legitimate messages that happen to use similar wording (e.g. a real bank's own app asking a user to "verify your account").
- URL analysis is structural only. It does not check domain reputation, registration age, redirect chains, or page content — none of which are available without visiting the link or querying an external service, both out of scope for a zero-dependency, offline-capable tool.
- The scoring model is additive and rule-based; it is not a statistical estimate of the probability that content is malicious, and its "confidence" value reflects how much evidence was found, not certainty of intent.
- Some internal strings carried over from earlier development (the server's startup log line and the browser page title) still read "CyberShield AI." This is a naming artifact, not a reflection of any added AI/ML functionality — the actual `ai_analyzer.py` behavior is described accurately above.
- CyberShield is an assistive analysis tool, not a security guarantee. It does not certify that any message or URL is safe, and it should not replace verifying sensitive requests through an organization's official channel.

## Installation

Requires Python 3.8 or later. There is no installation step — `requirements.txt` is empty and nothing needs to be fetched with `pip`.

```bash
git clone <your-repo-url>
cd CyberShield
```

## Running the Application

```bash
python main.py
```

Then open **http://localhost:8000** in a browser. The port can be overridden with the `PORT` environment variable, e.g. `PORT=9000 python main.py`.

## Usage

1. Open the app and go to the **Analyzer** page.
2. Choose **Message** or **URL**.
3. Paste the suspicious content.
4. Click **Analyze**.
5. Review the risk score, contributing indicators, and recommended actions on the **Results** page. Switch between **Simple Explanation** and **Technical Analysis** as needed.

## Testing

```bash
python -m unittest discover -s tests -v
```

The suite covers `analyzer.py`, `url_analyzer.py`, and `threat_detector.py`: normal input, a phishing-style message, an urgency-based scam, a credential-theft message, a suspicious URL, a normal URL, empty input, a malformed URL, deterministic score calculation, and score capping at 100. Coverage has not been formally measured.

## Hackathon Compliance

- **Zero-Dependency Craft (30%)** — `requirements.txt` is empty; every backend import is a standard-library module, verifiable directly in each file's `import` statements, and the frontend loads no external scripts, fonts, or CDN resources. `ai_analyzer.py` in particular makes no network calls despite its name.
- **Functionality & Usefulness (35%)** — the message and URL analyzers are fully working end to end, from the browser form through the API to a rendered result, covering the core phishing/scam-detection use case with real input validation and error handling.
- **Code Quality & Idiom (25%)** — responsibilities are split across single-purpose modules, all indicator weights and thresholds live in one auditable file (`config.py`), and the test suite runs with the standard-library `unittest` runner.
- **Innovation (10%)** — the project treats explainability itself as the feature rather than a byproduct: the scoring model is fully additive and inspectable, and the contextual-reasoning layer only ever comments on indicators the rule-based engine has already found, so the "why" behind every result is always traceable to a specific, readable rule rather than a model's internal state.
- **Reproducibility** — a single `python main.py` command starts the entire application locally with no build step, package installation, or configuration required; `python -m unittest discover -s tests -v` verifies the core logic independently of the server.

## Future Improvements

- Expanded, localized phrase sets for scam patterns common outside English-language messaging.
- A local, non-identifying analysis history using `sqlite3` (still standard-library) so a user could revisit past checks.
- Renaming the remaining "CyberShield AI" strings in the UI and server log to match the project's actual, non-AI-branded name.
- If external dependencies were ever permitted in a future version, `ai_analyzer.py` is the one module that could be swapped for a real language-model call without touching the rule-based detection or scoring logic, since it already sits behind the same interface.

## License

MIT License — see [LICENSE](LICENSE).
```
