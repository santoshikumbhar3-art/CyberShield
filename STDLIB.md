# STDLIB.md

CyberShield AI is built with **zero third-party dependencies**. Every piece
of backend functionality uses Python's standard library only, and the
frontend uses plain, browser-native HTML/CSS/JavaScript with no frameworks,
build tools, or CDN-hosted scripts.

This document lists every standard-library module used, what it does in
this project, and which common third-party dependency it replaces.

## Python Standard Library Modules Used

| Module | Used in | What it does here | Common dependency it replaces |
|---|---|---|---|
| `http.server` | `main.py` | Serves static web files and handles the `/api/analyze` endpoint | Flask, FastAPI, Express |
| `socketserver` | `main.py` | Provides the TCP server that `http.server` runs on | uvicorn / gunicorn (app server) |
| `json` | `main.py` | Parses incoming request bodies and serializes API responses | — (json is stdlib, no replacement needed, but frameworks like Flask often wrap it) |
| `urllib.parse` | `main.py`, `url_analyzer.py` | Parses URLs into scheme/host/path components; parses query strings from request paths | `requests` (for URL parsing utilities), `tldextract` |
| `re` | `analyzer.py`, `url_analyzer.py` | Regex matching to find embedded URLs in messages and detect suspicious character patterns | — (re is stdlib) |
| `os` | `main.py` | Reads the `PORT` environment variable and resolves the web directory path | `python-dotenv` |
| `unittest` | `tests/*.py` | Test framework: test discovery, assertions, test runner | `pytest` |
| `sys` | `tests/*.py` | Adjusts `sys.path` so tests can import project modules without installation/packaging | `pytest` (auto path handling), `setuptools` (editable installs) |

## Frontend

| Technology | Used in | Replaces |
|---|---|---|
| Native `fetch()` API | `web/app.js` | `axios`, `jQuery.ajax` |
| Native DOM APIs (`querySelector`, `addEventListener`, `createElement`) | `web/app.js` | React, Vue, jQuery |
| CSS custom properties (`:root { --var }`) | `web/style.css` | Sass/Less variables, CSS-in-JS, Tailwind |
| System font stack (`-apple-system`, `ui-monospace`, etc.) | `web/style.css` | Google Fonts / CDN-hosted web fonts |

## Why this matters

Every replacement above was a deliberate choice, not an oversight:

- **No package manager files are needed.** `requirements.txt` is
  intentionally empty — running `python main.py` requires nothing beyond
  a standard Python 3 installation.
- **No CDN calls at runtime.** The app has zero external network
  dependencies once running, including no external font or script loads,
  so it works fully offline (useful for demoing on unreliable wifi).
- **Nothing here is a hidden reimplementation of a banned package.** The
  rule-based detection engine (`analyzer.py`, `url_analyzer.py`,
  `threat_detector.py`) and the contextual reasoning layer
  (`ai_analyzer.py`) are original logic, not a vendored copy of an
  external library.