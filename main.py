"""
main.py
-------
What this is: the entry point of CyberShield AI. Running this one file
starts a small web server that (1) serves the website in web/ and
(2) handles the /api/analyze endpoint the page calls when you click
"Analyze".

Why it's built this way: the hackathon rules require zero third-party
dependencies, so instead of Flask/FastAPI we use Python's built-in
http.server module. It's less convenient than a framework, but it is
100% standard library — nothing to install, ever.

How to run it:
    python main.py
Then open http://localhost:8000 in your browser.

No external packages — only Python's standard library.
"""

import json
import os
import socketserver
import http.server
from urllib.parse import urlparse

from analyzer import analyze_message
from url_analyzer import analyze_url
from threat_detector import evaluate
from ai_analyzer import generate_ai_note
from explainer import build_explanation

PORT = int(os.environ.get("PORT", 8000))
WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")


def run_full_analysis(analysis_type: str, content: str) -> dict:
    """
    Run the complete pipeline for one submission:
      rule-based analysis -> risk scoring -> contextual "AI" note -> explanation

    analysis_type: "message" or "url"
    content: the raw text the user submitted
    """
    message_result = None
    url_result = None

    if analysis_type == "message":
        message_result = analyze_message(content)
        if not message_result["valid"]:
            return {"ok": False, "error": message_result["error"]}

        # If the message contains a URL, analyze the first one found too —
        # a suspicious link inside a message is itself strong evidence.
        if message_result["urls_found"]:
            url_result = analyze_url(message_result["urls_found"][0])

    elif analysis_type == "url":
        url_result = analyze_url(content)
        if not url_result["valid"]:
            return {"ok": False, "error": url_result["error"]}

    else:
        return {"ok": False, "error": "Unknown analysis type."}

    verdict = evaluate(message_result=message_result, url_result=url_result)

    message_indicators = (message_result or {}).get("indicators", {})
    url_indicators = (url_result or {}).get("indicators", {})
    ai_note = generate_ai_note(message_indicators, url_indicators)

    explanation = build_explanation(verdict, ai_note)

    return {
        "ok": True,
        "type": analysis_type,
        "score": verdict["score"],
        "level": verdict["level"],
        "category": verdict["category"],
        "confidence": verdict["confidence"],
        "contributing_indicators": verdict["contributing_indicators"],
        "simple_explanation": explanation["simple"],
        "technical_explanation": explanation["technical"],
        "ai_context": explanation["ai_context"],
        "recommended_actions": explanation["recommended_actions"],
        "urls_found": (message_result or {}).get("urls_found", []),
    }


class CyberShieldHandler(http.server.SimpleHTTPRequestHandler):
    """
    Handles two kinds of requests:
      - GET  /            -> serves static files from web/
      - POST /api/analyze -> runs the analysis pipeline and returns JSON
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)

    def log_message(self, fmt, *args):
        # Quieter, single-line request logging instead of the default format.
        print(f"[{self.address_string()}] {fmt % args}")

    def _send_json(self, status: int, payload: dict):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        parsed = urlparse(self.path)

        if parsed.path != "/api/analyze":
            self._send_json(404, {"ok": False, "error": "Not found."})
            return

        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length <= 0 or content_length > 200_000:
                self._send_json(400, {"ok": False, "error": "Invalid request size."})
                return

            raw_body = self.rfile.read(content_length)
            data = json.loads(raw_body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self._send_json(400, {"ok": False, "error": "Malformed request."})
            return

        analysis_type = data.get("type", "")
        content = data.get("content", "")

        if not isinstance(analysis_type, str) or not isinstance(content, str):
            self._send_json(400, {"ok": False, "error": "Malformed request."})
            return

        try:
            result = run_full_analysis(analysis_type, content)
        except Exception as exc:  # noqa: BLE001 - last-resort safety net
            # Never leak internal stack traces or details to the client.
            print(f"Internal error during analysis: {exc}")
            self._send_json(500, {
                "ok": False,
                "error": "Something went wrong while analyzing. Please try again.",
            })
            return

        status = 200 if result.get("ok") else 400
        self._send_json(status, result)

    def do_GET(self):
        # Let SimpleHTTPRequestHandler serve everything under web/ as-is.
        super().do_GET()


def main():
    with socketserver.TCPServer(("0.0.0.0", PORT), CyberShieldHandler) as httpd:
        print(f"CyberShield AI running at http://localhost:{PORT}")
        print("Press Ctrl+C to stop.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down CyberShield AI.")


if __name__ == "__main__":
    main()