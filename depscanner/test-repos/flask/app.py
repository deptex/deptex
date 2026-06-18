"""Minimal Flask app with one reachable and one unreachable path-traversal sink."""

import os
from flask import Flask, request, send_from_directory
from werkzeug.utils import safe_join

from vuln_routes import vuln_bp

app = Flask(__name__)
app.register_blueprint(vuln_bp)

UPLOAD_DIR = "/var/data/uploads"


@app.route("/read")
def read_file():
    # REACHABLE: request.args.get('p') -> safe_join (vulnerable in werkzeug 0.15.3)
    # -> send_from_directory.
    name = request.args.get("p")
    safe = safe_join(UPLOAD_DIR, name)
    return send_from_directory(UPLOAD_DIR, os.path.basename(safe))


@app.route("/dump")
def internal_dump():
    # UNREACHABLE: the path is a server-side constant; no user taint reaches sink.
    fixed = safe_join(UPLOAD_DIR, "system-report.txt")
    return send_from_directory(UPLOAD_DIR, fixed)


if __name__ == "__main__":
    app.run()
