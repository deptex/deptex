from flask import Flask, request, make_response

app = Flask(__name__)


@app.route("/profile")
def profile():
    """CVE-2023-30861 — Flask <= 2.2.2 cookie cache leak.

    A response that pulls user-supplied data into the body and is then
    served behind a shared cache (no explicit Vary / Cache-Control private)
    can leak session cookies between users.
    """
    name = request.args.get("name", "anon")
    # Sink: build response body from user-controlled query param.
    resp = make_response(f"<h1>Hello {name}</h1>")
    return resp
