"""
Sanitizer-absence — vulnerable fixture (Flask cookie security shape;
CVE-2023-30861-class).

The handler issues a session-token cookie via `response.set_cookie`
WITHOUT `secure=True` and WITHOUT `httponly=True`, exposing the
session ID over plaintext HTTP and to client-side JavaScript. The
non-taint detector regime fires twice (one finding per forbidden
literal contract) — the validate harness only requires >= 1.
"""

from flask import Flask, make_response

app = Flask(__name__)


@app.route('/login')
def login():
    response = make_response('logged in')
    response.set_cookie('session', 'abc123', secure=False, httponly=False)
    return response
