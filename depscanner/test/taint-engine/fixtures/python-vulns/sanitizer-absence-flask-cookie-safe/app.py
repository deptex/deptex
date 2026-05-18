"""
Sanitizer-absence — safe fixture (Flask cookie security hardened).

Hardened equivalent of the vuln fixture: `secure=True` and
`httponly=True` are both set, so neither forbidden-literal contract
fires.
"""

from flask import Flask, make_response

app = Flask(__name__)


@app.route('/login')
def login():
    response = make_response('logged in')
    response.set_cookie('session', 'abc123', secure=True, httponly=True)
    return response
