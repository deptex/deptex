"""
Sanitizer-absence — vulnerable fixture (CVE-2024-35195 shape).

The application calls `requests.get(..., verify=False)` from a Flask
handler. Disabling TLS verification on a session that ships sensitive
data is the underlying weak-crypto failure. The non-taint detector
regime fires from the `required_arguments` contract on `requests.get`
in flask.yaml regardless of whether the URL is tainted.
"""

from flask import Flask, request
import requests

app = Flask(__name__)


@app.route('/fetch')
def fetch():
    url = request.args.get('url')
    resp = requests.get(url, verify=False)
    return resp.text
