"""
Sanitizer-absence — safe fixture (CVE-2024-35195 hardened).

Equivalent flow but TLS verification is left at its safe default
(verify omitted = True). The non-taint detector regime emits no
finding because the `verify=False` forbidden-literal contract is
not triggered.

Note: the same call still routes a tainted URL into `requests.get`,
so the SSRF taint flow may still fire — but the validate script
counts findings by *class*, and the sanitizer-absence path tracks
weak_crypto / auth_bypass, not ssrf. We use vuln_class slug
`weak-crypto` on the parent dir to scope the assertion.
"""

from flask import Flask, request
import requests

app = Flask(__name__)


@app.route('/fetch')
def fetch():
    url = request.args.get('url')
    resp = requests.get(url)
    return resp.text
