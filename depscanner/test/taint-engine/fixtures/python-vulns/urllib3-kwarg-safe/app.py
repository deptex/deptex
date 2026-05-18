"""
Kwarg-aware sink matching — safe fixture.

Same call shapes as the -vuln counterpart, but the url/method kwargs bind
to constants instead of attacker-controlled values. Must emit ZERO ssrf
flows; if the kwarg widening becomes too aggressive (e.g. ignoring local
taint state and tagging every kwarg-bearing call), this fixture will
light up and the safe-fixture gate fails.
"""

from flask import Flask, request
import urllib3

app = Flask(__name__)
http = urllib3.PoolManager()

INTERNAL_URL = 'https://api.internal/status'


@app.route('/fetch')
def fetch():
    # No taint reaches any kwarg — `target` is read from the source, then
    # NOT used as a kwarg value. Constants bind by name.
    target = request.args.get('url')
    _ = target  # silence unused
    response = http.request(method='GET', url=INTERNAL_URL)
    return response.data


@app.route('/swap')
def swap():
    response = http.request(url=INTERNAL_URL, method='POST')
    return response.data
