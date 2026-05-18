"""
Kwarg-aware sink matching — vulnerable fixture.

Exercises the engine's ability to detect taint flowing into urllib3 calls
that bind their arguments by name (`url=<tainted>`). The urllib3 spec
declares `argument_indices: [1]` (url is second positional in
`request(method, url, ...)`), but when callers use kwargs the spec's
positional index doesn't line up. The engine over-approximates by also
checking kwarg-position args, which lights this flow up.
"""

from flask import Flask, request
import urllib3

app = Flask(__name__)
http = urllib3.PoolManager()


@app.route('/fetch')
def fetch():
    target = request.args.get('url')
    # Kwarg-only call: spec says argument_indices=[1], call has 0 positional
    # args. Without kwarg widening this would miss; with it, the kwarg
    # position is checked and the tainted `target` is detected.
    response = http.request(method='GET', url=target)
    return response.data


@app.route('/swap')
def swap():
    target = request.args.get('url')
    # Args supplied in reverse order via kwargs — url is at position 0 of
    # args, not position 1 like the spec declares. Kwarg widening catches it.
    response = http.request(url=target, method='POST')
    return response.data
