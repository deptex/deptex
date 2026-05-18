from flask import Flask, request
import requests

app = Flask(__name__)
session = requests.Session()


@app.route('/fetch')
def fetch():
    # Static URL, verify enabled — no taint reaches the sink.
    session.get('https://api.internal/status', verify=True)
    return 'ok'


@app.route('/proxy')
def proxy():
    url = 'https://api.internal/status'
    proxies = {'https': 'http://test:pass@localhost:8090'}
    req = requests.Request('GET', url)
    prep = req.prepare()
    session.rebuild_proxies(prep, proxies)
    return str('Proxy-Authorization' in prep.headers)
