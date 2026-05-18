from flask import Flask, request
import requests

app = Flask(__name__)
session = requests.Session()


@app.route('/fetch')
def fetch():
    target = request.args.get('url')
    # CVE-2024-35195 shape — Session reused after verify=False keeps
    # cert verification disabled across subsequent requests.
    session.get(target, verify=False)
    return 'ok'


@app.route('/proxy')
def proxy():
    url = request.args.get('url')
    # CVE-2023-32681 shape — tainted URL flows into Session.rebuild_proxies
    # where Proxy-Authorization can leak across redirects.
    proxies = {'https': 'http://test:pass@localhost:8090'}
    req = requests.Request('GET', url)
    prep = req.prepare()
    session.rebuild_proxies(prep, proxies)
    return str('Proxy-Authorization' in prep.headers)
