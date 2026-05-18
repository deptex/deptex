from flask import Flask, request
import urllib3

app = Flask(__name__)
http = urllib3.PoolManager()


@app.route('/fetch')
def fetch():
    target = request.args.get('url')
    # CVE-2023-43804 shape — tainted URL flows into PoolManager.request
    # while a sensitive Cookie header rides along on the redirect.
    response = http.request('GET', target, headers={'Cookie': 'session=secret'})
    return response.data


@app.route('/raw')
def raw():
    method = request.args.get('method')
    # CVE-2020-26137 shape — tainted method name flows into HTTPConnection.putrequest
    # where it gets CRLF-spliced into the request line.
    conn = urllib3.HTTPConnection('example.com')
    conn.putrequest(method, '/test')
    return 'done'
