from flask import Flask, request
import urllib3

app = Flask(__name__)
http = urllib3.PoolManager()


@app.route('/fetch')
def fetch():
    # Static URL, no taint.
    response = http.request('GET', 'https://api.internal/status', headers={'Cookie': 'session=secret'})
    return response.data


@app.route('/raw')
def raw():
    # Static method, no taint.
    conn = urllib3.HTTPConnection('example.com')
    conn.putrequest('GET', '/test')
    return 'done'
