import shlex
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route('/ping')
def ping():
    host = request.args.get('host')
    safe_host = shlex.quote(host)
    return subprocess.check_output("ping -c 1 " + safe_host, shell=True)


@app.route('/run')
def run():
    cmd = request.args.get('cmd')
    # Numeric coercion is the wrong sanitizer for cmd, so use shlex.split.
    parts = shlex.split(cmd)
    # Pass argv list — without shell=True the value is not interpreted by a shell.
    return subprocess.check_output(parts)
