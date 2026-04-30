import os
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route('/ping')
def ping():
    host = request.args.get('host')
    # Direct shell with concatenated user input.
    return os.system("ping -c 1 " + host)


@app.route('/run')
def run():
    cmd = request.args.get('cmd')
    return subprocess.check_output(cmd, shell=True)
