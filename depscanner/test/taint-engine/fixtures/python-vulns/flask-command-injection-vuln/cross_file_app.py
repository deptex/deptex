from flask import Flask, request
from runner import run_shell

app = Flask(__name__)


@app.route('/exec')
def do_exec():
    user_cmd = request.args.get('cmd')
    return run_shell("echo " + user_cmd)
