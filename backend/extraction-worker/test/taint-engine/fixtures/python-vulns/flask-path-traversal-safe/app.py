from flask import Flask, request
from file_loader import read_user_file

app = Flask(__name__)


@app.route('/download')
def download():
    raw_name = request.args.get('name')
    safe_name = _basename(raw_name)
    return read_user_file(safe_name)


def _basename(name):
    import os.path
    return os.path.basename(name)
