from flask import Flask, request
from file_loader import read_user_file

app = Flask(__name__)


@app.route('/download')
def download():
    name = request.args.get('name')
    return read_user_file(name)
