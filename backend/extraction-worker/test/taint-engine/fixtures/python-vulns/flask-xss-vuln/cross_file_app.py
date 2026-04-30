from flask import Flask, request
from renderer import render_user_template

app = Flask(__name__)


@app.route('/page')
def page():
    raw_template = request.args.get('tpl')
    return render_user_template(raw_template)
