from flask import Flask, request
from services.renderer import render_user_greeting
from services.audit import audit_request

app = Flask(__name__)


@app.route('/render')
def render_view():
    username = request.args.get('user')
    audit_request(request)
    return render_user_greeting(username)
