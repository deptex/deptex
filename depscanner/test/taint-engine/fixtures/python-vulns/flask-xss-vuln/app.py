from flask import Flask, request, render_template_string
from markupsafe import Markup

app = Flask(__name__)


@app.route('/hello')
def hello():
    name = request.args.get('name')
    template = "<h1>Hello " + name + "</h1>"
    return render_template_string(template)


@app.route('/profile')
def profile():
    bio = request.args.get('bio')
    safe_bio = Markup(bio)
    return "<div>" + str(safe_bio) + "</div>"
