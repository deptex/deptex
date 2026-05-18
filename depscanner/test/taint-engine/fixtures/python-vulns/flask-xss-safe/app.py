from flask import Flask, request, render_template_string
from markupsafe import escape

app = Flask(__name__)


@app.route('/hello')
def hello():
    name = request.args.get('name')
    safe_name = escape(name)
    # The escaped value passed in is safe; render_template_string still uses a
    # static template so the only attacker influence is through the escaped
    # variable, which is clean.
    return render_template_string("<h1>Hello {{ name }}</h1>", name=safe_name)


@app.route('/profile')
def profile():
    bio = request.args.get('bio')
    # html.escape wraps the value with HTML-entity encoding before any sink.
    import html
    safe_bio = html.escape(bio)
    return "<div>" + safe_bio + "</div>"
