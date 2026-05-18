from flask import Flask, request
from services.renderer import render_user_template
from services.audit import audit_request

app = Flask(__name__)


@app.route('/render')
def render_view():
    template_source = request.args.get('tmpl')
    audit_request(request)
    return render_user_template(template_source)
