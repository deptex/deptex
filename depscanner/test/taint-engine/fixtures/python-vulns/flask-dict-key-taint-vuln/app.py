from flask import Flask, request, render_template_string

app = Flask(__name__)


# Dict-literal-key taint propagation. Modeled on the jinja2-22195 / 34064
# pattern: a tainted source flows into a dict literal as the KEY, not the
# value. Before the python/ir.ts dict-key fix, the lowerer only walked
# pair.value, so `data` ended up untainted despite the user-controlled key.
@app.route('/render')
def render():
    data = {request.args.get('x'): 'value'}
    return render_template_string(str(data))


# F-string interpolation as dict key — the jinja2-22195 exact shape.
@app.route('/render2')
def render2():
    data = {f'prefix-{request.args.get("y")}': 'value'}
    return render_template_string(str(data))
