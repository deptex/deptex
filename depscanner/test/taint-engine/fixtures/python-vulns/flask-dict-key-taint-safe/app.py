from flask import Flask, request, render_template_string

app = Flask(__name__)


# Safe counterpart: dict literal with constant keys and constant values.
# No taint flows into the dict, so the render_template_string sink stays
# clean — the dict-key fix must NOT taint constant-key dicts.
@app.route('/render')
def render():
    data = {'x': 'value', 'y': 'other'}
    return render_template_string(str(data))


# Tainted dict literal in a different function — taint must not leak across
# functions of its own accord; ensures the fix is local to the dict literal.
@app.route('/render2')
def render2():
    data = {'safe': 'value'}
    return render_template_string(str(data))
