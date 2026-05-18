from flask import Flask, request
import jinja2

app = Flask(__name__)


@app.route('/render')
def render():
    env = jinja2.SandboxedEnvironment()
    # Static template source — no taint reaches from_string.
    template = env.from_string('Hello, World!')
    data = {'format_map': str.format_map}
    return template.render(data)


@app.route('/attrs')
def attrs():
    # Static keys — no taint flows into render's xmlattr filter.
    template = jinja2.Template('<div{{ attrs|xmlattr }}></div>')
    return template.render(attrs={'class': 'safe'})
