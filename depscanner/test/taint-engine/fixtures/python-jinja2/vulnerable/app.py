from flask import Flask, request
import jinja2

app = Flask(__name__)


@app.route('/render')
def render():
    # CVE-2019-10906 shape — tainted template source flows into
    # SandboxedEnvironment.from_string, allowing sandbox escape via
    # str.format_map.
    template_str = request.args.get('tmpl')
    env = jinja2.SandboxedEnvironment()
    template = env.from_string(template_str)
    data = {'format_map': str.format_map}
    return template.render(data)


@app.route('/attrs')
def attrs():
    # CVE-2024-22195 / CVE-2024-34064 shape — tainted user input flows
    # into Template.render via the xmlattr filter.
    key = request.args.get('key')
    template = jinja2.Template('<div{{ attrs|xmlattr }}></div>')
    return template.render(attrs={key: 'value'})
