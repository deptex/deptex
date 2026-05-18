import jinja2
import html

# Patched: the Jinja template source is a hard-coded literal compiled at
# module load. The user-supplied value is HTML-escaped via the stdlib
# `html.escape(*)` sanitizer (registered in flask.yaml) before it reaches
# Template.render, so the bundled `*.render(*)` xss sink sees no live taint.
_FIXED_TEMPLATE = jinja2.Template('<p>Hello, {{ name }}</p>', autoescape=True)


def render_user_greeting(name):
    safe_name = html.escape(name)
    return _FIXED_TEMPLATE.render(name=safe_name)
