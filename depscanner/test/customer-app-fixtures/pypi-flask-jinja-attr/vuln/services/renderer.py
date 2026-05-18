import jinja2


def render_user_template(source):
    # Sink: jinja2.Template(source) compiles attacker-controlled template
    # source — classic SSTI / RCE (CVE-2024-22195 family).
    template = jinja2.Template(source)
    return template.render(name='world')
