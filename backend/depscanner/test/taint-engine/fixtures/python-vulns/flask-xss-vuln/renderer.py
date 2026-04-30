from flask import render_template_string


def render_user_template(template_str):
    return render_template_string(template_str)
