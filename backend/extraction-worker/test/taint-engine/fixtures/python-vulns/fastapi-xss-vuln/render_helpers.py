from markupsafe import Markup


def render_user_html(raw_bio):
    return Markup("<div class='bio'>" + raw_bio + "</div>")
