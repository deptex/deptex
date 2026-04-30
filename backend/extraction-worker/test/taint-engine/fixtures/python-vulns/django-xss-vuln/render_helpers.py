from django.utils.safestring import mark_safe


def render_user_html(raw_bio):
    return mark_safe("<div class='bio'>" + raw_bio + "</div>")
