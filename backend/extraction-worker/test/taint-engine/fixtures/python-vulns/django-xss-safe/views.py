from django.http import HttpResponse
from render_helpers import render_user_html


def show_profile(request):
    raw_bio = request.GET.get('bio')
    safe_bio = _escape(raw_bio)
    body = render_user_html(safe_bio)
    return HttpResponse(body)


def _escape(value):
    import html
    return html.escape(value)
