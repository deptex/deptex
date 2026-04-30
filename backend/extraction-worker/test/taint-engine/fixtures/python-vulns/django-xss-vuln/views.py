from django.http import HttpResponse
from render_helpers import render_user_html


def show_profile(request):
    bio = request.GET.get('bio')
    body = render_user_html(bio)
    return HttpResponse(body)
