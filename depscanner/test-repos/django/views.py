"""Minimal Django views — one reachable XSS, one safe."""

from django.http import HttpResponse
from django.utils.safestring import mark_safe


def render_message(request):
    # REACHABLE: request.GET['msg'] -> mark_safe -> response body (XSS).
    msg = request.GET.get("msg", "")
    return HttpResponse(f"<div>{mark_safe(msg)}</div>")


def render_static(request):
    # UNREACHABLE: mark_safe on a server-side constant; no user taint.
    return HttpResponse(mark_safe("<div>welcome</div>"))
