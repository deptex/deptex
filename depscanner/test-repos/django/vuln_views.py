"""Intentionally vulnerable Django views — one clean reachable taint flow per view.

Each view takes a single request input and passes it directly into one dangerous
sink, then returns a constant response (no reflection). These exist to exercise
the Deptex taint engine end-to-end across vuln classes. DO NOT ship to prod.
"""

import os
import subprocess
import pickle
import re

import requests
import yaml
from django.db import connection
from django.http import HttpResponse, HttpResponseRedirect


def search_users(request):
    # REACHABLE: sql_injection
    name = request.GET.get("name", "")
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return HttpResponse("ok")


def ping_host(request):
    # REACHABLE: command_injection
    host = request.GET.get("host", "")
    os.system("ping -c 1 " + host)
    return HttpResponse("pinged")


def run_command(request):
    # REACHABLE: command_injection
    cmd = request.POST.get("cmd", "")
    subprocess.call(cmd, shell=True)
    return HttpResponse("ran")


def download_file(request):
    # REACHABLE: path_traversal
    filename = request.GET.get("file", "")
    open(filename, "rb")
    return HttpResponse("downloaded")


def serve_report(request):
    # REACHABLE: path_traversal
    report = request.GET.get("report", "")
    os.remove(report)
    return HttpResponse("deleted")


def fetch_url(request):
    # REACHABLE: ssrf
    target = request.GET.get("url", "")
    requests.get(target)
    return HttpResponse("fetched")


def proxy_avatar(request):
    # REACHABLE: ssrf
    avatar = request.POST.get("avatar_url", "")
    requests.post(avatar)
    return HttpResponse("proxied")


def go_next(request):
    # REACHABLE: open_redirect
    nxt = request.GET.get("next", "")
    return HttpResponseRedirect(nxt)


def load_session(request):
    # REACHABLE: deserialization
    blob = request.body
    pickle.loads(blob)
    return HttpResponse("loaded")


def import_config(request):
    # REACHABLE: deserialization
    raw = request.POST.get("config", "")
    yaml.load(raw)
    return HttpResponse("imported")


def calculate(request):
    # REACHABLE: deserialization (code injection via eval)
    expr = request.GET.get("expr", "")
    eval(expr)
    return HttpResponse("calculated")


def filter_logs(request):
    # REACHABLE: redos
    pattern = request.GET.get("pattern", "")
    re.compile(pattern)
    return HttpResponse("filtered")
