"""Intentionally vulnerable Flask routes for the dogfood taint corpus.

Each handler is ONE clean reachable flow: a Flask request input assigned to a
local, flowing directly into a single dangerous sink. Responses return a
constant so tainted data is never reflected back. Idiomatic, realistic Flask.

These routes seed the first-party taint-flow findings exercised by the engine.
"""

import os
import pickle
import re
import subprocess
import urllib.request

import requests
import yaml
from flask import (
    Blueprint,
    redirect,
    render_template_string,
    request,
)

vuln_bp = Blueprint("vuln", __name__)

# Module-level DBAPI cursor (sqlite3 stdlib — no extra dependency).
import sqlite3

_db = sqlite3.connect(":memory:", check_same_thread=False)
cursor = _db.cursor()


@vuln_bp.route("/exec/sql")
def sql_injection():
    # REACHABLE: sql_injection — request.args -> cursor.execute
    user_id = request.args.get("id")
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
    return "ok"


@vuln_bp.route("/exec/cmd")
def command_injection():
    # REACHABLE: command_injection — request.args -> os.system
    host = request.args.get("host")
    os.system("ping -c 1 " + host)
    return "ok"


@vuln_bp.route("/exec/spawn")
def command_injection_subprocess():
    # REACHABLE: command_injection — request.form -> subprocess.call
    target = request.form.get("target")
    subprocess.call("nmap " + target, shell=True)
    return "ok"


@vuln_bp.route("/files/read")
def path_traversal_open():
    # REACHABLE: path_traversal — request.args -> open
    name = request.args.get("name")
    with open(name, "rb") as fh:
        fh.read()
    return "ok"


@vuln_bp.route("/files/delete")
def path_traversal_remove():
    # REACHABLE: path_traversal — request.values -> os.remove
    doomed = request.values.get("path")
    os.remove(doomed)
    return "ok"


@vuln_bp.route("/fetch/proxy")
def ssrf_requests():
    # REACHABLE: ssrf — request.args -> requests.get
    url = request.args.get("url")
    requests.get(url)
    return "ok"


@vuln_bp.route("/fetch/raw")
def ssrf_urllib():
    # REACHABLE: ssrf — request.args -> urllib.request.urlopen
    endpoint = request.args.get("endpoint")
    urllib.request.urlopen(endpoint)
    return "ok"


@vuln_bp.route("/render/template")
def xss_template():
    # REACHABLE: xss — request.args -> render_template_string
    name = request.args.get("name")
    template = "<h1>Hello " + name + "</h1>"
    render_template_string(template)
    return "ok"


@vuln_bp.route("/code/eval")
def code_injection_eval():
    # REACHABLE: deserialization/code_injection — request.args -> eval
    expr = request.args.get("expr")
    eval(expr)
    return "ok"


@vuln_bp.route("/deser/pickle", methods=["POST"])
def deserialization_pickle():
    # REACHABLE: deserialization — request.data -> pickle.loads
    blob = request.data
    pickle.loads(blob)
    return "ok"


@vuln_bp.route("/deser/yaml", methods=["POST"])
def deserialization_yaml():
    # REACHABLE: deserialization — request.form -> yaml.load
    doc = request.form.get("doc")
    yaml.load(doc)
    return "ok"


@vuln_bp.route("/go")
def open_redirect():
    # REACHABLE: open_redirect — request.args -> redirect
    dest = request.args.get("next")
    return redirect(dest)


@vuln_bp.route("/search")
def redos():
    # REACHABLE: redos — request.args -> re.compile
    pattern = request.args.get("q")
    re.compile(pattern)
    return "ok"
