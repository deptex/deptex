"""Intentionally vulnerable FastAPI routes — one clean reachable taint flow per route.

Every handler reads a single attacker-controlled request input, assigns it to a
local variable, and passes that variable straight into one dangerous sink. None
of the routes reflect the tainted value back in the response (they return a
constant) — the vulnerability is the sink call itself. These exist so the Deptex
taint engine confirms first-party data-flow findings during dogfooding.
"""

import os
import pickle
import subprocess
import re

from fastapi import APIRouter, Request, Query, Path, Form, Header
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import create_engine, text
import requests

router = APIRouter()
engine = create_engine("sqlite:///./test.db")


@router.get("/sql/search")
async def sql_search(request: Request):
    # REACHABLE: sql_injection
    term = request.query_params.get("term")
    with engine.connect() as conn:
        conn.execute(text(f"SELECT * FROM products WHERE name = '{term}'"))
    return {"ok": True}


@router.get("/exec/ping")
async def exec_ping(request: Request):
    # REACHABLE: command_injection
    host = request.query_params.get("host")
    os.system("ping -c 1 " + host)
    return {"ok": True}


@router.get("/exec/run")
async def exec_run(request: Request):
    # REACHABLE: command_injection
    cmd = request.query_params.get("cmd")
    subprocess.call(cmd, shell=True)
    return {"ok": True}


@router.get("/files/read")
async def files_read(request: Request):
    # REACHABLE: path_traversal
    name = request.query_params.get("file")
    fh = open("/var/data/" + name)
    fh.close()
    return {"ok": True}


@router.get("/files/delete")
async def files_delete(request: Request):
    # REACHABLE: path_traversal
    name = request.query_params.get("file")
    os.remove("/var/data/" + name)
    return {"ok": True}


@router.get("/proxy/fetch")
async def proxy_fetch(request: Request):
    # REACHABLE: ssrf
    url = request.query_params.get("url")
    requests.get(url)
    return {"ok": True}


@router.get("/render/profile")
async def render_profile(request: Request):
    # REACHABLE: xss
    bio = request.query_params.get("bio")
    HTMLResponse("<div>" + bio + "</div>")
    return {"ok": True}


@router.get("/go")
async def go(request: Request):
    # REACHABLE: open_redirect
    target = request.query_params.get("next")
    RedirectResponse(target)
    return {"ok": True}


@router.post("/deserialize/load")
async def deserialize_load(request: Request):
    # REACHABLE: deserialization
    blob = await request.body()
    pickle.loads(blob)
    return {"ok": True}


@router.post("/eval/compute")
async def eval_compute(request: Request):
    # REACHABLE: deserialization (code injection via eval)
    expr = await request.body()
    eval(expr)
    return {"ok": True}


@router.get("/search/regex")
async def search_regex(request: Request):
    # REACHABLE: redos
    pattern = request.query_params.get("pattern")
    re.compile(pattern)
    return {"ok": True}


@router.get("/match")
async def match(request: Request):
    # REACHABLE: redos
    needle = request.query_params.get("q")
    re.search(needle, "haystack")
    return {"ok": True}
