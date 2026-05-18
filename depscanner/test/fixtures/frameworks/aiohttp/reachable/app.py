from aiohttp import web

# CVE-2024-23334 — aiohttp 3.9.1 path traversal via web.static when
# follow_symlinks is True or routing config trusts user paths.
app = web.Application()


async def fetch(request: web.Request) -> web.Response:
    name = request.match_info["name"]
    # Sink: open file via attacker-controlled relative path.
    with open(f"./public/{name}", "rb") as fh:
        return web.Response(body=fh.read())


app.router.add_get("/files/{name}", fetch)
# Also add the classic web.static which exhibits the CVE directly.
app.router.add_static("/assets/", path="./public", follow_symlinks=True)
