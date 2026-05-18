from aiohttp import web

# aiohttp imported, but no static handler / no file IO from user paths.
app = web.Application()


async def healthz(_request):
    return web.json_response({"ok": True})


app.router.add_get("/healthz", healthz)
