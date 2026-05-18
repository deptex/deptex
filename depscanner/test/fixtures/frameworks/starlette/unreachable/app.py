from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route


async def home(_request):
    # Plain text — no RedirectResponse anywhere.
    return PlainTextResponse("ok")


app = Starlette(routes=[Route("/", home)])
