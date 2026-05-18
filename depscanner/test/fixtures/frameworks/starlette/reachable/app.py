from starlette.applications import Starlette
from starlette.responses import RedirectResponse
from starlette.routing import Route


async def go(request):
    """CVE-2023-29159 — open redirect via user-controlled Location header."""
    target = request.query_params.get("next", "/")
    # Sink: RedirectResponse to attacker-controlled URL.
    return RedirectResponse(url=target)


app = Starlette(routes=[Route("/go", go)])
