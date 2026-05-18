from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from render_helpers import render_user_html

app = FastAPI()


@app.get('/profile')
async def profile(request: Request):
    raw_bio = request.query_params.get('bio')
    safe_bio = _escape(raw_bio)
    body = render_user_html(safe_bio)
    return HTMLResponse(body)


def _escape(value):
    import html
    return html.escape(value)
