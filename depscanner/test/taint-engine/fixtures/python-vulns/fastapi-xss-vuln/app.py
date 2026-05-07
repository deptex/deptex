from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from render_helpers import render_user_html

app = FastAPI()


@app.get('/profile')
async def profile(request: Request):
    bio = request.query_params.get('bio')
    body = render_user_html(bio)
    return HTMLResponse(body)
