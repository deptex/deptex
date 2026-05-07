from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from file_helpers import resolve_user_file

app = FastAPI()


@app.get('/download')
async def download(request: Request):
    name = request.query_params.get('file')
    path = resolve_user_file(name)
    return FileResponse(path)
