from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from file_helpers import resolve_user_file

app = FastAPI()


@app.get('/download')
async def download(request: Request):
    raw_name = request.query_params.get('file')
    safe_name = _strip_path(raw_name)
    path = resolve_user_file(safe_name)
    return FileResponse(path)


def _strip_path(name):
    import os.path
    return os.path.basename(name)
