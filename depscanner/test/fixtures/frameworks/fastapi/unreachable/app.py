from fastapi import FastAPI

app = FastAPI()


# Routes only consume JSON / query params. python-multipart is shipped as a
# transitive but never invoked because no Form() / File() / UploadFile param
# triggers the multipart parser.
@app.get("/healthz")
async def healthz():
    return {"ok": True}
