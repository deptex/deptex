from fastapi import FastAPI, Form

# CVE-2024-24762 — python-multipart <= 0.0.6 ReDoS in Content-Type parser.
# Triggered when a request hits a Form() endpoint with a crafted Content-Type.
app = FastAPI()


@app.post("/upload")
async def upload(name: str = Form(...)):
    # Sink: Form() dependency triggers python-multipart parsing on every call.
    return {"name": name}
