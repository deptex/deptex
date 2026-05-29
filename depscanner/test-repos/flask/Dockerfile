# Intentionally vulnerable: pinned old python image.
FROM python:3.7.0

# IaC misconfig: CKV_DOCKER_8 — running as root.
USER root

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PORT=4005
EXPOSE 4005

# IaC misconfig: CKV_DOCKER_2 — no HEALTHCHECK.

CMD ["flask", "run", "--host=0.0.0.0", "--port=4005"]
