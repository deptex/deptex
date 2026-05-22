# Intentionally vulnerable: pinned to an old python image with known
# CVEs in its OS packages.
FROM python:3.7.0

# IaC misconfig: CKV_DOCKER_8 — running as root.
USER root

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PORT=4003
EXPOSE 4003

# IaC misconfig: CKV_DOCKER_2 — no HEALTHCHECK.

CMD ["python", "-m", "django", "runserver", "0.0.0.0:4003"]
