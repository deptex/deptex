# Intentionally vulnerable: pinned old golang image.
FROM golang:1.17.0

# IaC misconfig: CKV_DOCKER_8 — running as root.
USER root

WORKDIR /app

COPY go.mod ./
RUN go mod download || true

COPY . .

RUN go build -o /app/server ./...

ENV PORT=4007
EXPOSE 4007

# IaC misconfig: CKV_DOCKER_2 — no HEALTHCHECK.

CMD ["/app/server"]
