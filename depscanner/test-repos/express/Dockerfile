# Intentionally vulnerable base image: node:14 has many published CVEs in
# its os-package layer (openssl/libc/etc.). Trivy/dep-scan container layer
# surfaces these as project_container_findings.
FROM node:20-slim

WORKDIR /app

COPY package.json ./
RUN npm install --no-audit --no-fund

COPY . .

# CKV_DOCKER_8 — container runs as root user.
USER root

EXPOSE 4001

# CKV_DOCKER_2 — no HEALTHCHECK declared.
# CKV_DOCKER_7 — using :latest semantics (the node:14.0 base above isn't
# pinned by digest, so the same posture applies for container drift).

CMD ["node", "server.js"]
