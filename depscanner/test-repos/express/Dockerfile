FROM node:20-slim

WORKDIR /app

COPY package.json ./
RUN npm install --no-audit --no-fund

COPY . .

# CKV_DOCKER_8 — container runs as root user.
USER root

EXPOSE 4001

# CKV_DOCKER_2 — no HEALTHCHECK declared.
# CKV_DOCKER_7 — using :latest semantics (the node:20-slim base above isn't
# pinned by digest, so the same posture applies for container drift).

CMD ["node", "server.js"]
