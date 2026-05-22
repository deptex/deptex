# Intentionally vulnerable: pinned to an old major node with known CVEs
# in its OS packages. Trivy / dep-scan container should surface at least
# one os-package CVE here. Aligned with the express fixture for
# uniform IaC + container coverage across the dogfood corpus.
FROM node:14.0

# IaC misconfig: CKV_DOCKER_8 — running as root.
USER root

WORKDIR /app

COPY package.json ./
RUN npm install --production --no-audit

COPY . .

ENV NODE_ENV=production
ENV PORT=4002
EXPOSE 4002

# IaC misconfig: CKV_DOCKER_2 — no HEALTHCHECK.

CMD ["npm", "run", "start"]
