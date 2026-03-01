FROM node:20-slim

RUN apt-get update && apt-get install -y \
  git \
  curl \
  python3 \
  python3-pip \
  python3-venv \
  && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir --break-system-packages \
  owasp-depscan==6.* \
  semgrep==1.* \
  2>/dev/null || true

RUN which trufflehog 2>/dev/null || \
  (curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
  | sh -s -- -b /usr/local/bin) 2>/dev/null || true

RUN useradd -m -s /bin/bash worker

ENV DEPSCAN_CACHE_DIR=/tmp/depscan-cache

WORKDIR /app

COPY package*.json ./
COPY tsconfig.json ./

RUN npm ci

COPY src ./src

RUN npm run build

RUN rm -rf src tsconfig.json && npm ci --only=production

RUN chown -R worker:worker /app /tmp

USER worker

CMD ["node", "dist/index.js"]
