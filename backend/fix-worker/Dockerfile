FROM node:20-slim

# Base toolchain: git for clone, curl for tooling install, python3 + pip for
# Python projects (M6), Go for Go projects (M6). Stretch languages are added
# in M8. JS/TS only is exercised end-to-end in M5.
RUN apt-get update && apt-get install -y \
  git \
  curl \
  python3 \
  python3-pip \
  python3-venv \
  ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Go 1.22 — same version pin as extraction-worker for parity.
RUN curl -sL https://go.dev/dl/go1.22.10.linux-amd64.tar.gz \
  | tar xz -C /usr/local
ENV PATH="/usr/local/go/bin:${PATH}"

RUN useradd -m -s /bin/bash worker

WORKDIR /app

COPY package*.json ./
COPY tsconfig.json ./

RUN npm ci

COPY src ./src

RUN npm run build

RUN rm -rf src tsconfig.json && npm ci --only=production

# /work is the sandbox root for clone + edit + test cycles. Cleared per job.
RUN mkdir -p /work && chown -R worker:worker /app /work

USER worker

CMD ["node", "dist/index.js"]
