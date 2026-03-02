FROM node:20-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl python3 python3-pip python3-venv && \
    python3 -m venv /opt/aider-venv && \
    /opt/aider-venv/bin/pip install --no-cache-dir aider-chat && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

ENV PATH="/opt/aider-venv/bin:$PATH"

RUN git config --global user.name "Deptex AI" && \
    git config --global user.email "ai@deptex.dev"

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --production
COPY dist/ ./dist/

USER node
CMD ["node", "dist/index.js"]
