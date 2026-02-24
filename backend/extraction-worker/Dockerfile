FROM node:20-slim

RUN apt-get update && apt-get install -y \
  git \
  python3 \
  python3-pip \
  && rm -rf /var/lib/apt/lists/*

# Install dep-scan (Python), semgrep, trufflehog
RUN pip3 install --no-cache-dir owasp-depscan 2>/dev/null || true
RUN pip3 install --no-cache-dir semgrep 2>/dev/null || true
RUN which trufflehog 2>/dev/null || (curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin) 2>/dev/null || true

WORKDIR /app

COPY package*.json ./
COPY tsconfig.json ./

RUN npm ci

COPY src ./src

RUN npm run build

RUN rm -rf src tsconfig.json && npm ci --only=production

CMD ["node", "dist/index.js"]
