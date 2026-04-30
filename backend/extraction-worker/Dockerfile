FROM node:20-slim

RUN apt-get update && apt-get install -y \
  git \
  curl \
  python3 \
  python3-pip \
  python3-venv \
  && rm -rf /var/lib/apt/lists/*

# Install Eclipse Temurin JDK 21 (full JDK for Maven + atom)
RUN curl -sL https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.6%2B7/OpenJDK21U-jdk_x64_linux_hotspot_21.0.6_7.tar.gz \
  | tar xz -C /opt \
  && ln -s /opt/jdk-21.0.6+7/bin/java /usr/local/bin/java \
  && ln -s /opt/jdk-21.0.6+7/bin/javac /usr/local/bin/javac
ENV JAVA_HOME=/opt/jdk-21.0.6+7

# Install Maven 3.9
RUN curl -sL https://archive.apache.org/dist/maven/maven-3/3.9.9/binaries/apache-maven-3.9.9-bin.tar.gz \
  | tar xz -C /opt \
  && ln -s /opt/apache-maven-3.9.9/bin/mvn /usr/local/bin/mvn

# Install Go 1.22
RUN curl -sL https://go.dev/dl/go1.22.10.linux-amd64.tar.gz \
  | tar xz -C /usr/local
ENV PATH="/usr/local/go/bin:${PATH}"

# Install dep-scan and Semgrep into the system Python. semgrep is exact-pinned
# because it ships breaking changes frequently. dep-scan is major-version-pinned
# (6.*) to allow patch uptake while blocking the 6→7 breaking-change class.
RUN pip3 install --no-cache-dir --break-system-packages \
  owasp-depscan==6.* \
  semgrep==1.160.0 \
  && depscan --help >/dev/null \
  && semgrep --version

# Install Checkov in an isolated venv at /opt/checkov-venv. Checkov pins
# packageurl-python<0.14.0 while owasp-depscan pins >=0.16.0 — the two cannot
# coexist in the same Python environment. Pinning Checkov to the 3.2.x line —
# the rule library is what we depend on; 3.x→4.x will be a deliberate bump with
# bench re-runs. The /usr/local/bin symlink keeps `checkov` on PATH.
RUN python3 -m venv /opt/checkov-venv \
  && /opt/checkov-venv/bin/pip install --no-cache-dir checkov==3.2.420 \
  && ln -s /opt/checkov-venv/bin/checkov /usr/local/bin/checkov \
  && checkov --version

# Install Trivy (Aquasec) for Dockerfile misconfig + container CVE scanning.
# Pin to a specific release tarball (no install.sh / curl-pipe-sh) for the
# same supply-chain reasons as TruffleHog below.
RUN curl -sSfL https://github.com/aquasecurity/trivy/releases/download/v0.69.3/trivy_0.69.3_Linux-64bit.tar.gz \
  -o /tmp/trivy.tar.gz \
  && tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy \
  && rm /tmp/trivy.tar.gz \
  && chmod +x /usr/local/bin/trivy \
  && trivy --version

# Install cdxgen globally (dep-scan invokes it for SBOM generation + atom reachability)
# and atom (reachability engine used by dep-scan --profile research)
RUN npm install -g @cyclonedx/cdxgen @appthreat/atom \
  && java -version \
  && cdxgen --version \
  && atom --help >/dev/null 2>&1 || true

# Install TruffleHog from a pinned release tarball instead of `curl | sh`.
# The official install.sh fetches the latest release at build time AND was
# itself a curl-pipe-sh supply-chain vector (compromised github account or
# MITM could inject malicious payload). Pinning to a specific version makes
# builds reproducible and removes the pipe-to-shell risk.
RUN curl -sSfL https://github.com/trufflesecurity/trufflehog/releases/download/v3.83.6/trufflehog_3.83.6_linux_amd64.tar.gz \
  -o /tmp/trufflehog.tar.gz \
  && tar -xzf /tmp/trufflehog.tar.gz -C /usr/local/bin trufflehog \
  && rm /tmp/trufflehog.tar.gz \
  && chmod +x /usr/local/bin/trufflehog \
  && trufflehog --version

RUN useradd -m -s /bin/bash worker

RUN mkdir -p /data /data/cache && chown -R worker:worker /data

ENV VDB_HOME=/data
ENV DEPSCAN_CACHE_DIR=/data/cache

WORKDIR /app

COPY package*.json ./
COPY tsconfig.json ./

RUN npm ci

COPY src ./src

# Phase 3 reachability rule packs (per-CVE Semgrep taint YAMLs + fixtures)
# are runtime data, not bundled into dist/. The pipeline reads them with
# loadAllRulesWithSkipped(path.resolve(__dirname, '..', 'reachability-rules'))
# so they need to live next to dist/ inside the image, otherwise the
# reachability_rules step warns "No rules loaded" and every taint
# promotion silently disappears.
COPY reachability-rules ./reachability-rules

# Local CLI mode reads schema.sql via PGLiteStorage at runtime. The
# `docker:build` npm script stages the backend/database folder into
# extraction-worker/.schema before invoking docker build so we can COPY it
# in here. On Fly.io (which uses Supabase, not PGLite) this dir is unused.
COPY .schema/schema.sql /database/schema.sql

RUN npm run build

RUN rm -rf src tsconfig.json && npm ci --only=production

RUN chown -R worker:worker /app /tmp /data /database

USER worker

CMD ["node", "dist/index.js"]
