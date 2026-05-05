# ============================================================================
# Stage 1: ZAP source — extract OWASP ZAP binaries for the DAST pipeline.
# Base image is ~1.7GB; we COPY only the runtime tree (/zap) into the runtime
# stage so we don't carry the whole base image. Java is provided by the
# runtime stage (Temurin 21 already installed for atom + Maven).
# ============================================================================
FROM ghcr.io/zaproxy/zaproxy:stable AS zap

# ============================================================================
# Stage 2: depscanner runtime
# ============================================================================
FROM node:20-slim

RUN apt-get update && apt-get install -y \
  git \
  curl \
  python3 \
  python3-pip \
  python3-venv \
  python-is-python3 \
  xmlstarlet \
  xvfb \
  xauth \
  fontconfig \
  libxi6 \
  libxtst6 \
  libxrender1 \
  xfonts-base \
  xfonts-encodings \
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

# Install GuardDog into an isolated venv. GuardDog ships its own pinned
# Semgrep dependency that conflicts with the version above; dropping it into
# /opt/guarddog-venv keeps the conflicts contained to the malicious-package
# scan step. The malicious-scan worker invokes /opt/guarddog-venv/bin/guarddog
# explicitly (never the global PATH).
RUN python3 -m venv /opt/guarddog-venv \
  && /opt/guarddog-venv/bin/pip install --no-cache-dir guarddog==2.9.0 \
  && /opt/guarddog-venv/bin/guarddog --version

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

# OWASP ZAP for the DAST pipeline (Phase 23b PR 3). Copied from the ZAP base
# image so we get zap.jar + addons + the python helper scripts used by Task 8's
# runner (zap-baseline.py / zap-full-scan.py / zap-api-scan.py). Java is shared
# with the existing JDK 21 install above.
COPY --from=zap /zap /zap
ENV PATH="/zap:${PATH}" \
    ZAP_PATH="/zap/zap.sh"

# ZAP's helper scripts (zap-baseline.py etc) need a small set of Python deps
# that are normally pre-installed in the official ZAP image but not in
# node:20-slim. Smoke check only verifies binaries exist (full version prints
# require the JVM warmup that we want to avoid at build time).
RUN pip3 install --no-cache-dir --break-system-packages \
  python-owasp-zap-v2.4 \
  && test -f /zap/zap.sh \
  && test -f /zap/zap-baseline.py \
  && test -f /zap/zap-api-scan.py \
  && test -f /zap/zap-full-scan.py

RUN useradd -m -s /bin/bash worker

RUN mkdir -p /data /data/cache && chown -R worker:worker /data

# /zap/wrk is the only directory ZAP's helper scripts will accept as a target
# for `-J / -r / -w / -x / -c / -g` (see zap-baseline.py:374, the script bails
# with `'/zap/wrk' is not mounted` otherwise). The runner writes report+stub
# files there. Owned by `worker` so the runtime user can mkdtempSync into it.
RUN mkdir -p /zap/wrk && chown worker:worker /zap/wrk

ENV VDB_HOME=/data
ENV DEPSCAN_CACHE_DIR=/data/cache

WORKDIR /app

COPY package*.json ./
COPY tsconfig.json ./

RUN npm ci

COPY src ./src

# Phase 6.5 / M5 — the legacy `reachability-rules/` directory of hand-authored
# Semgrep taint rule packs has been retired. The CVE-targeted FrameworkSpec
# generator + cross-file taint engine replace it; no bundled runtime data
# is required for the new path.

# Local CLI mode reads schema.sql via PGLiteStorage at runtime. The
# `docker:build` npm script stages the backend/database folder into
# depscanner/.schema before invoking docker build so we can COPY it
# in here. On Fly.io (which uses Supabase, not PGLite) this dir is unused.
COPY .schema/schema.sql /database/schema.sql

RUN npm run build

RUN rm -rf src tsconfig.json && npm ci --only=production

RUN chown -R worker:worker /app /tmp /data /database /zap

USER worker

CMD ["node", "dist/index.js"]
