# ============================================================================
# Stage 1: ZAP source — extract OWASP ZAP binaries for the DAST pipeline.
# Base image is ~1.7GB; we COPY only the runtime tree (/zap) into the runtime
# stage so we don't carry the whole base image. Java is provided by the
# runtime stage (Temurin 21 already installed for atom + Maven).
#
# v2.1d /criticalreview SVED-2 (P1): pinned to a content digest, NOT the
# floating `:stable` tag. v2.1d depends on a specific contract from ZAP
# 2.17.0 + authhelper v0.39.0 (`auth-report-json` report template +
# `summaryItems[]` keys + the schema's per-step `description:` requirement
# in `auth-config.ts:describeStep`). An unrelated future Dockerfile rebuild
# (cdxgen bump, Renovate node:20-slim refresh, CVE patch) would otherwise
# silently re-resolve `:stable` to whatever upstream ships at that moment,
# and a schema rename would break every recorded-login probe with no
# Deptex code change.
#
# DO NOT bump this digest without:
#   1. running depscanner/test/dast-recorded-pipeline.test.ts against the
#      new image's auth-report.json output (the captured fixtures under
#      depscanner/test/fixtures/zap-login-diagnostics/<version>/ are
#      version-pinned),
#   2. confirming authhelper version >= 0.39.0 (`zap.sh -addon-status` in
#      the new image),
#   3. updating both the fixture dir name AND the runbook reference.
#
# Captured digest from spike against ZAP 2.17.0 + authhelper 0.39.0:
FROM ghcr.io/zaproxy/zaproxy@sha256:8770b23f9e8b49038f413cb2b10c58c901e5b6717be221a22b1bcab5c9771b8a AS zap

# ============================================================================
# Stage 2: depscanner runtime
# ============================================================================
FROM node:20-slim

RUN apt-get update && apt-get install -y \
  git \
  curl \
  unzip \
  binutils \
  python3 \
  python3-pip \
  python3-venv \
  python-is-python3 \
  ruby \
  bundler \
  php-cli \
  composer \
  xmlstarlet \
  xvfb \
  xauth \
  fontconfig \
  libxi6 \
  libxtst6 \
  libxrender1 \
  xfonts-base \
  xfonts-encodings \
  firefox-esr \
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

# Crane (go-containerregistry) for HEAD-only manifest digest probe before the
# Trivy pull. Crane runs IN the worker that holds decrypted AWS root keys +
# GCP service-account JSON + Azure SP secrets — a compromised binary equals
# full credential exfiltration across every customer. Hence the same pinned
# tarball + sha256sum -c verification we apply to TruffleHog. Multi-arch via
# the buildx-populated TARGETARCH ARG. Bumping CRANE_VERSION without bumping
# both SHAs is enforced by .github/workflows/crane-pin-check.yml.
ARG CRANE_VERSION=v0.20.2
ARG CRANE_SHA256_AMD64=c14340087103ba9dadf61d45acd20675490fd0ccbd56ac7901fc1b502137f44b
ARG CRANE_SHA256_ARM64=aff0db48825124c9331ea310057214bd4e92c01aa2e414d539e9659841d9422a
ARG TARGETARCH
RUN set -eux; \
    case "$TARGETARCH" in \
      amd64) CRANE_ARCH=x86_64; CRANE_SHA256=$CRANE_SHA256_AMD64 ;; \
      arm64) CRANE_ARCH=arm64;  CRANE_SHA256=$CRANE_SHA256_ARM64 ;; \
      "") echo "TARGETARCH not set — build with docker buildx so it auto-populates"; exit 1 ;; \
      *) echo "Unsupported arch: $TARGETARCH"; exit 1 ;; \
    esac; \
    curl -sSfL "https://github.com/google/go-containerregistry/releases/download/${CRANE_VERSION}/go-containerregistry_Linux_${CRANE_ARCH}.tar.gz" \
      -o /tmp/crane.tar.gz; \
    echo "${CRANE_SHA256}  /tmp/crane.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/crane.tar.gz -C /usr/local/bin crane; \
    rm /tmp/crane.tar.gz; \
    chmod +x /usr/local/bin/crane; \
    crane version
# cosign verify-blob is the next-tier hardening. go-containerregistry releases
# ARE cosign-signed (Sigstore keyless OIDC). Add when cosign is in the base
# image:
#   RUN cosign verify-blob \
#     --certificate-identity-regexp='https://github.com/google/go-containerregistry' \
#     --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \
#     /tmp/crane.tar.gz

# Install GuardDog into an isolated venv. GuardDog ships its own pinned
# Semgrep dependency that conflicts with the version above; dropping it into
# /opt/guarddog-venv keeps the conflicts contained to the malicious-package
# scan step. The malicious-scan worker invokes /opt/guarddog-venv/bin/guarddog
# explicitly (never the global PATH).
RUN python3 -m venv /opt/guarddog-venv \
  && /opt/guarddog-venv/bin/pip install --no-cache-dir guarddog==2.9.0 \
  && /opt/guarddog-venv/bin/guarddog --version

# Install cdxgen globally (dep-scan invokes it for SBOM generation + atom reachability)
# and atom (reachability engine used by dep-scan --profile research).
# Pinned exact: both run against untrusted customer repos inside the worker —
# a floating `latest` is a supply-chain vector. Bump deliberately.
RUN npm install -g @cyclonedx/cdxgen@12.3.3 @appthreat/atom@2.5.2 \
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

# Bake the ZAP Passive Scan Rules — Alpha and Beta packs into /zap/plugin/.
# zap-baseline.py loads these by default at runtime via marketplace fetch;
# the AF YAML's `addOns: install` job DOES NOT reliably download missing
# add-ons (silent no-op observed against Juice Shop: 20 findings vs 43 from
# baseline.py). Baking them in at build time is the deterministic fix and
# also unblocks airgapped self-hosted deploys. Pinned by SHA-256.
RUN curl -sSfL https://github.com/zaproxy/zap-extensions/releases/download/pscanrulesAlpha-v47/pscanrulesAlpha-alpha-47.zap \
      -o /zap/plugin/pscanrulesAlpha-alpha-47.zap \
  && echo "2420200733fda276d50da2b3c51f7f9974978b9a6e7cf764929d71509500e18e  /zap/plugin/pscanrulesAlpha-alpha-47.zap" | sha256sum -c - \
  && curl -sSfL https://github.com/zaproxy/zap-extensions/releases/download/pscanrulesBeta-v47/pscanrulesBeta-beta-47.zap \
      -o /zap/plugin/pscanrulesBeta-beta-47.zap \
  && echo "ba01afb41d51663a2ea80eafea83507bf1103aeb784920b9395e8f7f12fddad4  /zap/plugin/pscanrulesBeta-beta-47.zap" | sha256sum -c -

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

# Nuclei (ProjectDiscovery) — second DAST engine (v2.1c), alongside ZAP.
# Pinned release zip + sha256sum -c, same supply-chain posture as Trivy /
# crane / TruffleHog: Nuclei runs inside the worker that holds decrypted
# customer credentials, so a compromised binary equals credential exfil.
# Multi-arch via the buildx-populated TARGETARCH. Always bump NUCLEI_VERSION
# and BOTH SHAs together — the build fails closed on a sha256sum mismatch.
ARG NUCLEI_VERSION=v3.8.0
ARG NUCLEI_SHA256_AMD64=cd4ea43c88b50af8ab96eb6ad3fb4debd8e9d51efaff4d4c2d99106041578943
ARG NUCLEI_SHA256_ARM64=deb622901acda6bbc6ffe771b98b2d41276667cc5dca6ce403b6ae331ccba64e
RUN set -eux; \
    NUCLEI_NUM="${NUCLEI_VERSION#v}"; \
    case "$TARGETARCH" in \
      amd64) NUCLEI_ARCH=amd64; NUCLEI_SHA256=$NUCLEI_SHA256_AMD64 ;; \
      arm64) NUCLEI_ARCH=arm64; NUCLEI_SHA256=$NUCLEI_SHA256_ARM64 ;; \
      "") echo "TARGETARCH not set — build with docker buildx so it auto-populates"; exit 1 ;; \
      *) echo "Unsupported arch: $TARGETARCH"; exit 1 ;; \
    esac; \
    curl -sSfL "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${NUCLEI_NUM}_linux_${NUCLEI_ARCH}.zip" \
      -o /tmp/nuclei.zip; \
    echo "${NUCLEI_SHA256}  /tmp/nuclei.zip" | sha256sum -c -; \
    unzip -j /tmp/nuclei.zip nuclei -d /usr/local/bin; \
    rm /tmp/nuclei.zip; \
    chmod +x /usr/local/bin/nuclei; \
    nuclei -version

# Nuclei templates corpus, pinned to an exact commit SHA — HEAD moves, so a
# plain `git clone --depth 1` is not reproducible. git fetch-by-SHA is
# supported by GitHub's smart HTTP transport. .git is dropped after checkout.
ARG NUCLEI_TEMPLATES_SHA=58569cb13cb2ce23d4c840771132e9341a585e9d
RUN set -eux; \
    git init /opt/nuclei-templates; \
    cd /opt/nuclei-templates; \
    git remote add origin https://github.com/projectdiscovery/nuclei-templates.git; \
    git fetch --depth 1 origin "$NUCLEI_TEMPLATES_SHA"; \
    git checkout "$NUCLEI_TEMPLATES_SHA"; \
    rm -rf .git; \
    test "$(find /opt/nuclei-templates -name '*.yaml' | wc -l)" -gt 9000; \
    chown -R worker:worker /opt/nuclei-templates
ENV NUCLEI_TEMPLATES_DIR=/opt/nuclei-templates

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
COPY .schema/schema.sql /backend/database/schema.sql

RUN npm run build

RUN rm -rf src tsconfig.json && npm ci --only=production

RUN chown -R worker:worker /app /tmp /data /backend/database /zap

USER worker

# Bump the V8 old-space cap to 8 GB. Default ~4 GB OOMs the worker on
# moderate-sized JS monorepos (express, react, etc.) while tree-sitter +
# downstream pipeline steps hold per-file extraction state. Fly machines and
# typical local Docker Desktop setups have ≥8 GB available; the higher cap
# is harmless on smaller hosts because V8 only uses what it needs. CLI users
# can override by setting NODE_OPTIONS before invoking the container.
ENV NODE_OPTIONS="--max-old-space-size=8192"

CMD ["node", "dist/index.js"]
