# Intentionally vulnerable: pinned old rust image.
FROM rust:1.60.0

# IaC misconfig: CKV_DOCKER_8 — running as root.
USER root

WORKDIR /app

COPY Cargo.toml ./
COPY src ./src

RUN cargo build --release || true

ENV PORT=4008
EXPOSE 4008

# IaC misconfig: CKV_DOCKER_2 — no HEALTHCHECK.

CMD ["/app/target/release/deptex-dogfood-axum"]
