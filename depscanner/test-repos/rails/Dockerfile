# Intentionally vulnerable: pinned old ruby image.
FROM ruby:2.7.0

# IaC misconfig: CKV_DOCKER_8 — running as root.
USER root

WORKDIR /app

COPY Gemfile ./
RUN bundle install --quiet || true

COPY . .

ENV PORT=4009
EXPOSE 4009

# IaC misconfig: CKV_DOCKER_2 — no HEALTHCHECK.

CMD ["rails", "server", "-b", "0.0.0.0", "-p", "4009"]
