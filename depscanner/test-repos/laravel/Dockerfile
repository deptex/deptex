# Intentionally vulnerable: pinned old PHP image.
FROM php:7.4.0-cli

# IaC misconfig: CKV_DOCKER_8 — running as root.
USER root

WORKDIR /app

COPY composer.json ./
RUN php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');" \
    && php composer-setup.php --install-dir=/usr/local/bin --filename=composer \
    || true

COPY . .

ENV PORT=4010
EXPOSE 4010

# IaC misconfig: CKV_DOCKER_2 — no HEALTHCHECK.

CMD ["php", "-S", "0.0.0.0:4010", "-t", "public"]
