# Pure-frontend SPA — served by an nginx stub for IaC + container scanner
# coverage. No DAST cell: a static site behind nginx has no application
# attack surface ZAP / Nuclei meaningfully probe in this corpus.
# Pinned to an old nginx image for predictable os-package CVE coverage.
FROM nginx:1.19.0

# IaC misconfig: CKV_DOCKER_8 — running as root.
USER root

COPY index.html /usr/share/nginx/html/index.html
COPY src /usr/share/nginx/html/src

EXPOSE 80

# IaC misconfig: CKV_DOCKER_2 — no HEALTHCHECK.

CMD ["nginx", "-g", "daemon off;"]
