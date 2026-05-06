# Minimal Dockerfile for the configured-image fixture. The container scanner
# will detect ghcr.io/foo/sample:1.2.3 as a Dockerfile-derived image; the
# .deptex/configured-images.example.json file alongside this Dockerfile is
# documentation only — the actual scan target list lives in
# project_configured_images and is loaded by the orchestrator at scan time.
FROM ghcr.io/foo/sample:1.2.3

LABEL purpose="configured-image fixture"

CMD ["echo", "fixture"]
