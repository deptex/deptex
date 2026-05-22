# Intentionally vulnerable: pinned old OpenJDK image.
FROM openjdk:11.0.0-jdk

# IaC misconfig: CKV_DOCKER_8 — running as root.
USER root

WORKDIR /app

COPY . .

# Pre-built jar would be copied from a build stage in real usage; here we
# rely on the maven SBOM (pom.xml) for the dependency scanners.
ENV PORT=4006
EXPOSE 4006

# IaC misconfig: CKV_DOCKER_2 — no HEALTHCHECK.

CMD ["java", "-jar", "deptex-dogfood-spring-boot-1.0.0.jar"]
