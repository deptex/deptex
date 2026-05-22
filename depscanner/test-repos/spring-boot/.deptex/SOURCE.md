# SOURCE

Standalone copy of upstream taint-engine fixture:

- **Upstream path:** `depscanner/fixtures/test-spring-petclinic-maven/`
- **Upstream tree SHA at copy time:** `742dd3f81a0fcf6f091d33163f2d2362da016fe7`
- **Files copied verbatim:** `pom.xml`, `src/main/java/com/deptex/fixtures/OwnerController.java`.

Added for the dogfood: commons-collections unreachable dep (pom.xml),
Dockerfile + k8s.yaml + .env.example, `.deptex/{expected.yaml,deploy.sh,
SOURCE.md}`, README rewritten. No malicious-pkg seed for maven —
historical-malicious maven packages are rare and ecosystem-specific
seeding is iterated in M4 walkthrough.

Upstream fixture stays byte-stable per Patch B.
