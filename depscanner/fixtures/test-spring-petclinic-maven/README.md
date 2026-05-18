# test-spring-petclinic-maven

Tiny Spring slice modelled on PetClinic. One controller is vulnerable
to SQLi via concatenation; another uses parameterised queries.

- **Ecosystem:** maven
- **Framework:** Spring MVC
- **Vulnerable dep:** `spring-core` 5.3.18 (Spring4Shell-adjacent
  versions) + a deliberately old `mysql-connector-java`.
- **Reachable handler:** `OwnerController.findOwners()` — request
  param concatenated into a JdbcTemplate string.
- **Unreachable handler:** `OwnerController.findById()` — uses bound
  parameters.

Expected snapshot: maven deps in `deps.json`, one entry point for the
reachable handler. Marked `slow: true` because Maven cold-build is
costly.
