# spring-boot

Tiny Spring slice modelled on PetClinic. One controller is vulnerable
to SQLi via concatenation; another uses parameterised queries.
Stand-alone copy of upstream taint-engine fixture
`depscanner/fixtures/test-spring-petclinic-maven/` layered with dogfood
categories.

- **Ecosystem:** maven
- **Framework:** Spring MVC
- **Reachable vuln dep:** `spring-core` 5.3.18 (Spring4Shell-adjacent
  versions) + `mysql-connector-java` 8.0.16.
- **Unreachable vuln dep:** `commons-collections` 3.2.1 — declared in
  pom.xml but never imported.
- **Reachable handler:** `OwnerController.findOwners()` — request param
  concatenated into a JdbcTemplate string.
- **Unreachable handler:** `OwnerController.findById()` — bound params.

See `.deptex/SOURCE.md` for provenance.
