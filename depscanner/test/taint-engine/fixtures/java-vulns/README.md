# Java Taint Engine — Fixture Suite

Each subdirectory is a self-contained mini Spring Boot project demonstrating
a taint pattern. Naming convention: `<framework>-<vuln_class>-<vuln|safe>`.

The validation harness (`npm run test:taint-engine-java`) walks this
directory, runs the Java propagator with `framework-models/spring-boot.yaml`
+ `framework-models/java-stdlib.yaml`, and asserts:

- `*-vuln` fixtures must produce >= 1 flow of the corresponding `vuln_class`
- `*-safe` fixtures must produce 0 flows of that `vuln_class`

Fixtures use cross-file structure to exercise inter-procedural propagation:
typically a `@RestController` invokes a method on an `@Service`/`@Repository`
class declared in a sibling file.
