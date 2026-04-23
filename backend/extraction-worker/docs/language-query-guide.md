# Language Query Guide

AST shapes, node types, and known quirks for each of the 8 languages the tree-sitter extractor supports. Read this before writing a detector for an unfamiliar grammar, or when something that "should work" doesn't match.

The extractor uses `web-tree-sitter` WASM grammars via `tree-sitter-wasms`. Grammars ship inside the Docker image at `node_modules/tree-sitter-wasms/out/`.

---

## Pipeline ecosystem ↔ language ID

These are two different namespaces and mixing them up is a pipeline-silent skip. `SupportedEcosystem` (canonical, matches cdxgen/SBOM) drives the pipeline's "should we run the extractor" gate. `SupportedLanguageId` is a detector-facing label.

| Ecosystem | Language ID | Extensions |
|-----------|-------------|------------|
| `npm` | `javascript` | `.js .mjs .cjs .jsx .ts .mts .cts .tsx` |
| `pypi` | `python` | `.py .pyi` |
| `maven` | `java` | `.java` |
| `golang` | `go` | `.go` |
| `gem` | `ruby` | `.rb` |
| `composer` | `php` | `.php` |
| `cargo` | `rust` | `.rs` |
| `nuget` | `csharp` | `.cs` |

`SupportedEcosystem` values are the canonical spellings — `golang` (not `go`), `gem` (not `rubygems`). This mismatch was a real bug during M9 testing; see the Phase 2 memory notes.

---

## JavaScript / TypeScript

Grammars: `tree-sitter-javascript.wasm`, `tree-sitter-typescript.wasm`, `tree-sitter-tsx.wasm`. Selection is by file extension — see `pickWasmForFile()` in `languages/javascript.ts`.

### Imports

Three forms cover ~all real code:

```js
import foo from 'bar';                       // default
import { a, b as c } from 'bar';             // named
import * as ns from 'bar';                   // namespace
import 'bar';                                // side-effect

const foo = require('bar');                  // CJS default
const { a, b: c } = require('bar');          // CJS destructure
const app = require('bar')(config);          // CJS IIFE (fastify style)
```

All of the above land in `ImportBinding[]` with the appropriate `kind`. The extractor records both `localName` (what the file uses) and `importedName` (the original export name), so aliases work naturally.

### Useful node types

- `import_statement`, `import_clause`, `named_imports`, `import_specifier`, `namespace_import`
- `call_expression` with `childForFieldName('function')` → `identifier` | `member_expression`
- `member_expression` has `object` + `property` fields
- `variable_declarator` with `name` + `value` fields
- `arrow_function`, `function_expression`, `function_declaration`

### Decorators (TS/TSX)

**Quirk:** `tree-sitter-typescript` nests decorators **inside** the decorated `class_declaration` as leading named children, not as preceding siblings. But when a class is wrapped in `export_statement`, decorators may also appear as siblings on the wrapper. Your detector must check both locations. See `detectors/nestjs.ts` for the dual-path walk.

Decorator shapes:
- `decorator > identifier` — bare `@Injectable`
- `decorator > call_expression` — `@Controller('users')`
- `decorator > member_expression` — `@Common.Injectable()` (rare)

### Strings

`string` nodes have named children: `string_start`, zero or more `string_fragment`, `string_end`. For literal content, take the `string_fragment` child's text. The helper `stringLiteralValue` handles this plus a quote-strip fallback.

### Helpers

`src/framework-rules/util/javascript.ts` — reference these instead of hand-walking: `walkTree`, `findInstancesOfImport`, `handlerDescriptor`, `stringLiteralValue`, `detectAuthMechanism`.

---

## Python

Grammar: `tree-sitter-python.wasm`.

### Imports

```py
import foo
import foo.bar
import foo as baz
from foo import bar, baz
from foo import bar as x
from . import mod       # relative — dropped by the resolver
```

The Python resolver maps distribution names ↔ module names via a curated table (PyPI's `pillow` → `PIL`, `pyyaml` → `yaml`, etc.) in `import-mapping/pypi.ts`. Add entries there, not inside detectors.

### Useful node types

- `import_statement`, `import_from_statement`
- `function_definition` with `name` + `parameters` + `body` fields
- `class_definition`
- `decorator` (preceding sibling of `function_definition`/`class_definition`)
- `call` (note: `call`, not `call_expression`) with `function` + `arguments` fields
- `attribute` with `object` + `attribute` fields
- `assignment` with `left` field; the RHS is the second named child (no `right` field)

### Decorator-based routes (Flask, FastAPI, Starlette, AIOHttp)

Decorators sit as preceding named children of the `function_definition` (not as children of a wrapper). Walk function_definitions and read `decorator` children at the start.

**Quirk (starlette):** Current detector only supports the decorator form (`@app.route('/x')`). The list form (`routes=[Route(...)]`) is not parsed — don't write tests against it.

### Django urls.py

**Quirk:** The `django` detector prepends `/` to all patterns — tests must expect `/articles/<int:year>/` not `articles/<int:year>/`.

### Strings

`string` node with a `string_content` named child. `pythonStringLiteral` in `util/python.ts` handles f-strings and b-strings via a regex fallback.

### Helpers

`src/framework-rules/util/python.ts` — `findClassInstances`, `pythonStringLiteral`, `HTTP_METHOD_NAMES`, decorator walkers.

---

## Java

Grammar: `tree-sitter-java.wasm`.

### Imports

```java
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.*;
import static org.example.Foo.BAR;
```

The `ImportBinding.source` is the full dotted path. For detector triggers, use the package prefix (`'org.springframework.web.bind.annotation'`) — the prefix-match logic handles both single-class imports and wildcard imports.

### Annotations

Java annotations sit as `modifiers > annotation | marker_annotation` children on the class/method. The marker form (`@Override`) has no arguments; the full form (`@RequestMapping("/api")`) is `annotation > name + argument_list`.

Inside `argument_list`:
- Positional: `argument_list > element_value` (single value)
- Key=value: `argument_list > element_value_pair > identifier + element_value`
- Arrays: `element_value_array_initializer > element_value+`

### Useful node types

- `package_declaration`, `import_declaration`
- `class_declaration`, `method_declaration`
- `modifiers` (wraps annotations + visibility)
- `annotation`, `marker_annotation`, `element_value_pair`
- `string_literal` (single node, text includes the quotes)

### Maven groupId

Java dep resolution needs groupId to disambiguate artifacts. The SBOM captures it into `project_dependencies.namespace`; the `ImportResolver` joins `name + namespace` when mapping imports to deps.

### Helpers

`src/framework-rules/util/java.ts`. Detectors: `spring.ts`, `jaxrs.ts`, `quarkus.ts`, `micronaut.ts`.

---

## Go

Grammar: `tree-sitter-go.wasm`.

### Imports

```go
import "github.com/gin-gonic/gin"
import gin "github.com/gin-gonic/gin"        // aliased
import _ "github.com/lib/pq"                 // blank (side-effect)

import (
    "fmt"
    "github.com/gin-gonic/gin"
)
```

Imports without an alias use the package's last path segment as the local name (`github.com/gin-gonic/gin` → `gin`). The Go language module handles this automatically.

The workspace's own module path (read from `go.mod`) is excluded so internal imports don't falsely resolve to a dep.

### Useful node types

- `import_declaration`, `import_spec`, `import_spec_list`
- `short_var_declaration` (`r := gin.Default()`) vs `assignment_statement` (`r = gin.Default()`)
  - Both have `left` + `right` fields that are `expression_list` nodes — unwrap even for single-var assignments.
- `call_expression` with `function` field
- `selector_expression` with `operand` + `field` fields (this is how `gin.Default` and `r.GET` are parsed)
- `interpreted_string_literal` (has `interpreted_string_literal_content` named child) vs `raw_string_literal` (backticks)

### Factory-then-verb pattern

Most Go web frameworks follow `r := framework.Default()` + `r.VERB(pattern, handler)`. The generic helper `findInstancesFromFactory` + `findRouteCalls` in `util/go.ts` covers this — Gin, Echo, Fiber, Chi, and Gorilla Mux are all ~30 lines each.

### Helpers

`src/framework-rules/util/go.ts` — `findInstancesFromFactory`, `findRouteCalls`, `GO_HTTP_METHODS_UPPER`/`_PASCAL` (some frameworks use `GET`, others `Get`).

---

## Ruby

Grammar: `tree-sitter-ruby.wasm`.

### Imports

```rb
require 'sinatra'
require_relative './foo'
```

`require` is the primary form. `ImportBinding.source` is the stringified path.

### Useful node types

- `call` (with `method` + `receiver` fields, and `arguments`)
- `do_block`, `block_body`
- `method` (method definition)
- `class` (class definition, note: not `class_declaration`)
- `symbol`, `string`

### DSL / block patterns

Sinatra and Grape use block DSLs heavily — `get '/x' do ... end`. The detector walks top-level `call` nodes where the receiver is nil or matches the expected DSL class (`Grape::API`).

Rails is route-file-specific (`config/routes.rb`). The `rails` detector matches by filename convention plus the DSL call shape.

### Helpers

`src/framework-rules/util/ruby.ts`.

---

## PHP

Grammar: `tree-sitter-php.wasm`.

### Imports

```php
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Routing\Annotation\Route as RouteAttr;
```

Backslash-separated FQN. Trigger strings use backslashes (`'Symfony\\Component\\Routing\\Annotation\\Route'` in a detector source).

### PHP 8 attributes

**Major quirk.** PHP attributes (`#[Route('/users', methods: ['GET'])]`) have a shifting AST shape across grammar versions:

- Older grammars wrap each argument in `named_argument` / `keyword_argument` nodes
- Newer grammars emit named arguments as `argument > name + value` pairs directly (no wrapper)

Your detector must handle both — see `detectors/symfony.ts:findRouteAttribute()` for the canonical dual-shape check.

Relevant node types:
- `attribute_list` wraps attributes attached to a declaration
- `attribute_group` wraps multiple attributes in a single `#[A, B]` declaration
- `attribute` has a `name` field + a `parameters` field (on newer grammars) or positional child-1 (older)
- `argument`, `named_argument`, `keyword_argument` — all three shapes must be supported
- `array_creation_expression` contains `array_element_initializer` children

### Useful node types

- `namespace_use_declaration`, `namespace_use_clause`
- `class_declaration`, `method_declaration`, `declaration_list`
- `string` with `string_content` named child
- `method_declaration > attribute_list + ... + name` — method attributes are direct children, not inside a `modifiers` wrapper

### Helpers

`src/framework-rules/util/php.ts` — `phpStringLiteral` handles both single-quoted and double-quoted with interpolation.

---

## Rust

Grammar: `tree-sitter-rust.wasm`.

### Imports

```rust
use actix_web::{get, post, web, App, HttpServer};
use rocket::{get, post, routes};
extern crate rocket;   // legacy — NOT tracked by the detector
```

`extern crate` is the Rust 2015 form and intentionally not tracked — modern Rust uses `use`. When writing tests, stick with `use` syntax.

### Useful node types

- `use_declaration`, `use_tree`, `use_list`
- `attribute_item` (e.g. `#[get("/hello")]`) — sits as a preceding sibling of `function_item`
- `function_item` with `name` + `parameters` + `body` fields
- `token_tree` — argument list inside an attribute macro. You walk its children and shape-match tokens since there's no structured parse inside macros.
- `string_literal` with `string_content` named child

### Macro attributes vs macro calls

`#[get("/hello")]` parses as `attribute_item > scoped_identifier + token_tree`. But `warp::path!(...)` parses as `macro_invocation` — structurally different. The Warp detector intentionally doesn't support the macro form; test with `warp::path("hello")` (call form) instead.

### Auth heuristics

Rust detectors currently default to `PUBLIC_UNAUTH` unconditionally — we don't yet walk Actix/Axum middleware chains. Adding middleware-aware classification is follow-up work.

### Helpers

No dedicated Rust util module yet — Rust detectors are ~50 lines each and use `walkTree` + `textOf` directly. If a second Rust pattern emerges, extract shared helpers.

---

## C#

Grammar: `tree-sitter-c-sharp.wasm`.

### Imports

```csharp
using Microsoft.AspNetCore.Mvc;
using static System.Math;
global using System;     // C# 10
```

Full dotted namespace in `ImportBinding.source`.

### Useful node types

- `using_directive`
- `class_declaration`, `method_declaration`
- `attribute_list`, `attribute` — C# attributes wrap like Java annotations but sit in their own `attribute_list` nodes before the declaration
- `interpolated_string_expression`, `string_literal`

### Attribute-based routes (ASP.NET Core)

Attributes sit as `attribute_list > attribute` preceding the `class_declaration` / `method_declaration`. Walk the preceding attribute lists, find `[HttpGet]` / `[HttpGet("/path")]` / `[Route("/api")]` and emit.

### Minimal APIs

`app.MapGet("/hello", ...)` — convention-based, matches via the `minimal-apis` detector which looks for `MapGet` / `MapPost` / etc. on any instance. No trigger imports; runs on every C# file and gates on the method call shape.

### Auth heuristics

Like Rust, C# defaults to `PUBLIC_UNAUTH`. Middleware chain inspection is follow-up.

---

## General debugging tips

**Dump the AST.** When a detector misfires, the first move is always to see what the grammar actually produced. Drop a temporary log:

```ts
walkTree(tree, (node) => {
  console.error(`${'  '.repeat(depthOf(node))}${node.type} [${node.startPosition.row}:${node.startPosition.column}]`);
});
```

Or for a targeted shape:

```ts
console.error(node.toString());   // S-expression dump of the subtree
```

**Verify the trigger fires.** If `detect` never runs, the issue is `triggerImports`, not the AST walk. Log `file.imports.map((i) => i.source)` at the top of `detect` to confirm what the extractor sees.

**Re-run unit tests, not the full fixture.** Detector tests are ~500ms each; fixture regeneration is 15-20 min. Iterate on unit tests.

**Grammar version pin.** `tree-sitter-wasms` is version-pinned in `package.json`. Bumping it can silently change AST shapes — validate all fixture snapshots after any upgrade.

---

## Further reading

- `src/tree-sitter-extractor/languages/` — per-language extractor modules
- `src/framework-rules/util/` — helpers grouped by language
- `src/framework-rules/detectors/` — 34 concrete detectors to crib from
- `docs/framework-rule-pack-guide.md` — how to add a detector
- [web-tree-sitter docs](https://github.com/tree-sitter/tree-sitter/tree/master/lib/binding_web) — the underlying library
