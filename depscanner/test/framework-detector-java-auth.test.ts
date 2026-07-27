/**
 * T7a — route-level auth classification + method-body spans for the Java
 * annotation detectors: Spring (@PreAuthorize SpEL, @Secured, method-beats-class,
 * SecurityFilterChain zero-carve-out centralized rule + belt), JAX-RS
 * (@RolesAllowed/@PermitAll/@DenyAll, JEE method-replaces-class), Quarkus
 * (@Authenticated), Micronaut (@Secured IS_AUTHENTICATED vs IS_ANONYMOUS).
 *
 * Run: npx tsx test/framework-detector-java-auth.test.ts
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { javaModule } from '../src/tree-sitter-extractor/languages/java';
import { entryPointsFor } from '../src/framework-rules/test-helpers';
import { resetSecurityChainMemo, workspaceHasFullSecurityChain } from '../src/framework-rules/util/java';
import type { EntryPoint } from '../src/framework-rules/types';

let failures = 0;
let passes = 0;
function assert(cond: unknown, msg: string): void {
  if (!cond) { console.error(`  FAIL: ${msg}`); failures++; }
  else { console.log(`  ok: ${msg}`); passes++; }
}
function eq(a: unknown, b: unknown, msg: string): void {
  assert(JSON.stringify(a) === JSON.stringify(b), `${msg} (got ${JSON.stringify(a)}, want ${JSON.stringify(b)})`);
}

async function detect(source: string, framework: string, workspaceRoot = '/tmp'): Promise<EntryPoint[]> {
  const file = await javaModule.extractFile(source, '/tmp/app/src/main/java/App.java', {
    deps: [], workspaceRoot,
  });
  return entryPointsFor(file, framework);
}

function byRoute(eps: EntryPoint[], pattern: string): EntryPoint | undefined {
  return eps.find((e) => e.routePattern === pattern);
}

async function run(): Promise<void> {
  // ==========================================================================
  console.log('\nSPRING — annotation evidence (method beats class)');
  // ==========================================================================
  {
    const eps = await detect(`
package app;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;

@RestController
@RequestMapping("/api")
public class ApiController {
  @GetMapping("/open")
  public String open(@RequestParam String q) { return q; }

  @PreAuthorize("isAuthenticated()")
  @GetMapping("/me")
  public String me(@RequestParam String q) { return q; }

  @PreAuthorize("permitAll()")
  @GetMapping("/docs")
  public String docs(@RequestParam String q) { return q; }

  @Secured("ROLE_ADMIN")
  @GetMapping("/admin")
  public String admin(@RequestParam String q) { return q; }
}
`, 'spring');
    eq(byRoute(eps, '/api/open')?.classification, 'PUBLIC_UNAUTH', 'no security annotation → PUBLIC (import sniff retired)');
    eq(byRoute(eps, '/api/me')?.classification, 'AUTH_INTERNAL', '@PreAuthorize(isAuthenticated()) → AUTH_INTERNAL');
    eq(byRoute(eps, '/api/docs')?.classification, 'PUBLIC_UNAUTH', '@PreAuthorize(permitAll()) SpEL → PUBLIC override');
    eq(byRoute(eps, '/api/admin')?.classification, 'AUTH_INTERNAL', '@Secured(ROLE_ADMIN) → AUTH_INTERNAL');
    const me = byRoute(eps, '/api/me')!;
    assert(me.handlerSpan != null, 'method-body span captured');
    eq(me.demotionEligible, true, 'declaration-bound → always eligible');
  }

  console.log('\nSPRING — class-level auth + method-level public override');
  {
    const eps = await detect(`
package app;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;

@RestController
@PreAuthorize("hasRole('USER')")
public class SecureController {
  @GetMapping("/covered")
  public String covered(@RequestParam String q) { return q; }

  @PreAuthorize("permitAll()")
  @GetMapping("/opted-out")
  public String optedOut(@RequestParam String q) { return q; }
}
`, 'spring');
    eq(byRoute(eps, '/covered')?.classification, 'AUTH_INTERNAL', 'class-level @PreAuthorize covers methods');
    eq(byRoute(eps, '/opted-out')?.classification, 'PUBLIC_UNAUTH', 'method-level permitAll beats class auth (Sem 2)');
  }

  console.log('\nSPRING — unresolvable SpEL constant is NOT evidence');
  {
    const eps = await detect(`
package app;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;

@RestController
public class ConstController {
  @PreAuthorize(SecurityRules.ADMIN_ONLY)
  @GetMapping("/const")
  public String c(@RequestParam String q) { return q; }
}
`, 'spring');
    eq(byRoute(eps, '/const')?.classification, 'PUBLIC_UNAUTH', 'constant-ref SpEL unresolvable → not evidence (fail-safe)');
  }

  // --- SecurityFilterChain centralized rule (workspace scan) ---
  console.log('\nSPRING — SecurityFilterChain zero-carve-out centralized coverage');
  const mkWorkspace = (securityJava: string | null): string => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'java-auth-test-'));
    if (securityJava !== null) {
      const cfgDir = path.join(dir, 'src', 'main', 'java', 'app', 'config');
      fs.mkdirSync(cfgDir, { recursive: true });
      fs.writeFileSync(path.join(cfgDir, 'SecurityConfig.java'), securityJava);
    }
    return dir;
  };
  const FULL_CHAIN = `
package app.config;
import org.springframework.security.web.SecurityFilterChain;
public class SecurityConfig {
  SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(a -> a.anyRequest().authenticated());
    return http.build();
  }
}
`;
  const CARVEOUT_CHAIN = `
package app.config;
import org.springframework.security.web.SecurityFilterChain;
public class SecurityConfig {
  SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(a -> a.requestMatchers("/public/**").permitAll().anyRequest().authenticated());
    return http.build();
  }
}
`;
  const CONTROLLER = `
package app;
import org.springframework.web.bind.annotation.*;

@RestController
public class HomeController {
  @GetMapping("/dashboard")
  public String dash(@RequestParam String q) { return q; }

  @PostMapping("/login")
  public String login(@RequestParam String u) { return u; }
}
`;
  {
    resetSecurityChainMemo();
    const ws = mkWorkspace(FULL_CHAIN);
    assert(workspaceHasFullSecurityChain(ws), 'full chain (anyRequest().authenticated(), no carve-outs) detected');
    const eps = await detect(CONTROLLER, 'spring', ws);
    eq(byRoute(eps, '/dashboard')?.classification, 'AUTH_INTERNAL', 'full chain covers annotation-less route');
    eq(byRoute(eps, '/login')?.classification, 'PUBLIC_UNAUTH', 'belt: /login never inherits the centralized demotion');
    fs.rmSync(ws, { recursive: true, force: true });
  }
  {
    resetSecurityChainMemo();
    const ws = mkWorkspace(CARVEOUT_CHAIN);
    assert(!workspaceHasFullSecurityChain(ws), 'permitAll carve-out kills centralized coverage (Sem 3)');
    const eps = await detect(CONTROLLER, 'spring', ws);
    eq(byRoute(eps, '/dashboard')?.classification, 'PUBLIC_UNAUTH', 'carve-out chain → no centralized coverage');
    fs.rmSync(ws, { recursive: true, force: true });
  }
  {
    resetSecurityChainMemo();
    const ws = mkWorkspace(null);
    assert(!workspaceHasFullSecurityChain(ws), 'no security config → no coverage');
    fs.rmSync(ws, { recursive: true, force: true });
    resetSecurityChainMemo();
  }

  // ==========================================================================
  console.log('\nJAX-RS — @RolesAllowed / @PermitAll / @DenyAll (JEE replacement)');
  // ==========================================================================
  {
    const eps = await detect(`
package app;
import javax.ws.rs.*;
import javax.annotation.security.RolesAllowed;
import javax.annotation.security.PermitAll;
import javax.annotation.security.DenyAll;

@Path("/items")
@RolesAllowed("user")
public class ItemResource {
  @GET
  public String list(@QueryParam("q") String q) { return q; }

  @PermitAll
  @GET @Path("/public")
  public String pub(@QueryParam("q") String q) { return q; }

  @DenyAll
  @GET @Path("/denied")
  public String denied() { return "x"; }
}
`, 'jaxrs');
    eq(byRoute(eps, '/items')?.classification, 'AUTH_INTERNAL', 'class @RolesAllowed inherited');
    eq(byRoute(eps, '/items/public')?.classification, 'PUBLIC_UNAUTH', 'method @PermitAll replaces class auth (JEE)');
    eq(byRoute(eps, '/items/denied')?.classification, 'AUTH_INTERNAL', '@DenyAll ≠ public surface');
    assert(byRoute(eps, '/items')!.handlerSpan != null, 'jaxrs method span captured');
    eq(byRoute(eps, '/items')!.demotionEligible, true, 'jaxrs declaration-bound eligible');
  }

  // ==========================================================================
  console.log('\nQUARKUS — @Authenticated');
  // ==========================================================================
  {
    const eps = await detect(`
package app;
import javax.ws.rs.*;
import io.quarkus.security.Authenticated;

@Path("/q")
public class QResource {
  @Authenticated
  @GET @Path("/me")
  public String me(@QueryParam("q") String q) { return q; }

  @GET @Path("/open")
  public String open(@QueryParam("q") String q) { return q; }
}
`, 'quarkus');
    eq(byRoute(eps, '/q/me')?.classification, 'AUTH_INTERNAL', '@Authenticated → AUTH_INTERNAL');
    eq(byRoute(eps, '/q/open')?.classification, 'PUBLIC_UNAUTH', 'no annotation → PUBLIC');
  }

  // ==========================================================================
  console.log('\nMICRONAUT — @Secured rules');
  // ==========================================================================
  {
    const eps = await detect(`
package app;
import io.micronaut.http.annotation.*;
import io.micronaut.security.annotation.Secured;

@Controller("/m")
public class MController {
  @Secured(SecurityRule.IS_AUTHENTICATED)
  @Get("/me")
  public String me(@QueryValue String q) { return q; }

  @Secured(SecurityRule.IS_ANONYMOUS)
  @Get("/anon")
  public String anon(@QueryValue String q) { return q; }

  @Get("/open")
  public String open(@QueryValue String q) { return q; }
}
`, 'micronaut');
    eq(byRoute(eps, '/m/me')?.classification, 'AUTH_INTERNAL', '@Secured(IS_AUTHENTICATED) → AUTH_INTERNAL');
    eq(byRoute(eps, '/m/anon')?.classification, 'PUBLIC_UNAUTH', '@Secured(IS_ANONYMOUS) → explicit public');
    eq(byRoute(eps, '/m/open')?.classification, 'PUBLIC_UNAUTH', 'no @Secured → PUBLIC');
    assert(byRoute(eps, '/m/me')!.handlerSpan != null, 'micronaut method span captured');
  }

  console.log(`\n${passes} passed, ${failures} failed`);
  if (failures > 0) process.exit(1);
}

run().catch((e) => { console.error(e); process.exit(1); });
