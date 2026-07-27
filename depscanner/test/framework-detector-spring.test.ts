/**
 * Unit tests for the Spring framework detector — the classic controller-route
 * path AND the config-driven actuator endpoint enumeration (fix #3, part 2).
 *
 * Runs the real Java tree-sitter module + detector over inline source. The
 * actuator cases stage a temp workspace with a real application.properties so
 * `readActuatorExposure` has a config file to read (the detector reads actuator
 * exposure from `ctx.workspaceRoot`, independent of the parsed source).
 *
 * Run: npx tsx test/framework-detector-spring.test.ts
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { javaModule } from '../src/tree-sitter-extractor/languages/java';
import { entryPointsFor } from '../src/framework-rules/test-helpers';
import type { KnownDep } from '../src/tree-sitter-extractor/languages/types';
import type { EntryPoint } from '../src/framework-rules/types';

let failures = 0;
let passes = 0;

function assert(cond: unknown, msg: string): void {
  if (!cond) {
    console.error(`  FAIL: ${msg}`);
    failures++;
  } else {
    console.log(`  ok: ${msg}`);
    passes++;
  }
}

async function detect(
  source: string,
  opts: { workspaceRoot?: string; deps?: KnownDep[]; filePath?: string } = {},
): Promise<EntryPoint[]> {
  const file = await javaModule.extractFile(
    source,
    opts.filePath ?? '/tmp/app/src/main/java/App.java',
    { deps: opts.deps ?? [], workspaceRoot: opts.workspaceRoot ?? '/tmp' },
  );
  return entryPointsFor(file, 'spring');
}

const CONTROLLER_SRC = `
package org.springframework.samples.petclinic.vet;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/vets")
class VetController {
    @GetMapping("/list")
    @ResponseBody
    public Object showVetList() { return null; }

    @PostMapping("/save")
    public String save() { return "redirect:/vets"; }
}
`;

function stageWorkspace(includeValue: string | null): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'spring-detector-'));
  const resDir = path.join(root, 'src', 'main', 'resources');
  fs.mkdirSync(resDir, { recursive: true });
  const lines = ['database=h2', 'spring.thymeleaf.mode=HTML'];
  if (includeValue !== null) {
    lines.push('# Actuator', `management.endpoints.web.exposure.include=${includeValue}`);
  }
  fs.writeFileSync(path.join(resDir, 'application.properties'), lines.join('\n') + '\n');
  return root;
}

function actuatorEps(eps: EntryPoint[]): EntryPoint[] {
  return eps.filter((e) => (e.metadata as any)?.actuator === true);
}

async function main(): Promise<void> {
  // ---------------------------------------------------------------------------
  // 1. Controller routes (regression) — join class prefix + verb methods.
  // ---------------------------------------------------------------------------
  console.log('controller routes (regression, no workspace config):');
  {
    const eps = await detect(CONTROLLER_SRC);
    const controllerEps = eps.filter((e) => (e.metadata as any)?.actuator !== true);
    assert(controllerEps.some((e) => e.httpMethod === 'GET' && e.routePattern === '/vets/list'), 'GET /vets/list');
    assert(controllerEps.some((e) => e.httpMethod === 'POST' && e.routePattern === '/vets/save'), 'POST /vets/save');
    assert(controllerEps.every((e) => e.entryPointType === 'http_route'), 'controller routes are http_route');
    // No workspace config → no actuator endpoints enumerated.
    assert(actuatorEps(eps).length === 0, 'no actuator endpoints without a config file');
  }

  // ---------------------------------------------------------------------------
  // 2. Actuator enumeration when exposure.include=* (petclinic shape).
  // ---------------------------------------------------------------------------
  console.log('\nactuator enumeration when exposed (include=*):');
  {
    const root = stageWorkspace('*');
    try {
      const eps = await detect(CONTROLLER_SRC, { workspaceRoot: root });
      const act = actuatorEps(eps);
      assert(act.length > 0, `actuator endpoints enumerated (got ${act.length})`);
      const loggersPost = act.find((e) => e.httpMethod === 'POST' && e.routePattern === '/actuator/loggers/{name}');
      assert(!!loggersPost, 'POST /actuator/loggers/{name} enumerated');
      assert((loggersPost?.metadata as any)?.json_body === true, 'loggers POST is flagged json_body');
      assert(loggersPost?.classification === 'PUBLIC_UNAUTH', 'unauthenticated (no Spring Security dep)');
      assert(act.some((e) => e.routePattern === '/actuator/health'), 'GET /actuator/health enumerated');
      assert(!act.some((e) => e.routePattern === '/actuator/shutdown'), 'shutdown NOT enumerated (off by default)');
      assert(act.every((e) => e.entryPointType === 'http_route' && e.framework === 'spring'), 'actuator rows are spring http_route');
      // Handler names unique per route (dedup key includes handler_name).
      const handlers = act.map((e) => e.handlerName);
      assert(new Set(handlers).size === handlers.length, 'actuator handler names are unique per route');
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  }

  // ---------------------------------------------------------------------------
  // 3. Explicit include list exposes only the named endpoints.
  // ---------------------------------------------------------------------------
  console.log('\nexplicit include list (health,info):');
  {
    const root = stageWorkspace('health,info');
    try {
      const act = actuatorEps(await detect(CONTROLLER_SRC, { workspaceRoot: root }));
      assert(act.some((e) => e.routePattern === '/actuator/health'), 'health exposed');
      assert(!act.some((e) => (e.metadata as any)?.endpoint_id === 'loggers'), 'loggers NOT exposed');
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  }

  // ---------------------------------------------------------------------------
  // 4. No exposure directive → no actuator endpoints.
  // ---------------------------------------------------------------------------
  console.log('\nno actuator exposure directive:');
  {
    const root = stageWorkspace(null);
    try {
      assert(actuatorEps(await detect(CONTROLLER_SRC, { workspaceRoot: root })).length === 0, 'no actuator endpoints when not exposed');
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  }

  // ---------------------------------------------------------------------------
  // 5. Spring Security present → actuator classified AUTH_INTERNAL.
  // ---------------------------------------------------------------------------
  console.log('\nSpring Security present → AUTH_INTERNAL:');
  {
    const root = stageWorkspace('*');
    try {
      const act = actuatorEps(
        await detect(CONTROLLER_SRC, {
          workspaceRoot: root,
          deps: [{ name: 'spring-boot-starter-security', namespace: null }],
        }),
      );
      assert(act.length > 0 && act.every((e) => e.classification === 'AUTH_INTERNAL'), 'actuator endpoints classified AUTH_INTERNAL when Spring Security is present');
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  }

  console.log(`\n${passes} passed, ${failures} failed`);
  if (failures > 0) process.exit(1);
}

main().catch((e) => { console.error(e); process.exit(1); });
