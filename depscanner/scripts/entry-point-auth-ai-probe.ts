/**
 * LIVE probe: does the fp-filter route-context injection (T5) actually change
 * the real model's endpoint verdict? (entry-point auth classification, T13d).
 *
 * Runs the REAL DeepInfra Qwen fp-filter over the express fixture's authed
 * lodash flow (req.query.tpl -> _.template inside the requireAuth-guarded
 * /api/admin/render handler) TWICE: once with no route context (the model sees
 * only the code) and once WITH the span-matched route context injected. Prints
 * both endpoint verdicts so we can see the injected middleware chain move the
 * model toward AUTH_INTERNAL.
 *
 * Needs DEEPINFRA_API_KEY (loaded from backend/.env). Costs a few cents.
 *
 * Run: npx tsx scripts/entry-point-auth-ai-probe.ts
 */
import * as path from 'path';
import * as dotenv from 'dotenv';
import { extractUsage } from '../src/tree-sitter-extractor';
import { buildEntryPointAuthMap, runPostProcess } from '../src/framework-rules/build-auth-map';
import { runEngineCore } from '../src/taint-engine/runner';
import { filterFlow } from '../src/taint-engine/fp-filter';
import { matchFlowToRoutes } from '../src/taint-engine/match-flow-to-routes';

dotenv.config({ path: path.resolve(__dirname, '../../backend/.env') });

const noopLogger = { async log() {} };
const ctx = { organizationId: 'probe', userId: 'probe', projectId: 'probe', extractionRunId: 'probe' };

async function main(): Promise<void> {
  const apiKey = process.env.DEEPINFRA_API_KEY;
  if (!apiKey) { console.error('DEEPINFRA_API_KEY not set — cannot run the live probe'); process.exit(2); }

  const workspaceRoot = path.resolve(__dirname, '..', 'test-repos', 'express');
  const extraction = await extractUsage({
    workspaceRoot, ecosystem: 'npm',
    deps: [{ name: 'express', namespace: null }, { name: 'lodash', namespace: null }],
  });
  const postRecords = await runPostProcess(extraction.files, workspaceRoot);
  const authMap = buildEntryPointAuthMap(extraction.files, postRecords, workspaceRoot);
  const engine = await runEngineCore({ workspaceRoot, ecosystem: 'npm' });
  const flows = engine.propagation?.flows ?? [];
  const adminFlow = flows.find((f) => f.entry_point_file.includes('admin.js'));
  if (!adminFlow) { console.error('no admin.js flow emitted — cannot probe'); process.exit(3); }

  const contextRoute = matchFlowToRoutes(authMap, adminFlow.entry_point_file, adminFlow.entry_point_line).contextRoute;
  console.log(`flow: ${adminFlow.entry_point_file}:${adminFlow.entry_point_line} -> ${adminFlow.sink_method}`);
  console.log(`span-matched route: ${contextRoute?.routePattern} middleware=${JSON.stringify(contextRoute?.middlewareChain)}\n`);

  const runOnce = async (routeContext: typeof contextRoute | null, label: string) => {
    const result = await filterFlow(
      { flow: adminFlow, workspaceRoot, apiKey, specs: engine.specs, routeContext },
      noopLogger, ctx,
    );
    const endpoint = (result as any).endpoint;
    console.log(`[${label}] verdict=${(result as any).verdict ?? (result as any).errorMessage} endpoint=${endpoint ? endpoint.classification : 'n/a'}`);
    if (endpoint?.reasoning) console.log(`  reasoning: ${endpoint.reasoning}`);
    return endpoint?.classification ?? null;
  };

  const without = await runOnce(null, 'NO route context ');
  const withCtx = await runOnce(contextRoute, 'WITH route ctx  ');

  console.log('');
  if (withCtx === 'AUTH_INTERNAL') {
    console.log('LIVE PROOF: with the injected requireAuth chain, the real model classifies the endpoint AUTH_INTERNAL.');
  } else {
    console.log(`Model returned endpoint=${withCtx} with context (without=${without}). Injection fired; the model's verdict is its own.`);
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
