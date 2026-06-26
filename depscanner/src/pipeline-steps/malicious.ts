/**
 * STEP: Malicious-package scan (OPTIONAL, soft-fail).
 *
 * Loads the project's resolved dependencies, runs the malicious-scan
 * pipeline (feed-lookup + GuardDog source-code analysis), and emits a
 * batched notification_events row when new findings land. Failure is
 * non-fatal and never blocks finalize.
 *
 * Self-contained — does not depend on the Phase 6 taint engine. The scan
 * builds its own per-project tree-sitter usage index for reachability
 * classification when the ecosystem is supported.
 */

import { runStage } from '../pipeline-stage-runner';
import { ScanFailedError } from '../scan-errors';
import type { SupportedEcosystem } from '../tree-sitter-extractor';
import type { PipelineContext } from '../pipeline-types';

export async function doMaliciousScan(ctx: PipelineContext): Promise<void> {
  const {
    supabase,
    job,
    projectId,
    organizationId,
    log,
    workspaceRoot,
    jobEcosystem,
    runId,
    checkCancelled,
    heartbeat,
  } = ctx;

  await runStage({
    name: 'malicious_scan',
    severity: 'error',
    supabase,
    jobId: job.jobId,
    projectId,
    log,
    onError: async ({ err }) => {
      const msg = `Malicious-package scan failed: ${(err as Error)?.message ?? err}`;
      await log.error('malicious_scan', msg);
      // severity: 'error' → runStage rethrows; the pipeline outer catch sets
      // the project to error state with this message.
      return { rethrow: true, throwAs: new ScanFailedError(msg) };
    },
    fn: async () => {
      const { data: pdRows, error: pdErr } = await supabase
        .from('project_dependencies')
        .select('id, name, namespace, version, dependency_id')
        .eq('project_id', projectId)
        .eq('last_seen_extraction_run_id', runId);
      if (pdErr) throw new Error(`malicious-scan failed to load dependencies: ${pdErr.message}`);

      const pdRowList = (pdRows ?? []) as Array<{
        id: string;
        name: string;
        namespace: string | null;
        version: string | null;
        dependency_id: string | null;
      }>;
      const depIds = Array.from(
        new Set(pdRowList.map((r) => r.dependency_id).filter((x): x is string => !!x)),
      );
      const ecoById = new Map<string, string>();
      if (depIds.length > 0) {
        const { data: depRows } = await supabase
          .from('dependencies')
          .select('id, ecosystem')
          .in('id', depIds);
        for (const d of (depRows ?? []) as Array<{ id: string; ecosystem: string }>) {
          ecoById.set(d.id, d.ecosystem);
        }
      }

      const packages = pdRowList
        .filter((r) => !!r.dependency_id && !!r.version)
        .map((r) => {
          // cdxgen splits a scoped npm package into name='supabase-js' +
          // namespace='@supabase'. Rejoin to the canonical
          // '@supabase/supabase-js' so the feed lookup + guarddog tarball
          // fetch key on the real registry name — otherwise a legit scoped
          // package collides with an unscoped typosquat malware advisory of
          // the same bare name (the @supabase/supabase-js ⟷ "supabase-js"
          // false positive). Mirrors the phase63 PDV scope-rejoin; the `@`
          // guard is npm-only (Maven's group:name namespace has no `@`).
          const name =
            r.namespace && r.namespace.startsWith('@')
              ? `${r.namespace}/${r.name}`
              : r.name;
          return {
            project_dependency_id: r.id,
            dependency_id: r.dependency_id as string,
            name,
            ecosystem: ecoById.get(r.dependency_id as string) ?? jobEcosystem,
            version: r.version,
          };
        });

      const { runMaliciousScan, eventDeduplicationKey } = await import('../malicious-scan');
      // Pass workspace info so the scan can build its own per-project
      // tree-sitter usage index for reachability classification.
      const supportedReachabilityEcosystems: readonly SupportedEcosystem[] = [
        'npm', 'pypi', 'maven', 'golang', 'gem', 'composer', 'cargo', 'nuget',
      ];
      const workspaceEcosystem = supportedReachabilityEcosystems.includes(
        jobEcosystem as SupportedEcosystem,
      )
        ? (jobEcosystem as SupportedEcosystem)
        : null;
      const result = await runMaliciousScan({
        supabase,
        projectId,
        organizationId,
        extractionRunId: runId,
        jobId: job.jobId ?? runId,
        packages,
        workspaceRoot,
        workspaceEcosystem,
        log,
        checkCancelled,
        heartbeat,
      });

      // Emit one batched event per (org, project, run). Idempotent via
      // dedup key — second extraction with no new findings emits nothing
      // because the upsert RPC returned 0.
      if (result.inserted_findings > 0) {
        try {
          const dedupKey = eventDeduplicationKey(organizationId, projectId, runId);
          const { data: insertedEvent, error: insertErr } = await supabase
            .from('notification_events')
            .insert({
              event_type: 'malicious_package_detected',
              organization_id: organizationId,
              project_id: projectId,
              payload: {
                organization_id: organizationId,
                project_id: projectId,
                extraction_run_id: runId,
                feed_hits: result.feed_hits,
                guarddog_hits: result.guarddog_hits,
                inserted_findings: result.inserted_findings,
              },
              source: 'extraction_worker',
              priority: 'critical',
              deduplication_key: dedupKey,
              status: 'pending',
            })
            .select('id')
            .single();

          // Trigger immediate dispatch via backend internal endpoint.
          // Without this, the row sits at status='pending' and only fires
          // when the reconcile-stuck-notifications cron sweeps it (≤10m
          // delay). For a critical-class event that delay is unacceptable.
          // If the dispatch call fails we leave the row pending and rely
          // on the reconciler — same eventual safety net, slower path.
          if (!insertErr && insertedEvent?.id) {
            try {
              const backendBaseUrl = process.env.BACKEND_URL || process.env.API_BASE_URL || 'http://localhost:3001';
              const internalKey = process.env.INTERNAL_API_KEY;
              if (internalKey) {
                const url = `${backendBaseUrl.replace(/\/$/, '')}/api/workers/dispatch-notification`;
                await fetch(url, {
                  method: 'POST',
                  headers: {
                    'Content-Type': 'application/json',
                    'X-Internal-Api-Key': internalKey,
                  },
                  body: JSON.stringify({ eventId: insertedEvent.id }),
                });
              }
            } catch (dispatchErr: any) {
              await log.warn('malicious_scan', `Dispatch trigger failed (reconciler will retry): ${dispatchErr?.message ?? dispatchErr}`);
            }
          } else if (insertErr && (insertErr as any).code !== '23505') {
            // 23505 = dedup hit on (org, dedup_key) — expected on idempotent re-run.
            await log.warn('malicious_scan', `Event emission failed: ${insertErr.message ?? insertErr}`);
          }
        } catch (eventErr: any) {
          // Non-fatal — findings are already in the DB; the dispatcher
          // can still surface them on read.
          await log.warn('malicious_scan', `Event emission failed: ${eventErr?.message ?? eventErr}`);
        }
      }

      // Persist scan_status onto scan_jobs for the malicious-specific
      // "Partial coverage" banner.
      if (job.jobId) {
        try {
          await supabase
            .from('scan_jobs')
            .update({ malicious_scan_status: result.status })
            .eq('id', job.jobId);
        } catch (e) {
          // Non-fatal: the status column only drives the malicious "Partial
          // coverage" banner. A transient write miss shouldn't fail an
          // otherwise-successful scan.
          await log.warn('malicious_scan', `malicious_scan_status write failed (non-fatal): ${(e as Error)?.message ?? e}`);
        }
      }

      // Hard-fail only when the scan genuinely FAILED (a crash, e.g. GuardDog
      // missing or erroring). 'partial' is a routine outcome (an ecosystem
      // GuardDog only partly supports) and keeps its own dedicated "Partial
      // coverage" banner — it does NOT fail the scan.
      if (result.status === 'failed') {
        throw new Error('Malicious-package scanner did not complete');
      }
    },
  });
}
