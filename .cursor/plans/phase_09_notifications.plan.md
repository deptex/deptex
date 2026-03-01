---
name: Phase 9 - Notifications & Integrations
overview: Event bus, notification dispatcher, 8 destination types, rate limiting.
todos:
  - id: phase-9-notifications
    content: "Phase 9: Notifications & Integrations - Event bus architecture (20 event types, notification_events table, QStash async dispatch), notification dispatcher engine (org/team/project rule cascade, isolated-vm sandbox execution, deduplication), trigger code validation on save (syntax + shape + fetch resilience, reuses Phase 4 pattern), enhanced trigger context with custom return values, 8 destination dispatchers (Slack Block Kit, Discord embeds, Jira tickets, Linear issues, Asana tasks, Email HTML, Custom HMAC webhooks, PagerDuty), batching + smart grouping (30s window, critical bypass), rate limiting (per-org + per-destination), delivery tracking + notification history UI, weekly digest via QStash cron, test/preview rules with dry run, event source integration hooks across extraction/PR/vuln-monitor/policy/watchtower/AI-fix pipelines, edge cases + 50-test suite"
    status: pending
isProject: false
---

## Phase 9: Notifications and Integrations

**Goal:** Build an enterprise-grade event-driven notification system that connects every meaningful action in Deptex (extraction, vulnerability discovery, PR checks, policy evaluation, AI fixes) to configurable notification rules at the org, team, and project levels, delivering alerts to Slack, Discord, Jira, Linear, Asana, email, PagerDuty, and custom webhooks with batching, rate limiting, delivery tracking, and full observability.

**Key design decisions:**

- Events are **persisted** to a `notification_events` table before dispatch (audit trail, replay, debugging)
- Dispatch is **async via QStash** -- the event source (extraction, PR handler, etc.) fires and forgets; delivery happens in the background
- Rule cascade is **additive**: org rules + team rules + project rules ALL fire independently (not override). Deduplication prevents the same destination receiving the same event twice
- Trigger code runs in the **same isolated-vm sandbox** as Phase 4 policy code, with the same `fetch()` support, timeout, and memory limits
- Code validation on save uses the **same 3-check pattern** as Phase 4: syntax compilation, shape validation (must return boolean or enhanced object), fetch resilience
- **Batching** groups high-volume events (e.g., 50 deps changed in one extraction) into a single summary notification. Critical events (malicious package, CISA KEV) bypass batching for immediate delivery
- **Rate limiting** prevents notification storms: per-org and per-destination hourly caps with burst allowance
- Custom webhook delivery uses the **existing HMAC-SHA256 signing** pattern (`X-Deptex-Signature`, `X-Deptex-Event` headers) with exponential backoff retries
- Each destination type has a dedicated **dispatcher module** that formats the event into the native format (Slack Block Kit, Jira ticket fields, etc.)

**Current state (what exists):**

- Notification rules tables: `organization_notification_rules`, `team_notification_rules`, `project_notification_rules` -- all with `name`, `trigger_type`, `custom_code`, `destinations` JSONB, `active`, `min_depscore_threshold`
- `trigger_type` CHECK constraint: `'weekly_digest' | 'vulnerability_discovered' | 'custom_code_pipeline'` (Phase 9 simplifies this to just `'weekly_digest' | 'custom_code_pipeline'` -- see 9N)
- Frontend: `NotificationRulesSection.tsx` with create/edit sidebar, `PolicyCodeEditor` for custom code, `NotificationAIAssistant` for AI-generated trigger code, destination picker (Slack, Discord, Jira, Linear, Asana, email, custom webhooks)
- Integration connections: `organization_integrations`, `team_integrations`, `project_integrations` tables storing OAuth tokens, webhook URLs, HMAC secrets for all providers
- Custom webhook test ping: `POST /organizations/:orgId/custom-integrations/:id/test` with HMAC signing and 10s timeout
- Email: `ee/backend/lib/email.ts` with nodemailer/Gmail transport
- Docs page: `NotificationRulesContent` with 10 trigger event types, context object reference, 6 example trigger functions
- **NOT implemented**: `notification-dispatcher.ts`, event emission, rule execution, destination delivery, batching, rate limiting, delivery tracking, weekly digest

### 9A: Event Type Catalog

Complete catalog of events that flow through the notification system. Each event has a `type` string, a `source` (which pipeline emits it), and a `category` for grouping in the UI.

**Vulnerability Events:**


| Event Type                         | Description                                                     | Source                                                     |
| ---------------------------------- | --------------------------------------------------------------- | ---------------------------------------------------------- |
| `vulnerability_discovered`         | New CVE/advisory found affecting a project dependency           | Background vuln monitoring (Phase 6D), extraction pipeline |
| `vulnerability_severity_increased` | EPSS score jumped significantly, or CISA KEV flag added         | Background vuln monitoring                                 |
| `vulnerability_resolved`           | Vuln no longer affects project (dep upgraded or vuln withdrawn) | Extraction pipeline (diff comparison)                      |


**Dependency Events:**


| Event Type              | Description                                     | Source                                |
| ----------------------- | ----------------------------------------------- | ------------------------------------- |
| `dependency_added`      | New dependency added to a project               | Extraction pipeline (diff comparison) |
| `dependency_updated`    | Dependency version changed                      | Extraction pipeline (diff comparison) |
| `dependency_removed`    | Dependency removed from a project               | Extraction pipeline (diff comparison) |
| `dependency_deprecated` | Upstream package marked as deprecated           | Watchtower poller                     |
| `new_version_available` | Newer version of a tracked dependency published | Watchtower poller                     |


**Policy and Compliance Events:**


| Event Type             | Description                                                        | Source                               |
| ---------------------- | ------------------------------------------------------------------ | ------------------------------------ |
| `policy_violation`     | Package policy returned `allowed: false` for a dependency          | Policy evaluation (after extraction) |
| `license_violation`    | Dependency has a banned or unapproved license                      | Policy evaluation                    |
| `status_changed`       | Project custom status changed (e.g., "Compliant" -> "Blocked")     | Policy evaluation                    |
| `compliance_violation` | Project transitioned from a passing status to a non-passing status | Policy evaluation                    |


**PR and Sync Events:**


| Event Type             | Description                                 | Source                       |
| ---------------------- | ------------------------------------------- | ---------------------------- |
| `extraction_completed` | Dependency extraction finished (success)    | Extraction pipeline          |
| `extraction_failed`    | Dependency extraction failed with error     | Extraction pipeline          |
| `pr_check_completed`   | PR guardrails check finished (pass or fail) | PR webhook handler (Phase 8) |


**Security Events:**


| Event Type                   | Description                                                              | Source                         |
| ---------------------------- | ------------------------------------------------------------------------ | ------------------------------ |
| `malicious_package_detected` | Dependency flagged as potentially malicious                              | Extraction pipeline (Phase 3A) |
| `supply_chain_anomaly`       | Suspicious commit activity or behavioral anomaly in a dependency         | Watchtower poller              |
| `security_analysis_failure`  | Registry integrity, install scripts, or entropy analysis returned "fail" | Watchtower poller              |


**AI Events:**


| Event Type         | Description                                         | Source                    |
| ------------------ | --------------------------------------------------- | ------------------------- |
| `ai_fix_completed` | AI-powered fix PR was generated for a vulnerability | AI fix pipeline (Phase 7) |


**System Events:**


| Event Type           | Description                                          | Source                                                         |
| -------------------- | ---------------------------------------------------- | -------------------------------------------------------------- |
| `risk_score_changed` | Project health score crossed a significant threshold | Health score calculation (after extraction or vuln monitoring) |


**Event priority classification** (used by batching engine in 9H):

- **Critical** (immediate, never batched): `malicious_package_detected`, `vulnerability_discovered` with CISA KEV flag, `security_analysis_failure`
- **High** (batched with 10s window): `vulnerability_discovered` (non-KEV critical/high), `compliance_violation`, `pr_check_completed` with failures, `ai_fix_completed`
- **Normal** (batched with 30s window): all other events
- **Low** (batched with 5min window): `new_version_available`, `risk_score_changed`

### 9B: Event Bus Architecture

Central event emission and async dispatch system. Every event goes through a single `emitEvent()` function that persists the event and queues delivery.

**File:** `ee/backend/lib/event-bus.ts`

```typescript
export interface DeptexEvent {
  type: string;                    // e.g. 'vulnerability_discovered'
  organizationId: string;
  projectId?: string;              // null for org-wide events
  teamId?: string;                 // resolved from project's owner team
  payload: Record<string, any>;    // event-specific data (dependency, vulnerability, PR info, etc.)
  source: string;                  // 'extraction' | 'vuln_monitor' | 'pr_handler' | 'policy_eval' | 'watchtower' | 'ai_fix' | 'system'
  priority: 'critical' | 'high' | 'normal' | 'low';
  deduplicationKey?: string;       // optional key to prevent duplicate events (e.g. `vuln:${osvId}:${projectId}`)
}

/**
 * Emit an event into the notification pipeline.
 * 1. Persist to notification_events table
 * 2. Queue async dispatch via QStash
 * Returns the event ID for tracking.
 */
const CRITICAL_EVENT_TYPES = ['malicious_package_detected', 'security_analysis_failure'];

export async function emitEvent(event: DeptexEvent): Promise<string> {
  const isCritical = event.priority === 'critical' || CRITICAL_EVENT_TYPES.includes(event.type);

  try {
    // 1. Resolve teamId from project if not provided
    const teamId = event.teamId || await resolveTeamId(event.projectId);

    // 2. Persist event (upsert on dedup key to prevent race conditions -- see 9N index)
    let row: { id: string };
    if (event.deduplicationKey) {
      const { data, error } = await supabase
        .from('notification_events')
        .insert({
          event_type: event.type,
          organization_id: event.organizationId,
          project_id: event.projectId,
          team_id: teamId,
          payload: event.payload,
          source: event.source,
          priority: event.priority,
          deduplication_key: event.deduplicationKey,
          status: 'pending',
        })
        .select('id')
        .single();

      if (error) {
        // UNIQUE constraint violation = duplicate, return the existing event ID
        if (error.code === '23505') {
          const { data: existing } = await supabase
            .from('notification_events')
            .select('id')
            .eq('deduplication_key', event.deduplicationKey)
            .order('created_at', { ascending: false })
            .limit(1)
            .single();
          return existing?.id ?? 'dedup-skipped';
        }
        throw error;
      }
      row = data;
    } else {
      const { data, error } = await supabase
        .from('notification_events')
        .insert({
          event_type: event.type,
          organization_id: event.organizationId,
          project_id: event.projectId,
          team_id: teamId,
          payload: event.payload,
          source: event.source,
          priority: event.priority,
          status: 'pending',
        })
        .select('id')
        .single();

      if (error) throw error;
      row = data;
    }

    // 3. Queue dispatch via QStash
    await queueNotificationDispatch(row.id, event.priority);

    return row.id;
  } catch (error) {
    console.error(`[event-bus] emitEvent failed for ${event.type}:`, error, {
      organizationId: event.organizationId,
      projectId: event.projectId,
      eventType: event.type,
      priority: event.priority,
    });

    // Critical events: propagate the error so the calling pipeline knows
    // the notification was NOT sent (extraction/PR handler can decide what to do)
    if (isCritical) {
      throw error;
    }

    // Non-critical: swallow the error -- don't crash the source pipeline
    // over a notification failure. The stuck-event reconciliation job (9B.2)
    // will catch events that were persisted but not queued.
    return 'emit-failed';
  }
}
```

**QStash dispatch queuing:**

```typescript
async function queueNotificationDispatch(eventId: string, priority: string): Promise<void> {
  const delay = priority === 'critical' ? 0 :
                priority === 'high' ? 0 :
                priority === 'normal' ? 30 :   // 30s batching window
                300;                            // 5min for low priority

  await qstash.publishJSON({
    url: `${API_BASE_URL}/api/workers/dispatch-notification`,
    body: { eventId },
    retries: 5,
    delay: `${delay}s`,
    headers: {
      'Upstash-Flow-Control-Key': `notifications-${eventId.slice(0, 8)}`,
    },
  });
}
```

The delay enables batching: multiple events that arrive within the window are collected and dispatched together (see 9H).

**Batch event emission** for high-volume scenarios (e.g., extraction completing with 50 dep changes):

```typescript
/**
 * Emit multiple events from a single source action.
 * Groups events by type and creates batch entries in notification_events,
 * then queues a single dispatch job for the batch.
 */
export async function emitEventBatch(events: DeptexEvent[]): Promise<string[]> {
  if (events.length === 0) return [];

  // Separate critical events (dispatch immediately) from batchable ones
  const critical = events.filter(e => e.priority === 'critical');
  const batchable = events.filter(e => e.priority !== 'critical');

  const ids: string[] = [];

  // Critical events: emit individually for immediate dispatch
  for (const event of critical) {
    ids.push(await emitEvent(event));
  }

  // Batchable events: insert all, queue one dispatch job with batch_id
  if (batchable.length > 0) {
    const batchId = crypto.randomUUID();
    const rows = batchable.map(e => ({
      event_type: e.type,
      organization_id: e.organizationId,
      project_id: e.projectId,
      team_id: e.teamId,
      payload: e.payload,
      source: e.source,
      priority: e.priority,
      deduplication_key: e.deduplicationKey,
      batch_id: batchId,
      status: 'pending',
    }));

    const { data } = await supabase
      .from('notification_events')
      .insert(rows)
      .select('id');

    ids.push(...(data?.map(r => r.id) || []));

    // Queue one dispatch job for the entire batch
    await qstash.publishJSON({
      url: `${API_BASE_URL}/api/workers/dispatch-notification-batch`,
      body: { batchId, eventCount: batchable.length },
      retries: 5,
      delay: '30s',
    });
  }

  return ids;
}
```

### 9B.2: Stuck Event Reconciliation

A QStash CRON job that runs every 15 minutes to catch events that were persisted to `notification_events` but never dispatched (e.g., QStash was down, or `emitEvent()` succeeded on the insert but failed on the queue step).

**Schedule:**

```typescript
await qstash.schedules.create({
  destination: `${API_BASE_URL}/api/workers/reconcile-stuck-notifications`,
  cron: '*/15 * * * *', // every 15 minutes
});
```

**Endpoint:**

```typescript
router.post('/reconcile-stuck-notifications', verifyQStash, async (req, res) => {
  const TEN_MINUTES_AGO = new Date(Date.now() - 10 * 60 * 1000).toISOString();
  const MAX_DISPATCH_ATTEMPTS = 3;

  // Find events stuck in 'pending' for over 10 minutes with < 3 attempts
  const { data: stuckEvents } = await supabase
    .from('notification_events')
    .select('id, priority, dispatch_attempts')
    .eq('status', 'pending')
    .lt('created_at', TEN_MINUTES_AGO)
    .lt('dispatch_attempts', MAX_DISPATCH_ATTEMPTS)
    .limit(100);

  if (!stuckEvents || stuckEvents.length === 0) {
    return res.json({ reconciled: 0 });
  }

  let reconciled = 0;
  for (const event of stuckEvents) {
    try {
      // Increment dispatch_attempts
      await supabase
        .from('notification_events')
        .update({ dispatch_attempts: (event.dispatch_attempts || 0) + 1 })
        .eq('id', event.id);

      // Re-queue via QStash
      await queueNotificationDispatch(event.id, event.priority);
      reconciled++;
    } catch (error) {
      console.error(`[reconcile] Failed to re-queue event ${event.id}:`, error);
    }
  }

  // Mark events that have exhausted all attempts as 'failed'
  await supabase
    .from('notification_events')
    .update({ status: 'failed' })
    .eq('status', 'pending')
    .lt('created_at', TEN_MINUTES_AGO)
    .gte('dispatch_attempts', MAX_DISPATCH_ATTEMPTS);

  res.json({ reconciled, total_stuck: stuckEvents.length });
});
```

**Database:** Requires a `dispatch_attempts` column on `notification_events` (see 9N).

### 9B.1: Sandbox fetch() SSRF Protection

The `fetch()` proxy used by trigger code (same isolated-vm sandbox as Phase 4 policy code) must block requests to private networks and cloud metadata endpoints before forwarding. This prevents malicious or careless org admins from using trigger code to probe internal infrastructure.

**Blocklist (applied before connecting):**

- IPv4 private ranges: `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- IPv4 link-local: `169.254.0.0/16` (includes AWS/GCP metadata at `169.254.169.254`)
- IPv6 loopback: `::1`
- IPv6 private: `fd00::/8`
- Explicit block: any URL matching `http://169.254.169.254/`* (cloud instance metadata)

**DNS rebinding prevention:**

Resolve the hostname to an IP address **before** opening the connection. If the resolved IP falls within any blocked range, reject the request immediately. This prevents an attacker from pointing a domain at `169.254.169.254` to bypass hostname-based checks.

```typescript
import { isIP } from 'net';
import { lookup } from 'dns/promises';

const BLOCKED_CIDRS = [
  { prefix: '127.', mask: 8 },
  { prefix: '10.', mask: 8 },
  { prefix: '172.16.', mask: 12 },
  { prefix: '192.168.', mask: 16 },
  { prefix: '169.254.', mask: 16 },
];

async function validateFetchUrl(url: string): Promise<{ allowed: boolean; error?: string }> {
  const parsed = new URL(url);
  const hostname = parsed.hostname;

  // Block direct IP addresses in private ranges
  if (isIP(hostname)) {
    if (isBlockedIP(hostname)) {
      return { allowed: false, error: `Blocked: ${hostname} is in a private IP range` };
    }
    return { allowed: true };
  }

  // Resolve hostname and check the resolved IP
  try {
    const { address } = await lookup(hostname);
    if (isBlockedIP(address)) {
      return { allowed: false, error: `Blocked: ${hostname} resolves to private IP ${address}` };
    }
  } catch {
    return { allowed: false, error: `DNS resolution failed for ${hostname}` };
  }

  return { allowed: true };
}

function isBlockedIP(ip: string): boolean {
  if (ip === '::1') return true;
  if (ip.startsWith('fd')) return true; // fd00::/8
  return BLOCKED_CIDRS.some(cidr => ip.startsWith(cidr.prefix));
}
```

**Audit logging:**

All fetch() calls from notification trigger code are logged to the same audit trail as Phase 4 policy fetch calls. Each log entry records: `organization_id`, `rule_id`, `url`, `resolved_ip`, `status_code`, `response_time_ms`, `blocked` (boolean). This provides visibility into data exfiltration attempts.

**Integration:** This validation runs inside the `fetch()` proxy function that the isolated-vm sandbox calls. The same proxy is shared with Phase 4 policy code -- if Phase 4 has not yet added SSRF protection, implement it there first and Phase 9 inherits it automatically.

### 9C: Notification Dispatcher Engine

The core engine that evaluates rules against events and dispatches to destinations.

**File:** `ee/backend/lib/notification-dispatcher.ts`

**9C.1: Dispatch endpoint (QStash consumer)**

```typescript
// In ee/backend/routes/workers.ts
router.post('/dispatch-notification', verifyQStash, async (req, res) => {
  const { eventId } = req.body;
  try {
    await dispatchNotification(eventId);
    res.json({ success: true });
  } catch (error) {
    console.error('Notification dispatch failed:', error);
    // Return 503 so QStash retries
    res.status(503).json({ error: 'Dispatch failed, will retry' });
  }
});

router.post('/dispatch-notification-batch', verifyQStash, async (req, res) => {
  const { batchId } = req.body;
  try {
    await dispatchNotificationBatch(batchId);
    res.json({ success: true });
  } catch (error) {
    console.error('Batch notification dispatch failed:', error);
    res.status(503).json({ error: 'Dispatch failed, will retry' });
  }
});
```

**9C.2: Core dispatch logic**

```
dispatchNotification(eventId):
  1. Load event from notification_events by ID
  2. If event.status !== 'pending', return (already dispatched or failed)
  3. Set event.status = 'dispatching'

  4. Load ALL matching notification rules:
     a. Org rules:  WHERE organization_id = event.organization_id AND active = true
     b. Team rules: WHERE team_id = event.team_id AND active = true (if event has team_id)
     c. Project rules: WHERE project_id = event.project_id AND active = true (if event has project_id)
     -> Combine into a single list with scope tags ('org', 'team', 'project')

  5. Build the context object (see 9E) from event.payload + enrichment queries

  6. Filter rules by trigger_type:
     - 'weekly_digest' rules: SKIP (these are cron-driven, not event-driven -- see 9K)
     - 'custom_code_pipeline' rules: proceed to evaluation

  7. For EACH custom_code_pipeline rule:
     a. Check min_depscore_threshold: if set and event is vulnerability_discovered,
        skip if depscore < threshold (fast path, no sandbox needed)
     b. Execute rule.custom_code in isolated-vm sandbox with context
        - Timeout: 10 seconds (shorter than policy's 30s -- notifications should be fast)
        - Memory: 128MB (half of policy's 256MB -- trigger code is simpler)
     c. If code returns truthy value:
        - If returns `true`: use default message template for this event type
        - If returns `{ notify: true, message?, title?, priority? }`: use custom message/title
        - If returns `false` or `{ notify: false }`: skip this rule
     d. For each destination in rule.destinations:
        - Check deduplication: has this destination already been queued for this event? (from another rule)
        - If not duplicate: create a notification_deliveries row with status 'pending'

  8. Process all pending deliveries for this event:
     a. Group deliveries by destination type
     b. For each group: call the appropriate destination dispatcher (9F)
     c. Update delivery rows with status, response, timestamps

  9. Set event.status = 'dispatched' (or 'failed' if all deliveries failed)
```

**9C.3: Batch dispatch logic**

```
dispatchNotificationBatch(batchId):
  1. Load all events with this batch_id from notification_events
  2. Group events by (organization_id, project_id, event_type)
  3. For each group:
     a. Build a SUMMARY context (not individual per-event):
        - context.events = array of individual event payloads
        - context.summary = { total: N, by_type: { dependency_added: 5, dependency_updated: 12, ... } }
        - context.project, context.event.type = first event's type (or 'batch')
     b. Load and evaluate rules against the summary context
     c. Each rule's custom_code sees the batch -- it can filter on summary counts
     d. Dispatch summary notifications (one per destination, not one per event)
  4. Mark all events in batch as 'dispatched'
```

**9C.4: Deduplication logic**

When multiple rules (org + team + project) would send to the same destination for the same event:

```typescript
function shouldDedup(eventId: string, destinationId: string): boolean {
  // Check notification_deliveries for an existing pending/delivered row
  // with this event_id + destination integration ID
  const { data } = await supabase
    .from('notification_deliveries')
    .select('id')
    .eq('event_id', eventId)
    .eq('destination_id', destinationId)
    .in('status', ['pending', 'delivered', 'sending'])
    .limit(1);
  return (data?.length ?? 0) > 0;
}
```

If an org rule sends to Slack channel #security and a project rule also sends to the same Slack channel #security for the same event, only one message is sent.

**9C.5: OAuth Token Refresh Mutex**

When multiple dispatches fire concurrently for the same integration connection (e.g., 5 Jira deliveries in parallel), they may all discover the token is expired and attempt to refresh simultaneously. OAuth refresh tokens are typically single-use -- the first refresh invalidates the token, causing attempts 2-5 to fail.

Use a Redis-based mutex to serialize token refreshes per integration connection:

```typescript
async function refreshTokenWithMutex(connection: IntegrationConnection): Promise<void> {
  // Check if token is still valid
  if (connection.token_expires_at && new Date(connection.token_expires_at) > new Date(Date.now() + 60_000)) {
    return; // token has > 1 minute of life left
  }

  const lockKey = `token-refresh:${connection.id}`;
  const lockValue = crypto.randomUUID();
  const LOCK_TTL_MS = 30_000; // 30s max hold time

  // Try to acquire lock
  const acquired = await redis.set(lockKey, lockValue, { NX: true, PX: LOCK_TTL_MS });

  if (!acquired) {
    // Another dispatch is refreshing. Wait up to 5s, then re-read the token.
    await waitForLockRelease(lockKey, 5_000);
    // Re-fetch connection from DB to get the updated token
    const { data: updated } = await supabase
      .from('organization_integrations')
      .select('access_token, refresh_token, token_expires_at')
      .eq('id', connection.id)
      .single();
    if (updated) {
      connection.access_token = updated.access_token;
      connection.refresh_token = updated.refresh_token;
      connection.token_expires_at = updated.token_expires_at;
    }
    return;
  }

  try {
    // Perform the actual token refresh (provider-specific)
    const newTokens = await refreshOAuthToken(connection);

    // Update DB with new tokens
    await supabase
      .from('organization_integrations')
      .update({
        access_token: newTokens.access_token,
        refresh_token: newTokens.refresh_token ?? connection.refresh_token,
        token_expires_at: newTokens.expires_at,
      })
      .eq('id', connection.id);

    // Update in-memory connection object
    connection.access_token = newTokens.access_token;
    if (newTokens.refresh_token) connection.refresh_token = newTokens.refresh_token;
    connection.token_expires_at = newTokens.expires_at;
  } finally {
    // Release lock (only if we still hold it)
    const current = await redis.get(lockKey);
    if (current === lockValue) await redis.del(lockKey);
  }
}

async function waitForLockRelease(key: string, timeoutMs: number): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const exists = await redis.exists(key);
    if (!exists) return;
    await new Promise(r => setTimeout(r, 200)); // poll every 200ms
  }
}
```

This pattern is used by the Jira (9F.5), Asana (9F.7), and any future OAuth-based dispatchers. Slack and Linear use long-lived bot tokens / API keys that don't need refresh, so they skip this.

### 9D: Trigger Code Validation (on save)

Reuses the Phase 4 isolated-vm sandbox validation pattern. When a user saves a notification rule, the trigger code is validated before persisting. Save is **blocked** if validation fails.

**Endpoint:** `POST /api/organizations/:id/validate-notification-rule` with `{ code }`

Also used by team and project rule endpoints: validation runs inline during the save (`POST` / `PUT`) request. If validation fails, the rule is not saved and the error is returned.

**9D.1: Validation checks (3 sequential checks)**

**Check 1 -- Syntax Compilation:**

- Wrap the code in `function trigger(context) { <user_code> }` and compile in isolated-vm
- If syntax error, return the error with line number (adjusted for the wrapper offset)
- Result: `{ pass: true }` or `{ pass: false, error: "SyntaxError at line 5: Unexpected token '}'" }`

**Check 2 -- Shape Validation (test run with sample data):**

- Generate a realistic sample context: a vulnerability_discovered event with a mock dependency, vulnerability, and project
- Execute the wrapped function against the sample context
- Validate the return value:
  - Must be `boolean` OR an object `{ notify: boolean, message?: string, title?: string, priority?: string }`
  - Common failures: returning `undefined` (forgot return statement), returning a string, returning a number
  - Error message: "Trigger function must return true/false or { notify: boolean }. Got: undefined. Did you forget a return statement?"

**Check 3 -- Fetch Resilience (only if code contains `fetch(`):**

- **Pass 1**: Run with fetch mocked to succeed (`{ ok: true, json: () => ({}) }`)
- **Pass 2**: Run with fetch mocked to throw `new Error('Network request failed')`
- If Pass 2 throws an unhandled error: **save is blocked**
- Error message: "Your code calls fetch() but crashes when the API is unreachable. Wrap fetch calls in try/catch. Line N: unhandled error."

**9D.2: Validation output format (displayed in editor)**

```
[pass] Syntax: Valid JavaScript
[pass] Shape: Returns boolean (true)
[pass] Test run: Returned true for sample vulnerability_discovered event
[fail] Fetch resilience: Code crashes when fetch() fails (line 3: TypeError: Cannot read property 'json' of undefined).
       Wrap fetch calls in try/catch. Save blocked.
```

**9D.3: Sample test contexts**

```typescript
const SAMPLE_CONTEXTS: Record<string, object> = {
  vulnerability_discovered: {
    event: { type: 'vulnerability_discovered' },
    project: {
      name: 'api-service', asset_tier: 'CROWN_JEWELS', health_score: 72,
      status: 'Compliant', status_is_passing: true, dependencies_count: 145,
    },
    dependency: {
      name: 'lodash', version: '4.17.20', license: 'MIT', is_direct: true,
      environment: 'production', score: 82, openssf_score: 7.2,
      weekly_downloads: 45000000, malicious_indicator: null, slsa_level: 0,
      is_dev_dependency: false, dependency_score: 82,
    },
    vulnerability: {
      osv_id: 'GHSA-test-0000-0000', severity: 'critical', cvss_score: 9.8,
      epss_score: 0.45, depscore: 88, is_reachable: true, cisa_kev: false,
      fixed_versions: ['4.17.21'], summary: 'Prototype Pollution in lodash',
    },
    previous: null,
  },
  dependency_added: {
    event: { type: 'dependency_added' },
    project: {
      name: 'web-app', asset_tier: 'EXTERNAL', health_score: 85,
      status: 'Compliant', status_is_passing: true, dependencies_count: 200,
    },
    dependency: {
      name: 'new-pkg', version: '1.0.0', license: 'MIT', is_direct: true,
      environment: 'production', score: 45, openssf_score: 3.1,
      weekly_downloads: 1200, malicious_indicator: null, slsa_level: 0,
      is_dev_dependency: false, dependency_score: 45,
    },
    vulnerability: null,
    previous: null,
  },
  status_changed: {
    event: { type: 'status_changed' },
    project: {
      name: 'api-service', asset_tier: 'CROWN_JEWELS', health_score: 45,
      status: 'Blocked', status_is_passing: false, dependencies_count: 145,
    },
    dependency: null,
    vulnerability: null,
    previous: { status: 'Compliant', status_is_passing: true, health_score: 72 },
  },
  // ... additional sample contexts for each event type
};
```

When validating, run the code against 3 different sample contexts (vulnerability_discovered, dependency_added, and the event type most likely to be targeted based on code analysis) to verify it handles different event shapes without crashing.

**9D.4: Integration into save endpoints**

Modify the existing notification rule CRUD endpoints in [ee/backend/routes/organizations.ts](ee/backend/routes/organizations.ts) and [ee/backend/routes/projects.ts](ee/backend/routes/projects.ts):

```typescript
// In POST /api/organizations/:id/notification-rules
// and PUT /api/organizations/:id/notification-rules/:ruleId

if (customCode && customCode.trim()) {
  const validation = await validateNotificationTriggerCode(customCode);
  if (!validation.passed) {
    return res.status(422).json({
      error: 'Validation failed',
      checks: validation.checks, // array of { name, pass, error? }
    });
  }
}
```

Same pattern for team and project rule endpoints.

**9D.5: Frontend validation display**

In `NotificationRulesSection.tsx`, when save returns a 422 with validation errors, display the check results inline below the code editor (same pattern as Phase 4 policy validation):

- Green checkmark + "Syntax: Valid JavaScript"
- Green checkmark + "Shape: Returns boolean"
- Red X + "Fetch resilience: Code crashes when fetch() fails..." with the specific error

The "Save" button shows a loading state during validation, and the validation results appear in-place without closing the sidebar.

### 9E: Enhanced Trigger Context Object

The context object passed to notification rule trigger code. This is what `context` looks like inside the user's function.

**9E.1: Context shape**

```typescript
interface NotificationContext {
  event: {
    type: string;           // one of the 20 event types from 9A
    timestamp: string;      // ISO 8601
    source: string;         // 'extraction' | 'vuln_monitor' | 'pr_handler' | etc.
  };
  project: {
    id: string;
    name: string;
    asset_tier: string;              // tier name (e.g. 'Crown Jewels')
    asset_tier_rank: number;         // tier rank (lower = more critical)
    health_score: number;            // 0-100
    status: string;                  // custom status name
    status_is_passing: boolean;
    dependencies_count: number;
    team_name: string | null;        // owner team name
  };
  dependency: {                      // null for non-dependency events
    name: string;
    version: string;
    license: string | null;
    is_direct: boolean;
    is_dev_dependency: boolean;
    environment: string;             // 'production' | 'development'
    score: number;                   // Deptex reputation score (0-100)
    dependency_score: number;        // same as score (alias for clarity)
    openssf_score: number | null;
    weekly_downloads: number | null;
    malicious_indicator: {           // null if not malicious
      source: string;
      confidence: string;
      reason: string;
    } | null;
    slsa_level: number;              // 0-4
    registry_integrity_status: string | null;  // 'pass' | 'warning' | 'fail'
    install_scripts_status: string | null;
    entropy_analysis_status: string | null;
    vulnerabilities: Array<{
      osv_id: string;
      severity: string;
      cvss_score: number;
      depscore: number;
      is_reachable: boolean;
      cisa_kev: boolean;
    }>;
  } | null;
  vulnerability: {                   // null for non-vulnerability events
    osv_id: string;
    severity: string;                // 'critical' | 'high' | 'medium' | 'low'
    cvss_score: number;
    epss_score: number;
    depscore: number;                // composite risk score (0-100)
    is_reachable: boolean;
    cisa_kev: boolean;
    fixed_versions: string[];
    summary: string;
  } | null;
  pr: {                              // null for non-PR events
    number: number;
    title: string;
    author: string;
    base_branch: string;
    head_branch: string;
    check_result: string;            // 'passed' | 'failed'
    check_summary: string;
    deps_added: number;
    deps_updated: number;
    deps_removed: number;
    provider_url: string;
  } | null;
  previous: {                        // null for non-change events
    status: string | undefined;
    status_is_passing: boolean | undefined;
    health_score: number | undefined;
  } | null;
  // Batch context (only present for batched events)
  batch: {
    total: number;
    by_type: Record<string, number>;
    events: Array<{ type: string; dependency?: { name: string; version: string }; vulnerability?: { osv_id: string; severity: string } }>;
  } | null;
}
```

**9E.2: Return value**

The trigger function can return:

1. `**true`** -- send notification with default message template for this event type
2. `**false`** -- skip notification
3. `**{ notify: true }`** -- same as `true`
4. `**{ notify: true, message: string }**` -- send with custom message body (replaces default template)
5. `**{ notify: true, title: string }**` -- send with custom title (replaces default)
6. `**{ notify: true, message: string, title: string, priority: 'critical' | 'high' | 'normal' | 'low' }**` -- full custom override

The dispatcher normalizes the return value:

```typescript
function normalizeReturn(result: any): { notify: boolean; message?: string; title?: string; priority?: string } {
  if (typeof result === 'boolean') return { notify: result };
  if (result && typeof result === 'object' && 'notify' in result) return result;
  // Truthy non-boolean, non-object: treat as true
  if (result) return { notify: true };
  return { notify: false };
}
```

### 9F: Destination Dispatcher Modules

Each integration type has a dedicated dispatcher that formats the event into the native message format and delivers it.

**File:** `ee/backend/lib/destination-dispatchers.ts` (or split into per-destination files in `ee/backend/lib/dispatchers/`)

**9F.1: Dispatcher interface**

```typescript
export interface DispatchResult {
  success: boolean;
  statusCode?: number;
  externalId?: string;    // message ID, ticket ID, etc. from the destination
  error?: string;
  retryable: boolean;     // true if the failure is transient (rate limit, timeout)
}

export interface NotificationMessage {
  title: string;
  body: string;            // plain text or markdown
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  eventType: string;
  projectName: string;
  deptexUrl: string;       // deep link back to Deptex
  metadata: Record<string, any>;  // event-specific data for rich formatting
}
```

**9F.2: Default message templates**

```typescript
function buildDefaultMessage(event: NotificationEvent, context: NotificationContext): NotificationMessage {
  const templates: Record<string, (ctx: NotificationContext) => NotificationMessage> = {

    vulnerability_discovered: (ctx) => ({
      title: `New ${ctx.vulnerability!.severity} vulnerability in ${ctx.dependency!.name}`,
      body: `${ctx.vulnerability!.osv_id} (CVSS ${ctx.vulnerability!.cvss_score}) affects ${ctx.dependency!.name}@${ctx.dependency!.version} in ${ctx.project.name}. Depscore: ${ctx.vulnerability!.depscore}/100.${ctx.vulnerability!.cisa_kev ? ' CISA KEV: actively exploited.' : ''}${ctx.vulnerability!.is_reachable ? ' Reachable from project code.' : ''}`,
      severity: ctx.vulnerability!.severity as any,
      eventType: 'vulnerability_discovered',
      projectName: ctx.project.name,
      deptexUrl: `${APP_URL}/projects/${ctx.project.id}/security`,
      metadata: { vulnerability: ctx.vulnerability, dependency: ctx.dependency },
    }),

    malicious_package_detected: (ctx) => ({
      title: `MALICIOUS PACKAGE: ${ctx.dependency!.name}@${ctx.dependency!.version}`,
      body: `${ctx.dependency!.name}@${ctx.dependency!.version} in ${ctx.project.name} has been flagged as malicious. Source: ${ctx.dependency!.malicious_indicator!.source}. Reason: ${ctx.dependency!.malicious_indicator!.reason}. Immediate action required.`,
      severity: 'critical',
      eventType: 'malicious_package_detected',
      projectName: ctx.project.name,
      deptexUrl: `${APP_URL}/projects/${ctx.project.id}/dependencies`,
      metadata: { dependency: ctx.dependency },
    }),

    status_changed: (ctx) => ({
      title: `${ctx.project.name} status: ${ctx.previous?.status} -> ${ctx.project.status}`,
      body: `Project ${ctx.project.name} changed from "${ctx.previous?.status}" to "${ctx.project.status}".${!ctx.project.status_is_passing ? ' Project is now in a non-passing state.' : ''}`,
      severity: ctx.project.status_is_passing ? 'info' : 'high',
      eventType: 'status_changed',
      projectName: ctx.project.name,
      deptexUrl: `${APP_URL}/projects/${ctx.project.id}/compliance`,
      metadata: { previous: ctx.previous, current: { status: ctx.project.status } },
    }),

    pr_check_completed: (ctx) => ({
      title: `PR #${ctx.pr!.number} ${ctx.pr!.check_result === 'passed' ? 'passed' : 'FAILED'} checks in ${ctx.project.name}`,
      body: `${ctx.pr!.title} by ${ctx.pr!.author}. ${ctx.pr!.check_summary}. ${ctx.pr!.deps_added} added, ${ctx.pr!.deps_updated} updated, ${ctx.pr!.deps_removed} removed.`,
      severity: ctx.pr!.check_result === 'passed' ? 'info' : 'high',
      eventType: 'pr_check_completed',
      projectName: ctx.project.name,
      deptexUrl: ctx.pr!.provider_url,
      metadata: { pr: ctx.pr },
    }),

    ai_fix_completed: (ctx) => ({
      title: `AI fix ready: ${ctx.vulnerability!.osv_id} in ${ctx.dependency!.name}`,
      body: `Deptex generated an automated fix for ${ctx.vulnerability!.osv_id} (${ctx.vulnerability!.severity}) in ${ctx.dependency!.name}@${ctx.dependency!.version}. A draft PR has been created for review.`,
      severity: 'info',
      eventType: 'ai_fix_completed',
      projectName: ctx.project.name,
      deptexUrl: `${APP_URL}/projects/${ctx.project.id}/security`,
      metadata: { vulnerability: ctx.vulnerability, dependency: ctx.dependency },
    }),

    extraction_completed: (ctx) => ({
      title: `Extraction completed: ${ctx.project.name}`,
      body: `Dependency extraction finished for ${ctx.project.name}. ${ctx.project.dependencies_count} dependencies tracked.`,
      severity: 'info',
      eventType: 'extraction_completed',
      projectName: ctx.project.name,
      deptexUrl: `${APP_URL}/projects/${ctx.project.id}`,
      metadata: {},
    }),

    // ... templates for all 20 event types
  };

  const template = templates[event.event_type];
  if (!template) {
    return {
      title: `${event.event_type} in ${context.project.name}`,
      body: JSON.stringify(event.payload, null, 2),
      severity: 'info',
      eventType: event.event_type,
      projectName: context.project.name,
      deptexUrl: `${APP_URL}/projects/${context.project.id}`,
      metadata: event.payload,
    };
  }
  return template(context);
}
```

**9F.3: Slack dispatcher**

Uses the Slack Bot API (`chat.postMessage`) with Block Kit for rich formatting.

```typescript
async function dispatchSlack(
  connection: IntegrationConnection,
  message: NotificationMessage,
): Promise<DispatchResult> {
  const channelId = connection.metadata?.channel_id
    || connection.metadata?.incoming_webhook?.channel_id;
  if (!channelId) return { success: false, error: 'No channel configured', retryable: false };

  const severityColor = {
    critical: '#dc2626', high: '#ea580c', medium: '#ca8a04', low: '#2563eb', info: '#71717a',
  }[message.severity] || '#71717a';

  const blocks = [
    {
      type: 'section',
      text: { type: 'mrkdwn', text: `*${message.title}*` },
    },
    {
      type: 'section',
      text: { type: 'mrkdwn', text: message.body },
    },
    {
      type: 'context',
      elements: [
        { type: 'mrkdwn', text: `*Project:* ${message.projectName}` },
        { type: 'mrkdwn', text: `*Severity:* ${message.severity.toUpperCase()}` },
        { type: 'mrkdwn', text: `*Event:* ${message.eventType}` },
      ],
    },
    {
      type: 'actions',
      elements: [
        {
          type: 'button',
          text: { type: 'plain_text', text: 'View in Deptex' },
          url: message.deptexUrl,
          style: message.severity === 'critical' ? 'danger' : undefined,
        },
      ],
    },
  ];

  const response = await fetch('https://slack.com/api/chat.postMessage', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${connection.access_token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      channel: channelId,
      text: message.title, // fallback for notifications
      attachments: [{ color: severityColor, blocks }],
    }),
  });

  const data = await response.json();
  if (!data.ok) {
    const retryable = ['rate_limited', 'service_unavailable'].includes(data.error);
    return { success: false, error: data.error, retryable };
  }
  return { success: true, externalId: data.ts };
}
```

**9F.4: Discord dispatcher**

Uses Discord Bot API to post embed messages.

```typescript
async function dispatchDiscord(
  connection: IntegrationConnection,
  message: NotificationMessage,
): Promise<DispatchResult> {
  const guildId = connection.metadata?.guild_id;
  // Discord requires a channel -- resolve from guild's first text channel or a configured channel
  const channelId = connection.metadata?.channel_id || await getDiscordDefaultChannel(connection);
  if (!channelId) return { success: false, error: 'No channel configured', retryable: false };

  const severityColor = {
    critical: 0xdc2626, high: 0xea580c, medium: 0xca8a04, low: 0x2563eb, info: 0x71717a,
  }[message.severity] || 0x71717a;

  const response = await fetch(`https://discord.com/api/v10/channels/${channelId}/messages`, {
    method: 'POST',
    headers: {
      'Authorization': `Bot ${connection.access_token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      embeds: [{
        title: message.title,
        description: message.body,
        color: severityColor,
        fields: [
          { name: 'Project', value: message.projectName, inline: true },
          { name: 'Severity', value: message.severity.toUpperCase(), inline: true },
        ],
        url: message.deptexUrl,
        footer: { text: 'Deptex Security' },
        timestamp: new Date().toISOString(),
      }],
    }),
  });

  if (!response.ok) {
    const retryable = response.status === 429 || response.status >= 500;
    return { success: false, error: `Discord API ${response.status}`, retryable, statusCode: response.status };
  }
  const data = await response.json();
  return { success: true, externalId: data.id };
}
```

**9F.5: Jira dispatcher**

Creates a Jira issue (ticket) for actionable events. Uses Jira REST API v3.

```typescript
async function dispatchJira(
  connection: IntegrationConnection,
  message: NotificationMessage,
): Promise<DispatchResult> {
  const projectKey = connection.metadata?.project_key;
  if (!projectKey) {
    return {
      success: false,
      error: 'No Jira project configured. Set a project_key in the integration settings.',
      retryable: false,
    };
  }

  const isDataCenter = connection.metadata?.type === 'data_center';
  const baseUrl = isDataCenter
    ? connection.metadata?.base_url
    : `https://api.atlassian.com/ex/jira/${connection.metadata?.cloud_id}`;

  // Refresh token if needed (Cloud only), with mutex (see 9C.5)
  if (!isDataCenter) {
    await refreshTokenWithMutex(connection);
  }

  const priorityMap: Record<string, string> = {
    critical: 'Highest', high: 'High', medium: 'Medium', low: 'Low', info: 'Lowest',
  };

  const response = await fetch(`${baseUrl}/rest/api/3/issue`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${connection.access_token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      fields: {
        project: { key: projectKey },
        summary: message.title.slice(0, 255),
        description: {
          type: 'doc', version: 1,
          content: [
            { type: 'paragraph', content: [{ type: 'text', text: message.body }] },
            { type: 'paragraph', content: [
              { type: 'text', text: 'View in Deptex: ' },
              { type: 'text', text: message.deptexUrl, marks: [{ type: 'link', attrs: { href: message.deptexUrl } }] },
            ]},
          ],
        },
        issuetype: { name: 'Task' },
        priority: { name: priorityMap[message.severity] || 'Medium' },
        labels: ['deptex', `deptex-${message.eventType}`, `severity-${message.severity}`],
      },
    }),
  });

  if (!response.ok) {
    const retryable = response.status === 429 || response.status >= 500;
    return { success: false, error: `Jira API ${response.status}`, retryable, statusCode: response.status };
  }
  const data = await response.json();
  return { success: true, externalId: data.key };
}
```

**9F.6: Linear dispatcher**

Creates a Linear issue via GraphQL.

```typescript
async function dispatchLinear(
  connection: IntegrationConnection,
  message: NotificationMessage,
): Promise<DispatchResult> {
  const linearTeamId = connection.metadata?.team_id;
  if (!linearTeamId) {
    return {
      success: false,
      error: 'No Linear team configured. Set a team_id in the integration settings.',
      retryable: false,
    };
  }

  const priorityMap: Record<string, number> = {
    critical: 1, high: 2, medium: 3, low: 4, info: 0,
  };

  const mutation = `
    mutation CreateIssue($input: IssueCreateInput!) {
      issueCreate(input: $input) {
        success
        issue { id identifier url }
      }
    }
  `;

  const response = await fetch('https://api.linear.app/graphql', {
    method: 'POST',
    headers: {
      'Authorization': connection.access_token,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      query: mutation,
      variables: {
        input: {
          teamId: linearTeamId,
          title: message.title.slice(0, 255),
          description: `${message.body}\n\n[View in Deptex](${message.deptexUrl})`,
          priority: priorityMap[message.severity] ?? 3,
          labelIds: [],
        },
      },
    }),
  });

  const data = await response.json();
  if (!data.data?.issueCreate?.success) {
    return { success: false, error: JSON.stringify(data.errors), retryable: false };
  }
  return { success: true, externalId: data.data.issueCreate.issue.identifier };
}
```

**9F.7: Asana dispatcher**

Creates an Asana task via REST API.

```typescript
async function dispatchAsana(
  connection: IntegrationConnection,
  message: NotificationMessage,
): Promise<DispatchResult> {
  await refreshTokenWithMutex(connection); // mutex-protected refresh (see 9C.5)

  const taskData: Record<string, any> = {
    name: message.title.slice(0, 255),
    notes: `${message.body}\n\nView in Deptex: ${message.deptexUrl}`,
    workspace: connection.metadata?.workspace_gid,
  };

  // Assign to a specific Asana project if configured (prevents orphaned tasks)
  if (connection.metadata?.project_gid) {
    taskData.projects = [connection.metadata.project_gid];
  }

  const response = await fetch('https://app.asana.com/api/1.0/tasks', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${connection.access_token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ data: taskData }),
  });

  if (!response.ok) {
    const retryable = response.status === 429 || response.status >= 500;
    return { success: false, error: `Asana API ${response.status}`, retryable, statusCode: response.status };
  }
  const data = await response.json();
  return { success: true, externalId: data.data?.gid };
}
```

**9F.8: Email dispatcher**

Uses the existing `ee/backend/lib/email.ts` nodemailer transport with an HTML template.

```typescript
async function dispatchEmail(
  connection: IntegrationConnection,
  message: NotificationMessage,
): Promise<DispatchResult> {
  const emailAddress = connection.metadata?.email || connection.display_name;
  if (!emailAddress) return { success: false, error: 'No email address', retryable: false };

  const severityBadge = {
    critical: { bg: '#dc2626', text: 'CRITICAL' },
    high: { bg: '#ea580c', text: 'HIGH' },
    medium: { bg: '#ca8a04', text: 'MEDIUM' },
    low: { bg: '#2563eb', text: 'LOW' },
    info: { bg: '#71717a', text: 'INFO' },
  }[message.severity];

  const html = `
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 600px; margin: 0 auto;">
      <div style="padding: 20px; background: #09090b; border-radius: 8px; border: 1px solid #27272a;">
        <div style="margin-bottom: 16px;">
          <span style="display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; color: white; background: ${severityBadge.bg};">${severityBadge.text}</span>
          <span style="color: #71717a; font-size: 12px; margin-left: 8px;">${message.eventType}</span>
        </div>
        <h2 style="color: #fafafa; font-size: 16px; margin: 0 0 12px 0;">${message.title}</h2>
        <p style="color: #a1a1aa; font-size: 14px; line-height: 1.6; margin: 0 0 20px 0;">${message.body}</p>
        <a href="${message.deptexUrl}" style="display: inline-block; padding: 8px 16px; background: #fafafa; color: #09090b; border-radius: 6px; text-decoration: none; font-size: 13px; font-weight: 500;">View in Deptex</a>
      </div>
      <p style="color: #52525b; font-size: 11px; text-align: center; margin-top: 16px;">Deptex Security Notifications</p>
    </div>
  `;

  // Sanitize subject to prevent email header injection (RFC 2822).
  // Strip CR/LF and cap at 998 chars (max header line length).
  const sanitizedTitle = message.title
    .replace(/[\r\n\x00]/g, '')
    .slice(0, 978); // 978 + '[Deptex] ' prefix = under 998

  try {
    await sendEmail({
      to: emailAddress,
      subject: `[Deptex] ${sanitizedTitle}`,
      html,
    });
    return { success: true };
  } catch (error: any) {
    return { success: false, error: error.message, retryable: true };
  }
}
```

**9F.9: Custom webhook dispatcher**

Reuses the existing HMAC-SHA256 signing pattern from the test ping endpoint.

```typescript
async function dispatchCustomWebhook(
  connection: IntegrationConnection,
  message: NotificationMessage,
  event: NotificationEvent,
): Promise<DispatchResult> {
  const webhookUrl = connection.metadata?.webhook_url;
  const secret = connection.access_token; // whsec_* HMAC secret
  if (!webhookUrl) return { success: false, error: 'No webhook URL', retryable: false };

  const deliveryId = crypto.randomUUID();
  const payload = JSON.stringify({
    id: deliveryId,
    event: event.event_type,
    timestamp: new Date().toISOString(),
    organization_id: event.organization_id,
    project: {
      id: event.project_id,
      name: message.projectName,
    },
    data: event.payload,
    message: {
      title: message.title,
      body: message.body,
      severity: message.severity,
      deptex_url: message.deptexUrl,
    },
  });

  const signature = 'sha256=' + crypto.createHmac('sha256', secret).update(payload).digest('hex');

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);

  try {
    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Deptex-Signature': signature,
        'X-Deptex-Event': event.event_type,
        'X-Deptex-Delivery': deliveryId,
        'User-Agent': 'Deptex-Webhooks/1.0',
      },
      body: payload,
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (!response.ok) {
      const retryable = response.status === 429 || response.status >= 500;
      return { success: false, error: `HTTP ${response.status}`, retryable, statusCode: response.status };
    }
    return { success: true, externalId: deliveryId, statusCode: response.status };
  } catch (error: any) {
    clearTimeout(timeout);
    if (error.name === 'AbortError') {
      return { success: false, error: 'Request timed out (10s)', retryable: true };
    }
    return { success: false, error: error.message, retryable: true };
  }
}
```

**9F.10: PagerDuty dispatcher**

Creates a PagerDuty incident via the Events API v2. PagerDuty integration uses a routing key stored in `organization_integrations.access_token`.

```typescript
async function dispatchPagerDuty(
  connection: IntegrationConnection,
  message: NotificationMessage,
): Promise<DispatchResult> {
  const routingKey = connection.access_token;
  if (!routingKey) return { success: false, error: 'No routing key', retryable: false };

  const pagerDutySeverity: Record<string, string> = {
    critical: 'critical', high: 'error', medium: 'warning', low: 'info', info: 'info',
  };

  const response = await fetch('https://events.pagerduty.com/v2/enqueue', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      routing_key: routingKey,
      event_action: 'trigger',
      dedup_key: `deptex-${message.eventType}-${message.projectName}-${Date.now()}`,
      payload: {
        summary: message.title.slice(0, 1024),
        source: 'Deptex',
        severity: pagerDutySeverity[message.severity] || 'info',
        component: message.projectName,
        group: message.eventType,
        custom_details: {
          body: message.body,
          deptex_url: message.deptexUrl,
          ...message.metadata,
        },
      },
      links: [{ href: message.deptexUrl, text: 'View in Deptex' }],
    }),
  });

  if (!response.ok) {
    return { success: false, error: `PagerDuty API ${response.status}`, retryable: response.status >= 500 };
  }
  const data = await response.json();
  return { success: true, externalId: data.dedup_key };
}
```

**9F.11: Dispatcher router**

```typescript
export async function dispatchToDestination(
  connection: IntegrationConnection,
  message: NotificationMessage,
  event: NotificationEvent,
): Promise<DispatchResult> {
  const dispatchers: Record<string, Function> = {
    slack: dispatchSlack,
    discord: dispatchDiscord,
    jira: dispatchJira,
    linear: dispatchLinear,
    asana: dispatchAsana,
    email: dispatchEmail,
    custom_notification: dispatchCustomWebhook,
    custom_ticketing: dispatchCustomWebhook,
    pagerduty: dispatchPagerDuty,
  };

  const dispatcher = dispatchers[connection.provider];
  if (!dispatcher) {
    return { success: false, error: `Unknown provider: ${connection.provider}`, retryable: false };
  }

  return dispatcher(connection, message, event);
}
```

### 9G: Custom Webhook Delivery Reliability

Webhook delivery with retries, timeout, and delivery tracking for custom webhook integrations.

**9G.1: Retry logic**

When a custom webhook delivery fails with a retryable error (5xx, 429, timeout), retry with exponential backoff:

- Attempt 1: immediate
- Attempt 2: 30 seconds delay
- Attempt 3: 2 minutes delay
- Attempt 4: 10 minutes delay
- Attempt 5: 1 hour delay (final attempt)

Retries are handled by QStash's built-in retry mechanism (`Upstash-Retries: 5`). Each delivery attempt is a separate QStash job.

If all 5 attempts fail, the `notification_deliveries` row is marked as `'failed'` with the last error message.

**9G.2: Rate limit handling**

If the webhook endpoint returns 429 with a `Retry-After` header, respect it. QStash handles this automatically via the retry delay.

**9G.3: Webhook IP allowlisting**

Document the IP ranges that Deptex webhooks originate from (QStash IP ranges from Upstash) so enterprise customers can allowlist them in their firewalls. Add to the Integrations docs page.

### 9H: Batching and Smart Grouping

Prevents notification spam when high-volume events occur (e.g., extraction finds 50 new deps, or background monitoring discovers 10 new vulns at once).

**9H.1: Batching strategy**

Events are grouped by `(organization_id, project_id, source)`. When `emitEventBatch()` is used (see 9B), the batch is dispatched as a single summary notification per destination.

For individual `emitEvent()` calls that arrive within a time window, the QStash delay parameter provides natural batching:

- **Critical priority** (0s delay): dispatched immediately, never batched
- **High priority** (0s delay): dispatched immediately, but use batch format if multiple arrive at once
- **Normal priority** (30s delay): events arriving within 30s are batched by the `dispatch-notification-batch` handler
- **Low priority** (5min delay): events arriving within 5 minutes are batched

**9H.2: Summary notification format**

When a batch of events is dispatched, the notification uses a summary format:

```
Title: "12 dependency changes in API Service"
Body:
  5 packages added: express@4.19.0, lodash@4.18.0, ...
  4 packages updated: axios 0.21.0 -> 1.6.0, ...
  3 packages removed: moment, left-pad, ...
  2 new vulnerabilities found (1 critical, 1 high)
```

The trigger function receives a `context.batch` object for batch events, allowing users to filter on aggregate counts:

```javascript
// Only alert if batch has 5+ dependency changes or any critical vuln
if (context.batch) {
  const depChanges = (context.batch.by_type.dependency_added || 0)
    + (context.batch.by_type.dependency_updated || 0)
    + (context.batch.by_type.dependency_removed || 0);
  return depChanges >= 5 || (context.batch.by_type.vulnerability_discovered || 0) > 0;
}
return false;
```

**9H.3: Critical event bypass**

These events are NEVER batched and are always dispatched immediately regardless of other pending events:

- `malicious_package_detected` -- always immediate
- `vulnerability_discovered` where `cisa_kev === true` -- actively exploited, immediate
- `security_analysis_failure` -- potential supply chain attack, immediate

The `emitEvent()` function checks for critical events and sets `priority: 'critical'` which bypasses the QStash delay.

### 9I: Rate Limiting

Prevents notification storms from overwhelming destinations or exceeding provider API limits.

**9I.1: Rate limit tiers**


| Scope                                               | Limit                  | Window         | Burst                        |
| --------------------------------------------------- | ---------------------- | -------------- | ---------------------------- |
| Per organization                                    | 200 notifications/hour | Rolling 1 hour | Allow 20 in a 1-minute burst |
| Per destination (integration connection)            | 30 notifications/hour  | Rolling 1 hour | Allow 5 in a 1-minute burst  |
| Per destination for ticketing (Jira, Linear, Asana) | 10 tickets/hour        | Rolling 1 hour | Allow 2 in a 1-minute burst  |


**9I.2: Implementation**

Use Redis sorted sets for sliding window rate limiting:

```typescript
async function checkRateLimit(
  scope: string,  // e.g. 'org:uuid' or 'dest:uuid'
  limit: number,
  windowMs: number,
): Promise<{ allowed: boolean; remaining: number; resetAt: number }> {
  const key = `ratelimit:notif:${scope}`;
  const now = Date.now();
  const windowStart = now - windowMs;

  // Remove entries outside the window
  await redis.zremrangebyscore(key, 0, windowStart);
  // Count entries in the window
  const count = await redis.zcard(key);

  if (count >= limit) {
    const oldestEntry = await redis.zrange(key, 0, 0, { withScores: true });
    const resetAt = oldestEntry.length > 0 ? Number(oldestEntry[0].score) + windowMs : now + windowMs;
    return { allowed: false, remaining: 0, resetAt };
  }

  // Add this request
  await redis.zadd(key, { score: now, member: `${now}:${crypto.randomUUID().slice(0, 8)}` });
  await redis.expire(key, Math.ceil(windowMs / 1000) + 60);

  return { allowed: true, remaining: limit - count - 1, resetAt: now + windowMs };
}
```

**9I.3: Rate limit exceeded behavior**

When a rate limit is hit:

1. The notification delivery row is marked `'rate_limited'` (not `'failed'` -- it's a soft skip)
2. A meta-notification is sent to the org owner/admins (once per hour per limit type): "Notification rate limit exceeded. Some notifications for [Slack #security] were suppressed. Consider adjusting your notification rules or upgrading your plan."
3. The rate-limited notification is NOT retried (it's not a transient failure)
4. The event remains in `notification_events` for the delivery history (visible with status `'rate_limited'`)

**9I.4: Phase 13 plan-tier limits**

Phase 13 (Billing) will add plan-tier restrictions on notification volume:

- **Free**: 50 notifications/month
- **Pro**: 1,000 notifications/month
- **Team**: 10,000 notifications/month
- **Enterprise**: Unlimited

Phase 9 builds the rate limiting infrastructure. Phase 13 adds the plan-tier enforcement layer on top.

### 9J: Delivery Tracking and Notification History

Track every notification delivery attempt for observability, debugging, and audit.

**9J.1: notification_deliveries table**

```sql
CREATE TABLE notification_deliveries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id UUID NOT NULL REFERENCES notification_events(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  rule_id UUID NOT NULL,
  rule_scope TEXT NOT NULL CHECK (rule_scope IN ('organization', 'team', 'project')),
  rule_name TEXT,
  destination_type TEXT NOT NULL,
  destination_id UUID NOT NULL,
  destination_name TEXT,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'sending', 'delivered', 'failed', 'rate_limited', 'skipped')),
  message_title TEXT,
  message_body TEXT,
  message_payload JSONB,
  response JSONB,
  external_id TEXT,
  error_message TEXT,
  attempts INTEGER DEFAULT 0,
  last_attempt_at TIMESTAMPTZ,
  delivered_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_notif_deliveries_event ON notification_deliveries(event_id);
CREATE INDEX idx_notif_deliveries_org ON notification_deliveries(organization_id, created_at DESC);
CREATE INDEX idx_notif_deliveries_status ON notification_deliveries(status) WHERE status IN ('pending', 'failed');
```

**9J.2: Notification History UI**

New "History" sub-tab within the Notifications tab of Organization Settings (alongside the existing rules list).

**Components:**

- Table with columns: Timestamp, Event Type (badge), Project, Rule Name, Destination (icon + name), Status (badge: delivered/failed/rate_limited/skipped), Actions (expand/retry)
- Expandable row detail: full message title + body, delivery attempts timeline, response data, error messages
- Filters: event type dropdown, destination dropdown, status (All/Delivered/Failed/Rate Limited), timeframe (24H/7D/30D)
- "Retry Failed" button on failed deliveries: re-queues the delivery via QStash
- Auto-refresh toggle (poll every 30s when active)

**API endpoints:**

1. `GET /api/organizations/:id/notification-history` -- paginated delivery list
  - Query params: `event_type`, `destination_type`, `status`, `timeframe`, `page`, `per_page`
  - Returns: deliveries joined with events for full context
2. `POST /api/organizations/:id/notification-history/:deliveryId/retry` -- retry a failed delivery
  - Requeues via QStash with the original event + destination

**9J.3: Retention**

- Keep `notification_events` for 90 days (configurable per plan tier in Phase 13)
- Keep `notification_deliveries` for 90 days
- A daily cleanup job (piggyback on watchtower-poller) deletes rows older than the retention period
- Enterprise plans can extend to 1 year

### 9K: Weekly Digest System

The `weekly_digest` trigger type sends a scheduled summary of the past week's events.

**9K.1: Schedule**

Digest runs every Monday at 9:00 AM UTC via QStash CRON:

```typescript
// Register on app startup
await qstash.schedules.create({
  destination: `${API_BASE_URL}/api/workers/weekly-digest`,
  cron: '0 9 * * 1', // Monday 9 AM UTC
});
```

**Timezone handling:** The CRON runs at a fixed UTC time. The digest email and Slack message should display all timestamps formatted in the org's configured timezone. If the `organizations` table has a `timezone` column (e.g., `'America/New_York'`), use it for formatting. If the column does not exist yet, default to UTC and add per-org timezone configuration as a future enhancement (Phase 10 UI or Phase 13). The CRON itself stays at UTC -- running per-org-timezone CRONs would require one QStash schedule per org, which is impractical.

**9K.2: Digest endpoint**

```typescript
router.post('/weekly-digest', verifyQStash, async (req, res) => {
  // 1. Load all orgs with at least one active weekly_digest rule
  const { data: rules } = await supabase
    .from('organization_notification_rules')
    .select('organization_id, destinations')
    .eq('trigger_type', 'weekly_digest')
    .eq('active', true);

  // Also check team and project rules
  // ...

  // 2. For each org: assemble digest content
  for (const orgId of uniqueOrgIds) {
    await assembleAndSendDigest(orgId);
  }

  res.json({ success: true });
});
```

**9K.3: Digest content assembly**

```
assembleAndSendDigest(orgId):
  1. Query notification_events for this org, last 7 days
  2. Group by project, then by event_type
  3. Build summary:
     - Total events this week
     - Per-project breakdown:
       - New vulnerabilities (count by severity)
       - Dependencies added/updated/removed
       - PR checks (passed/failed counts)
       - Status changes
       - AI fixes generated
     - Highlight: top 3 most critical events
     - Trend: "up 15% from last week" or "down 30%"
  4. Format as both Slack Block Kit and HTML email
  5. Dispatch to all destinations in the weekly_digest rules
```

**9K.4: Digest template (Slack)**

```
*Weekly Security Digest -- Jan 20-27, 2026*

*Summary:* 47 events across 8 projects

*Top Issues:*
- CRITICAL: CVE-2026-1234 in lodash@4.17.20 (API Service) -- CISA KEV, reachable
- HIGH: 3 policy violations in Web App after extraction
- MEDIUM: 12 new dependencies added to Data Pipeline

*Per Project:*
| Project | Vulns | Deps Changed | PRs | Status |
|---------|-------|-------------|-----|--------|
| API Service | 2 critical, 1 high | +3 -1 | 2 passed | Blocked |
| Web App | 0 | +5 ~8 | 1 failed | Compliant |
| ...

[View full report in Deptex](https://app.deptex.io/...)
```

### 9L: Test and Preview Rules

Allow users to test their notification rules before enabling them, and preview what notifications would look like.

**9L.1: "Test Rule" button**

In the notification rule sidebar (create/edit), add a "Test Rule" button below the code editor. This runs the trigger code against a sample event and shows the result without actually sending anything.

**Endpoint:** `POST /api/organizations/:id/test-notification-rule`

```typescript
// Request body
{
  code: string;                 // the trigger code to test
  eventType?: string;           // optional: specific event type to test against (default: test all)
}

// Response
{
  results: Array<{
    eventType: string;
    sampleContext: object;      // the context that was passed to the code
    returnValue: any;           // what the code returned
    wouldNotify: boolean;       // whether the notification would fire
    message?: {                 // what the notification would look like
      title: string;
      body: string;
      severity: string;
    };
    error?: string;             // if the code threw an error
    executionTimeMs: number;
  }>;
}
```

**9L.2: Test execution**

```
testNotificationRule(code, eventType?):
  1. Determine which event types to test:
     - If eventType provided: test that one
     - Else: test against 3 sample events (vulnerability_discovered, dependency_added, status_changed)
  2. For each event type:
     a. Load the sample context from SAMPLE_CONTEXTS (9D.3)
     b. Execute the code in sandbox (same as production, 5s timeout for tests)
     c. Normalize the return value
     d. If wouldNotify: build the default message using the template
     e. Record execution time
  3. Return all results
```

**9L.3: Preview in sidebar**

The test results are shown inline in the sidebar below the code editor:

- For each tested event type: show a card with:
  - Event type badge
  - "Would notify" (green check) or "Would skip" (gray dash)
  - If would notify: preview of the notification title + body
  - Execution time
  - If error: red error message with line number

**9L.4: "Send Test Notification" button**

After testing, a "Send Test" button appears on any result where `wouldNotify === true`. Clicking it sends the actual notification to the configured destinations with a `[TEST]` prefix on the title. This creates a real delivery entry in `notification_deliveries` with `is_test: true`.

### 9M: Integration with Event Sources

Where `emitEvent()` and `emitEventBatch()` are called across the codebase. Each integration point is a small addition to existing code.

**9M.1: Extraction pipeline completion**

In [ee/backend/routes/workers.ts](ee/backend/routes/workers.ts) `extractDependencies()`, after successful extraction:

```
After extraction completes:
  1. Compare old project_dependencies snapshot with new extraction results
  2. Compute diff: added, updated, removed dependencies
  3. Build events:
     - For each added dep: { type: 'dependency_added', payload: { name, version, license, ... } }
     - For each updated dep: { type: 'dependency_updated', payload: { name, oldVersion, newVersion, ... } }
     - For each removed dep: { type: 'dependency_removed', payload: { name, version } }
     - If any policy violations: { type: 'policy_violation', payload: { dependency, reasons } }
     - If any license violations: { type: 'license_violation', payload: { dependency, license } }
     - Always: { type: 'extraction_completed', payload: { depsCount, duration } }
  4. Call emitEventBatch(events)
```

On extraction failure:

```
  emitEvent({ type: 'extraction_failed', payload: { error, step }, priority: 'high' })
```

For resolved vulnerabilities (diff old vs new `project_dependency_vulnerabilities`):

```
After extraction + vuln scan completes:
  1. Snapshot project_dependency_vulnerabilities BEFORE extraction
  2. After new vuln data is written, compare old vs new
  3. For each vuln in old snapshot that is NOT in new data:
     - emitEvent({
         type: 'vulnerability_resolved',
         payload: { osvId, severity, packageName, packageVersion, resolvedBy: 'upgrade' | 'removal' | 'withdrawn' },
         priority: 'normal',
       })
```

The `resolvedBy` field indicates HOW the vuln was resolved:

- `'upgrade'` -- the dependency was updated to a version that fixes the vuln
- `'removal'` -- the dependency was removed from the project
- `'withdrawn'` -- the advisory was withdrawn upstream (vuln no longer valid)

**9M.2: Policy evaluation (after extraction)**

In the policy evaluation chain (Phase 4), after `projectStatus()` runs:

```
After projectStatus() returns:
  1. Compare previous status_id with new status_id
  2. If changed:
     - emitEvent({ type: 'status_changed', payload: { previousStatus, newStatus }, priority: 'high' })
     - If new status is non-passing and previous was passing:
       - emitEvent({ type: 'compliance_violation', payload: { ... }, priority: 'high' })
```

**9M.3: PR webhook handler**

In [ee/backend/routes/integrations.ts](ee/backend/routes/integrations.ts) `handlePullRequestEvent()`, after check runs are created:

```
After PR check completes (pass or fail):
  emitEvent({
    type: 'pr_check_completed',
    payload: { prNumber, title, author, checkResult, checkSummary, depsAdded, depsUpdated, depsRemoved, providerUrl },
    priority: checkResult === 'failed' ? 'high' : 'normal',
  })
```

**9M.4: Background vulnerability monitoring**

In the watchtower-poller dependency refresh job (Phase 6D), when new vulnerabilities are discovered:

```
For each new vulnerability affecting a project dependency:
  emitEvent({
    type: 'vulnerability_discovered',
    payload: { osvId, severity, cvssScore, epssScore, depscore, isReachable, cisaKev, affectedPackage, fixedVersions },
    priority: cisaKev ? 'critical' : (severity === 'critical' ? 'high' : 'normal'),
    deduplicationKey: `vuln:${osvId}:${projectId}`,
  })

For EPSS/KEV changes on existing vulns:
  emitEvent({
    type: 'vulnerability_severity_increased',
    payload: { osvId, previousEpss, newEpss, previousKev, newKev },
    priority: newKev ? 'critical' : 'high',
    deduplicationKey: `vuln-sev:${osvId}:${projectId}`,
  })
```

**9M.5: Watchtower poller**

In `backend/watchtower-poller/src/dependency-refresh.ts`:

```
When new version of a dependency is found:
  emitEvent({ type: 'new_version_available', payload: { name, currentVersion, latestVersion }, priority: 'low' })

When deprecation is detected:
  emitEvent({ type: 'dependency_deprecated', payload: { name, version, deprecationMessage }, priority: 'normal' })

When anomaly is detected (existing anomaly detection logic):
  emitEvent({ type: 'supply_chain_anomaly', payload: { name, version, anomalyType, details }, priority: 'high' })
```

**9M.6: Malicious package detection**

In the extraction pipeline (Phase 3A), when malicious indicator is set:

```
If dependency_version.malicious_indicator is set during extraction:
  emitEvent({
    type: 'malicious_package_detected',
    payload: { name, version, indicator: { source, confidence, reason } },
    priority: 'critical',
  })
```

**9M.7: AI fix pipeline**

In the AI fix orchestrator (Phase 7), when a fix PR is created:

```
After Aider creates a fix PR:
  emitEvent({
    type: 'ai_fix_completed',
    payload: { vulnerabilityId, osvId, packageName, fixStrategy, prUrl, prNumber },
    priority: 'high',
  })
```

**9M.8: Health score changes**

After health score recalculation (triggered by extraction or vuln monitoring):

```
If abs(newScore - previousScore) >= 10:
  emitEvent({
    type: 'risk_score_changed',
    payload: { previousScore, newScore, delta: newScore - previousScore },
    priority: 'low',
    deduplicationKey: `risk:${projectId}:${Math.floor(Date.now() / 3600000)}`, // dedup per hour
  })
```

### 9N: Database Migrations Summary

All new tables and columns added in Phase 9:

```sql
-- 9B: Event persistence
CREATE TABLE notification_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_type TEXT NOT NULL,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id UUID REFERENCES projects(id) ON DELETE SET NULL,
  team_id UUID REFERENCES teams(id) ON DELETE SET NULL,
  payload JSONB NOT NULL DEFAULT '{}',
  source TEXT NOT NULL,
  priority TEXT NOT NULL DEFAULT 'normal'
    CHECK (priority IN ('critical', 'high', 'normal', 'low')),
  batch_id UUID,
  deduplication_key TEXT,
  dispatch_attempts INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'dispatching', 'dispatched', 'failed')),
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_notif_events_org ON notification_events(organization_id, created_at DESC);
CREATE INDEX idx_notif_events_project ON notification_events(project_id, created_at DESC);
CREATE INDEX idx_notif_events_batch ON notification_events(batch_id) WHERE batch_id IS NOT NULL;
CREATE INDEX idx_notif_events_status ON notification_events(status) WHERE status = 'pending';

-- UNIQUE partial index to prevent dedup race conditions (TOCTOU).
-- emitEvent() uses INSERT ... ON CONFLICT DO NOTHING with this index.
-- The 24-hour window is enforced at the application layer; the index covers
-- all non-null dedup keys. A daily cleanup job removes old events, keeping
-- the index compact.
CREATE UNIQUE INDEX idx_notif_events_dedup_unique
  ON notification_events(deduplication_key)
  WHERE deduplication_key IS NOT NULL;

-- Lookup index for dedup key queries (non-unique, for SELECT fallback)
CREATE INDEX idx_notif_events_dedup ON notification_events(deduplication_key, created_at DESC)
  WHERE deduplication_key IS NOT NULL;

-- Index for stuck-event reconciliation (9B.2)
CREATE INDEX idx_notif_events_stuck ON notification_events(created_at, dispatch_attempts)
  WHERE status = 'pending';

-- 9J: Delivery tracking
CREATE TABLE notification_deliveries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id UUID NOT NULL REFERENCES notification_events(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  rule_id UUID NOT NULL,
  rule_scope TEXT NOT NULL CHECK (rule_scope IN ('organization', 'team', 'project')),
  rule_name TEXT,
  destination_type TEXT NOT NULL,
  destination_id UUID NOT NULL,
  destination_name TEXT,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'sending', 'delivered', 'failed', 'rate_limited', 'skipped')),
  is_test BOOLEAN NOT NULL DEFAULT false,
  message_title TEXT,
  message_body TEXT,
  message_payload JSONB,
  response JSONB,
  external_id TEXT,
  error_message TEXT,
  attempts INTEGER DEFAULT 0,
  last_attempt_at TIMESTAMPTZ,
  delivered_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_notif_deliveries_event ON notification_deliveries(event_id);
CREATE INDEX idx_notif_deliveries_org_time ON notification_deliveries(organization_id, created_at DESC);
CREATE INDEX idx_notif_deliveries_status ON notification_deliveries(status)
  WHERE status IN ('pending', 'failed');

-- 9I: Rate limiting uses Redis (no SQL table needed)

-- 9K: Weekly digest uses QStash CRON (no SQL table needed)

-- Simplify trigger_type to 2 values:
-- - 'weekly_digest': scheduled summary (no custom code, runs on cron)
-- - 'custom_code_pipeline': event-driven with user-written JS trigger code
-- Drop 'vulnerability_discovered' as a separate type. Users who want vuln-only
-- alerts use custom_code_pipeline with `if (context.event.type !== 'vulnerability_discovered') return false;`
-- The min_depscore_threshold column still works as a fast-path filter on custom_code_pipeline rules.
-- Migrate any existing 'vulnerability_discovered' rules to 'custom_code_pipeline' with auto-generated code.

-- Step 1: Migrate existing vulnerability_discovered rules to custom_code_pipeline
UPDATE organization_notification_rules
  SET trigger_type = 'custom_code_pipeline',
      custom_code = COALESCE(custom_code,
        'if (context.event.type !== ''vulnerability_discovered'') return false;' || chr(10) ||
        'if (!context.vulnerability) return false;' || chr(10) ||
        'return true;')
  WHERE trigger_type = 'vulnerability_discovered';

UPDATE team_notification_rules
  SET trigger_type = 'custom_code_pipeline',
      custom_code = COALESCE(custom_code,
        'if (context.event.type !== ''vulnerability_discovered'') return false;' || chr(10) ||
        'if (!context.vulnerability) return false;' || chr(10) ||
        'return true;')
  WHERE trigger_type = 'vulnerability_discovered';

UPDATE project_notification_rules
  SET trigger_type = 'custom_code_pipeline',
      custom_code = COALESCE(custom_code,
        'if (context.event.type !== ''vulnerability_discovered'') return false;' || chr(10) ||
        'if (!context.vulnerability) return false;' || chr(10) ||
        'return true;')
  WHERE trigger_type = 'vulnerability_discovered';

-- Step 2: Update CHECK constraints
ALTER TABLE organization_notification_rules DROP CONSTRAINT IF EXISTS organization_notification_rules_trigger_type_check;
ALTER TABLE organization_notification_rules ADD CONSTRAINT organization_notification_rules_trigger_type_check
  CHECK (trigger_type IN ('weekly_digest', 'custom_code_pipeline'));

ALTER TABLE team_notification_rules DROP CONSTRAINT IF EXISTS team_notification_rules_trigger_type_check;
ALTER TABLE team_notification_rules ADD CONSTRAINT team_notification_rules_trigger_type_check
  CHECK (trigger_type IN ('weekly_digest', 'custom_code_pipeline'));

ALTER TABLE project_notification_rules DROP CONSTRAINT IF EXISTS project_notification_rules_trigger_type_check;
ALTER TABLE project_notification_rules ADD CONSTRAINT project_notification_rules_trigger_type_check
  CHECK (trigger_type IN ('weekly_digest', 'custom_code_pipeline'));

-- Row Level Security for notification tables.
-- notification_events: any org member can read their org's events.
-- notification_deliveries: only org admins/owners can read deliveries
-- (they contain message payloads with potentially sensitive vulnerability data).

ALTER TABLE notification_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Org members can view their org notification events"
  ON notification_events FOR SELECT
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
    )
  );

CREATE POLICY "Service role full access to notification events"
  ON notification_events FOR ALL
  USING (auth.role() = 'service_role');

ALTER TABLE notification_deliveries ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Org admins can view their org notification deliveries"
  ON notification_deliveries FOR SELECT
  USING (
    organization_id IN (
      SELECT om.organization_id FROM organization_members om
      WHERE om.user_id = auth.uid()
        AND om.role IN ('owner', 'admin')
    )
  );

CREATE POLICY "Service role full access to notification deliveries"
  ON notification_deliveries FOR ALL
  USING (auth.role() = 'service_role');
```

### 9O: New and Modified Files Summary

**New files:**

- `ee/backend/lib/event-bus.ts` -- event emission, QStash dispatch queuing, batch emission, SSRF-protected fetch proxy (9B, 9B.1)
- `ee/backend/lib/notification-dispatcher.ts` -- core dispatch engine, rule resolution, sandbox execution, OAuth refresh mutex (9C, 9C.5)
- `ee/backend/lib/notification-validator.ts` -- trigger code validation (syntax, shape, fetch resilience) (9D)
- `ee/backend/lib/destination-dispatchers.ts` -- all 8 destination dispatchers + message templates (9F)
- `ee/backend/lib/notification-rate-limiter.ts` -- Redis sliding window rate limiting (9I)
- `backend/database/notification_events_schema.sql` -- events table with dispatch_attempts column, UNIQUE dedup index (9N)
- `backend/database/notification_deliveries_schema.sql` -- deliveries table with denormalized organization_id (9N)
- `backend/database/phase9_migrations.sql` -- CHECK constraint updates, RLS policies (9N)

**Modified files:**

- `ee/backend/routes/workers.ts` -- add QStash consumer endpoints: `dispatch-notification`, `dispatch-notification-batch`, `weekly-digest`, `reconcile-stuck-notifications` (9C, 9K, 9B.2); add `emitEvent()` calls after extraction (9M.1)
- `ee/backend/routes/organizations.ts` -- add validation to notification rule CRUD endpoints (9D.4); add `/validate-notification-rule` endpoint (9D); add `/test-notification-rule` endpoint (9L); add `/notification-history` + retry endpoints (9J.2)
- `ee/backend/routes/projects.ts` -- add validation to project notification rule CRUD endpoints (9D.4); add project-scoped notification history endpoint
- `ee/backend/routes/integrations.ts` -- add `emitEvent()` calls in `handlePullRequestEvent` (9M.3)
- `ee/backend/lib/qstash.ts` -- add `queueNotificationDispatch()` function (9B)
- `backend/watchtower-poller/src/dependency-refresh.ts` -- add `emitEvent()` calls for new versions, deprecations, anomalies (9M.5)
- `frontend/src/app/pages/NotificationRulesSection.tsx` -- add validation error display (9D.5), add "Test Rule" button and results UI (9L.3), add "Send Test" button (9L.4)
- `frontend/src/app/pages/OrganizationSettingsPage.tsx` -- add "History" sub-tab in Notifications section (9J.2)
- `backend/load-ee-routes.js` -- mount new QStash consumer routes

### 9P: Edge Cases and Error Handling

1. **Sandbox timeout during dispatch**: If a rule's trigger code hangs (e.g., slow external fetch), the 10s timeout kills it. The rule is marked as `'skipped'` for this event with error "Trigger code timed out (10s)". Other rules continue processing.
2. **Sandbox crash (OOM)**: If trigger code exceeds 128MB memory, isolated-vm throws. Catch the error, mark rule as `'skipped'`, log the OOM. Continue with other rules.
3. **Destination API down**: If Slack/Jira/etc. returns 5xx, the delivery is marked `'failed'` with `retryable: true`. QStash retries up to 5 times with exponential backoff. If still failing after all retries, the delivery stays `'failed'` and appears in the notification history with a "Retry" button.
4. **OAuth token expired (Jira, Asana, GitLab, Bitbucket OAuth)**: Before each API call, check token expiry. If expired, use the refresh_token to get a new access_token. If refresh fails (token revoked), mark delivery as `'failed'` with error "OAuth token expired. Please reconnect the integration in Organization Settings." Log the error and set the integration status to `'error'`.
5. **Destination removed between rule creation and dispatch**: A rule references a destination ID that no longer exists (integration was disconnected). The delivery is marked `'skipped'` with error "Destination not found. The integration may have been disconnected." No crash.
6. **Org deleted between event emission and dispatch**: The QStash consumer runs after the event was emitted. If the org is deleted by then, the event lookup returns null. Return early without error.
7. **Very high event volume (extraction with 500+ deps)**: The `emitEventBatch()` function handles this. Events are inserted in bulk and a single QStash dispatch job is created. The batch dispatcher sends one summary notification, not 500 individual ones.
8. **Rule custom code returns non-boolean**: The `normalizeReturn()` function handles any return type: truthy values -> notify, falsy -> skip. Only `undefined` is flagged during validation (likely a forgot-return bug).
9. **Same event matches multiple rules with different custom messages**: Each rule's custom message (if returned from trigger code) is used for that rule's destinations. Different rules can produce different messages for the same event going to different destinations.
10. **Circular notification (notification triggers notification)**: Events emitted by the notification system itself (meta-notifications like rate limit warnings) use a separate `source: 'notification_system'` tag. Rules can filter on `context.event.source !== 'notification_system'` (and the default templates exclude this source) to prevent loops.
11. **Webhook replay protection**: Custom webhook payloads include a unique `X-Deptex-Delivery` UUID. Consumers can track delivery IDs to detect replays. The payload also includes a timestamp for freshness checking.
12. **Empty destinations array**: If a rule has no destinations (all were removed), the rule evaluates but produces no deliveries. No error -- it's a valid (if useless) state.
13. **Concurrent dispatch of same event**: QStash may retry a dispatch that actually succeeded (the 200 response was lost). The deduplication check in notification_deliveries prevents creating duplicate delivery rows for the same event + destination.
14. **Large payload serialization**: Event payloads are capped at 100KB. If a payload exceeds this (e.g., a batch with hundreds of events), truncate the `events` array in the batch context to the first 50 entries with a `truncated: true` flag.
15. **Discord channel selection**: Discord connections store a guild_id but not always a channel_id. If no channel is configured, attempt to find the guild's first text channel via the Discord API. If that fails, mark delivery as `'failed'` with error "No Discord channel configured."
16. **emitEvent() DB failure on critical event**: If the Supabase insert fails for a critical event (`malicious_package_detected`, CISA KEV vuln), the error propagates to the calling pipeline. The extraction/PR handler should catch this and log it prominently -- the security alert was NOT sent. For non-critical events, the error is swallowed so the source pipeline continues.
17. **Stuck pending events (QStash outage)**: If QStash is down during `emitEvent()`, the event is persisted in `notification_events` with status `'pending'` but the QStash queue step fails. The stuck-event reconciliation job (9B.2) runs every 15 minutes, finds events older than 10 minutes still in `'pending'`, and re-queues them. After 3 failed dispatch attempts, the event is marked `'failed'`.
18. **Deduplication race condition**: Two concurrent `emitEvent()` calls with the same `deduplicationKey` could previously both insert. The UNIQUE partial index on `deduplication_key` (9N) ensures only one succeeds. The loser gets a `23505` constraint violation, catches it, and returns the existing event's ID.
19. **Jira/Linear/Asana missing project/team config**: If a Jira integration is missing `metadata.project_key`, the dispatcher immediately returns `{ success: false, error: 'No Jira project configured...', retryable: false }`. Same for Linear missing `metadata.team_id`. These are not retryable -- the admin must update the integration settings. The delivery is marked `'failed'` with a clear error message visible in the notification history UI.
20. **OAuth refresh contention**: When 5+ deliveries fire in parallel for the same OAuth integration (Jira, Asana) and the token is expired, the Redis mutex (9C.5) serializes the refresh. The first dispatch acquires the lock and refreshes. The other 4 wait up to 5 seconds, then re-read the token from the DB. If the lock times out (30s TTL), it auto-releases so the system isn't deadlocked.
21. **SSRF attempt via trigger code fetch()**: If notification trigger code calls `fetch('http://169.254.169.254/...')` or any private IP, the SSRF protection layer (9B.1) blocks the request before it leaves the server. The fetch returns an error ("Blocked: private IP range"), which the trigger code's try/catch handles. The blocked URL is logged to the audit trail with the org_id and rule_id for investigation.
22. **Email header injection attempt**: If trigger code returns `{ notify: true, title: "fake\r\nBcc: attacker@evil.com" }`, the email dispatcher strips `\r`, `\n`, and null bytes from the title before using it as the email subject (9F.8). The injection is neutralized, and the sanitized title is used as-is.

### 9Q: Test Plan

Tests 1-5 (Event Bus):

1. `emitEvent` persists event to `notification_events` with correct fields
2. `emitEvent` queues QStash job with correct delay for each priority level
3. `emitEvent` with deduplication key skips duplicate within 24h window
4. `emitEventBatch` inserts all events with shared batch_id
5. `emitEventBatch` separates critical events for immediate dispatch

Tests 6-10 (Dispatcher Engine):

1. Dispatcher loads org + team + project rules correctly
2. Dispatcher evaluates trigger code in sandbox and respects true/false return
3. Dispatcher handles enhanced return value `{ notify: true, message: '...' }`
4. Dispatcher deduplicates: same destination from org rule and project rule -> one delivery
5. Dispatcher continues processing other rules when one rule's code throws

Tests 11-15 (Trigger Code Validation):

1. Syntax error in trigger code blocks save with line number
2. Code returning undefined fails shape validation with "forgot return" hint
3. Code returning `{ allowed: true }` (wrong shape) fails with suggestion
4. Code using fetch() without try/catch fails fetch resilience check
5. Code using fetch() with proper try/catch passes all 3 checks

Tests 16-20 (Destination Dispatchers):

1. Slack dispatcher sends Block Kit message with correct severity color
2. Discord dispatcher sends embed with correct fields
3. Jira dispatcher creates issue with correct priority mapping
4. Linear dispatcher creates issue via GraphQL
5. Custom webhook dispatcher signs payload with HMAC-SHA256

Tests 21-25 (Webhook Delivery):

1. Successful webhook delivery records 200 status in notification_deliveries
2. 5xx response triggers retry via QStash (retryable: true)
3. 4xx response (non-429) does not retry (retryable: false)
4. 429 response retries with respect to Retry-After header
5. Webhook timeout (10s) returns retryable error

Tests 26-30 (Batching):

1. Multiple dependency_added events within 30s window are batched into one notification
2. Critical priority event (malicious_package_detected) bypasses batching
3. Batch notification includes summary with per-type counts
4. Trigger code receives context.batch with correct totals
5. Mixed-priority batch: critical dispatched immediately, normal batched

Tests 31-35 (Rate Limiting):

1. Org rate limit (200/hour) enforced: 201st notification is rate_limited
2. Destination rate limit (30/hour) enforced per integration connection
3. Burst allowance: 20 notifications in 1 minute allowed within hourly limit
4. Rate-limited delivery marked as 'rate_limited' (not 'failed')
5. Meta-notification sent to org admins when rate limit hit (once per hour)

Tests 36-40 (Delivery Tracking):

1. notification_deliveries row created with correct status transitions: pending -> sending -> delivered
2. Failed delivery records error_message and increments attempts
3. Notification history API returns paginated, filterable results
4. Retry endpoint re-queues failed delivery via QStash
5. Retention cleanup deletes events and deliveries older than 90 days

Tests 41-45 (Weekly Digest):

1. Weekly digest assembles correct event summary for past 7 days
2. Digest groups events by project with per-type counts
3. Digest Slack message uses correct Block Kit format
4. Digest email uses HTML template with severity badges
5. Digest only runs for orgs with active weekly_digest rules

Tests 46-50 (Integration and Edge Cases):

1. Full flow: extraction completes -> events emitted -> rules evaluated -> Slack message sent -> delivery tracked
2. Full flow: vulnerability discovered by background monitor -> critical Slack alert + Jira ticket created
3. Full flow: PR check failed -> notification sent -> notification history shows delivery
4. Sandbox OOM doesn't crash dispatcher, other rules continue
5. Destination removed between rule creation and dispatch -> delivery marked 'skipped'

Tests 51-53 (Missing Dispatcher Coverage):

1. Email dispatcher sends HTML email with correct severity badge and sanitized subject
2. Asana dispatcher creates task with project assignment when project_gid is configured
3. PagerDuty dispatcher sends event with correct severity mapping and routing key

Tests 54-56 (SSRF Protection):

1. Sandbox fetch() to `http://169.254.169.254/...` (cloud metadata) is blocked
2. Sandbox fetch() to `http://10.0.0.1/internal-api` (private IP) is blocked
3. Sandbox fetch() to hostname that DNS-resolves to a private IP is blocked (DNS rebinding)

Tests 57 (Email Security):

1. Email subject with `\r\n` injection characters is sanitized (CR/LF stripped, capped at 998 chars)

Tests 58-60 (Event Bus Resilience):

1. `emitEvent()` DB failure on critical event propagates error to caller
2. Stuck-event reconciliation re-queues events in `'pending'` status older than 10 minutes
3. Concurrent `emitEvent()` calls with same dedup key: only one row inserted (UNIQUE index)

Tests 61-62 (Dispatcher Config Validation):

1. Jira dispatcher with missing `project_key` returns clear error, delivery marked `'failed'` (not retryable)
2. Linear dispatcher with missing `team_id` returns clear error, delivery marked `'failed'` (not retryable)

Tests 63 (OAuth Mutex):

1. Concurrent dispatches to same OAuth integration: only one token refresh occurs, others wait and reuse the new token

Tests 64-65 (RLS):

1. Supabase client query on `notification_events` returns only the authenticated user's org's events
2. Non-admin org member cannot read `notification_deliveries` (RLS blocks, only admin/owner allowed)

