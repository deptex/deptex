/**
 * stress-test-canvas.mjs
 *
 * Stress-tests the Supabase Realtime Broadcast layer used by the org canvas
 * multiplayer feature. Simulates N concurrent users sending cursor events and
 * a single receiver that measures delivery rate, drop rate, and latency.
 *
 * Usage:
 *   node backend/scripts/stress-test-canvas.mjs [--users=N] [--duration=N] [--drag]
 *
 * Required environment variables:
 *   SUPABASE_URL      – e.g. https://xxxx.supabase.co
 *   SUPABASE_ANON_KEY – public anon key (RLS will apply; use service role for
 *                       private channels, but anon is fine for public broadcast)
 *   ORG_ID            – UUID of the org whose canvas channel to test
 *
 * Options:
 *   --users=N      Number of concurrent sender clients (default: 5)
 *   --duration=N   Test duration in seconds (default: 10)
 *   --drag         Also run a drag-phase test after the cursor phase
 *
 * Example:
 *   ORG_ID=abc-123 SUPABASE_URL=https://xxx.supabase.co SUPABASE_ANON_KEY=eyJ... \
 *     node backend/scripts/stress-test-canvas.mjs --users=10 --duration=15 --drag
 *
 * Notes:
 *   - Uses public (non-private) channels so no JWT is required.
 *   - The receiver subscribes to the same org channel topic and counts events
 *     that are NOT its own (self: false is set on senders).
 *   - Each sender uses a unique faked userId so the receiver never filters
 *     them out by the "skip own events" guard.
 *   - The receiver's own channel also has self: false so it won't mistakenly
 *     count its own rare heartbeats.
 */

import { createRequire } from 'module';
import { randomUUID } from 'crypto';
const require = createRequire(import.meta.url);
const { createClient } = require('@supabase/supabase-js');

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const CURSOR_SEND_INTERVAL_MS = 80;  // mirrors app constant
const DRAG_SEND_INTERVAL_MS   = 40;  // mirrors app constant
const DRAG_MOVE_COUNT         = 20;  // drag-move events per drag sequence

function die(msg) {
  console.error(`\n[error] ${msg}\n`);
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Parse CLI args
// ---------------------------------------------------------------------------

const args = Object.fromEntries(
  process.argv.slice(2).map((a) => {
    const [k, v] = a.replace(/^--/, '').split('=');
    return [k, v ?? true];
  }),
);

const NUM_USERS    = Math.max(1, parseInt(args.users    ?? '5',  10));
const DURATION_SEC = Math.max(1, parseInt(args.duration ?? '10', 10));
const RUN_DRAG     = Boolean(args.drag);

// ---------------------------------------------------------------------------
// Env validation
// ---------------------------------------------------------------------------

const SUPABASE_URL      = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
const ORG_ID            = process.env.ORG_ID;

if (!SUPABASE_URL)      die('Missing env var: SUPABASE_URL');
if (!SUPABASE_ANON_KEY) die('Missing env var: SUPABASE_ANON_KEY');
if (!ORG_ID)            die('Missing env var: ORG_ID');

// ---------------------------------------------------------------------------
// Channel topic (mirrors useOrgCanvasCursors.ts: orgTopic())
// ---------------------------------------------------------------------------

const CHANNEL_TOPIC = `org-canvas:${ORG_ID}:org`;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Create a fresh Supabase client (each simulated user gets its own). */
function makeClient() {
  return createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    realtime: { params: { eventsPerSecond: 100 } },
  });
}

/** Sleep for ms milliseconds. */
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Wait until a Supabase channel reaches SUBSCRIBED status, with timeout. */
function waitSubscribed(channel, timeoutMs = 10_000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`Channel ${channel.topic} subscription timed out`)),
      timeoutMs,
    );
    channel.subscribe((status) => {
      if (status === 'SUBSCRIBED') {
        clearTimeout(timer);
        resolve();
      } else if (status === 'CHANNEL_ERROR' || status === 'TIMED_OUT') {
        clearTimeout(timer);
        reject(new Error(`Channel ${channel.topic} error: ${status}`));
      }
    });
  });
}

/** Compute percentile from a sorted numeric array. */
function percentile(sorted, p) {
  if (sorted.length === 0) return 0;
  const idx = Math.ceil((p / 100) * sorted.length) - 1;
  return sorted[Math.max(0, Math.min(idx, sorted.length - 1))];
}

/** Render a simple ASCII table row. */
function row(label, value) {
  const pad = 30;
  return `  ${label.padEnd(pad)} ${value}`;
}

function hr(char = '─', width = 55) {
  return '  ' + char.repeat(width);
}

// ---------------------------------------------------------------------------
// Receiver
// ---------------------------------------------------------------------------

class Receiver {
  constructor() {
    this.client   = makeClient();
    this.channel  = null;
    this.latencies = [];    // raw latency samples (ms)
    this.received  = 0;     // total cursor events counted
    this.dragEventsReceived = 0; // drag-move events counted
    this.dragLatencies = [];
  }

  async subscribe() {
    this.channel = this.client.channel(CHANNEL_TOPIC, {
      config: { broadcast: { self: false } },
    });

    this.channel.on('broadcast', { event: 'cursor' }, (msg) => {
      const p = msg.payload;
      if (!p) return;
      const latency = Date.now() - (p.sentAt ?? Date.now());
      this.latencies.push(latency);
      this.received++;
    });

    this.channel.on('broadcast', { event: 'drag-move' }, (msg) => {
      const p = msg.payload;
      if (!p) return;
      const latency = Date.now() - (p.sentAt ?? Date.now());
      this.dragLatencies.push(latency);
      this.dragEventsReceived++;
    });

    await waitSubscribed(this.channel);
    console.log(`  [receiver] subscribed to ${CHANNEL_TOPIC}`);
  }

  async unsubscribe() {
    if (this.channel) {
      await this.channel.unsubscribe();
      this.client.removeChannel(this.channel);
    }
  }
}

// ---------------------------------------------------------------------------
// Sender
// ---------------------------------------------------------------------------

class Sender {
  constructor(index) {
    this.index     = index;
    this.userId    = `stress-user-${randomUUID()}`;
    this.sessionId = randomUUID();
    this.client    = makeClient();
    this.channel   = null;
    this.seq       = 0;
    this.sent      = 0;
    this._timer    = null;
  }

  /** Build a realistic cursor payload matching the app's CursorPayload shape.
   *  We add a `sentAt` field (not in the app payload) for latency measurement. */
  _cursorPayload(x, y) {
    return {
      userId:    this.userId,
      name:      `Stress User ${this.index + 1}`,
      avatarUrl: null,
      role:      'member',
      roleLabel: 'Member',
      roleColor: '#6366f1',
      x,
      y,
      seq:       ++this.seq,
      sessionId: this.sessionId,
      sentAt:    Date.now(),
    };
  }

  async subscribe() {
    // Senders also subscribe (required before .send()) but with self: false so
    // they don't receive their own events back (matches app behaviour).
    this.channel = this.client.channel(CHANNEL_TOPIC, {
      config: { broadcast: { self: false, ack: false } },
    });
    await waitSubscribed(this.channel);
  }

  /** Start sending cursor events at CURSOR_SEND_INTERVAL_MS cadence. */
  startCursorLoop() {
    this._timer = setInterval(() => {
      // Walk the sender around the canvas in a simple Lissajous path.
      const t  = Date.now() / 1000;
      const x  = 500 + 300 * Math.sin(t * (1 + this.index * 0.1));
      const y  = 400 + 200 * Math.cos(t * (0.7 + this.index * 0.07));

      this.channel.send({
        type:    'broadcast',
        event:   'cursor',
        payload: this._cursorPayload(x, y),
      });
      this.sent++;
    }, CURSOR_SEND_INTERVAL_MS);
  }

  stopCursorLoop() {
    if (this._timer) {
      clearInterval(this._timer);
      this._timer = null;
    }
  }

  /**
   * Simulate one drag sequence:
   *   drag-start → N × drag-move (at 40 ms intervals) → drag-stop
   * Returns the number of drag-move events sent.
   */
  async runDragSequence(nodeId = 'team-stress-node') {
    // drag-start
    this.channel.send({
      type:    'broadcast',
      event:   'drag-start',
      payload: { userId: this.userId, nodeId, seq: ++this.seq, canDrag: true, sentAt: Date.now() },
    });

    // drag-move events at the app's DRAG_SEND_INTERVAL_MS throttle
    for (let i = 0; i < DRAG_MOVE_COUNT; i++) {
      await sleep(DRAG_SEND_INTERVAL_MS);
      const x = 200 + i * 10;
      const y = 200 + i * 5;
      this.channel.send({
        type:    'broadcast',
        event:   'drag-move',
        payload: {
          userId: this.userId,
          moves:  [{ nodeId, x, y }],
          seq:    ++this.seq,
          sentAt: Date.now(),
        },
      });
    }

    // drag-stop
    await sleep(DRAG_SEND_INTERVAL_MS);
    this.channel.send({
      type:    'broadcast',
      event:   'drag-stop',
      payload: { userId: this.userId, nodeId, seq: ++this.seq, sentAt: Date.now() },
    });

    return DRAG_MOVE_COUNT;
  }

  async unsubscribe() {
    this.stopCursorLoop();
    if (this.channel) {
      await this.channel.unsubscribe();
      this.client.removeChannel(this.channel);
    }
  }
}

// ---------------------------------------------------------------------------
// Print results
// ---------------------------------------------------------------------------

function printCursorResults({ numUsers, durationSec, expectedTotal, receiver, senders }) {
  const totalSent = senders.reduce((s, c) => s + c.sent, 0);
  const received  = receiver.received;
  // Each sender sends to N-1 other potential receivers (but we have 1 receiver
  // client). The receiver sees all events from all senders since it has a
  // unique userId and never filters them.  Expected = totalSent because all
  // events should reach the single receiver.
  const expectedReceived = totalSent;
  const dropped    = Math.max(0, expectedReceived - received);
  const dropRate   = expectedReceived > 0 ? (dropped / expectedReceived) * 100 : 0;

  const lats = [...receiver.latencies].sort((a, b) => a - b);
  const avg  = lats.length > 0 ? lats.reduce((s, v) => s + v, 0) / lats.length : 0;
  const p50  = percentile(lats, 50);
  const p95  = percentile(lats, 95);
  const p99  = percentile(lats, 99);
  const min  = lats[0] ?? 0;
  const max  = lats[lats.length - 1] ?? 0;

  const eventsPerSecSent = totalSent / durationSec;
  const eventsPerSecRecv = received  / durationSec;

  console.log('');
  console.log(hr('═'));
  console.log('  CURSOR STRESS TEST RESULTS');
  console.log(hr('═'));
  console.log(row('Users (senders)',         String(numUsers)));
  console.log(row('Duration (s)',            String(durationSec)));
  console.log(row('Send interval (ms)',      String(CURSOR_SEND_INTERVAL_MS)));
  console.log(hr());
  console.log(row('Events sent (total)',     String(totalSent)));
  console.log(row('Events sent/s',          eventsPerSecSent.toFixed(1)));
  console.log(row('Events received',         String(received)));
  console.log(row('Events received/s',       eventsPerSecRecv.toFixed(1)));
  console.log(row('Events dropped',          String(dropped)));
  console.log(row('Drop rate',              `${dropRate.toFixed(2)}%`));
  console.log(hr());
  console.log('  LATENCY (receiver: Date.now() − payload.sentAt)');
  console.log(hr());
  console.log(row('Samples',               String(lats.length)));
  console.log(row('Min (ms)',              String(min)));
  console.log(row('Avg (ms)',              avg.toFixed(1)));
  console.log(row('p50 (ms)',              String(p50)));
  console.log(row('p95 (ms)',              String(p95)));
  console.log(row('p99 (ms)',              String(p99)));
  console.log(row('Max (ms)',              String(max)));
  console.log(hr('═'));
}

function printDragResults({ sentCount, receiver }) {
  const received  = receiver.dragEventsReceived;
  const dropped   = Math.max(0, sentCount - received);
  const dropRate  = sentCount > 0 ? (dropped / sentCount) * 100 : 0;

  const lats = [...receiver.dragLatencies].sort((a, b) => a - b);
  const avg  = lats.length > 0 ? lats.reduce((s, v) => s + v, 0) / lats.length : 0;
  const p50  = percentile(lats, 50);
  const p95  = percentile(lats, 95);
  const p99  = percentile(lats, 99);

  console.log('');
  console.log(hr('═'));
  console.log('  DRAG-PHASE RESULTS  (drag-start → 20× drag-move → drag-stop)');
  console.log(hr('═'));
  console.log(row('Drag-move events sent',   String(sentCount)));
  console.log(row('Drag-move events received', String(received)));
  console.log(row('Dropped',                String(dropped)));
  console.log(row('Drop rate',             `${dropRate.toFixed(2)}%`));
  console.log(row('Throttle interval (ms)', String(DRAG_SEND_INTERVAL_MS)));
  console.log(hr());
  console.log('  DRAG-MOVE LATENCY');
  console.log(hr());
  console.log(row('Samples', String(lats.length)));
  console.log(row('Avg (ms)', avg.toFixed(1)));
  console.log(row('p50 (ms)', String(p50)));
  console.log(row('p95 (ms)', String(p95)));
  console.log(row('p99 (ms)', String(p99)));
  console.log(hr('═'));
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

console.log('');
console.log('  ╔══════════════════════════════════════════════════════╗');
console.log('  ║          org-canvas Broadcast Stress Test            ║');
console.log('  ╚══════════════════════════════════════════════════════╝');
console.log('');
console.log(row('Supabase URL',   SUPABASE_URL));
console.log(row('Channel topic',  CHANNEL_TOPIC));
console.log(row('Users',          String(NUM_USERS)));
console.log(row('Duration (s)',   String(DURATION_SEC)));
console.log(row('Drag phase',     RUN_DRAG ? 'yes' : 'no'));
console.log('');

// ------ Phase 1: subscribe all clients ------

console.log('  [setup] creating clients…');

const receiver = new Receiver();
const senders  = Array.from({ length: NUM_USERS }, (_, i) => new Sender(i));

// Subscribe receiver first, then all senders in parallel.
await receiver.subscribe();
await Promise.all(senders.map((s) => s.subscribe()));

console.log(`  [setup] ${NUM_USERS} sender(s) subscribed.`);

// Brief settle time so all WebSocket connections are fully established
// before we start the clock.
await sleep(500);

// ------ Phase 2: cursor stress ------

console.log(`\n  [cursor] running for ${DURATION_SEC}s at ${CURSOR_SEND_INTERVAL_MS}ms intervals…`);

const expectedEventsPerSender = Math.floor((DURATION_SEC * 1000) / CURSOR_SEND_INTERVAL_MS);
console.log(row('  Expected events/sender', String(expectedEventsPerSender)));
console.log(row('  Expected total sent',    String(expectedEventsPerSender * NUM_USERS)));

for (const sender of senders) sender.startCursorLoop();

await sleep(DURATION_SEC * 1000);

for (const sender of senders) sender.stopCursorLoop();

// Allow in-flight events a short window to arrive.
await sleep(300);

printCursorResults({
  numUsers:    NUM_USERS,
  durationSec: DURATION_SEC,
  expectedTotal: expectedEventsPerSender * NUM_USERS,
  receiver,
  senders,
});

// ------ Phase 3: drag stress (optional) ------

if (RUN_DRAG) {
  console.log('\n  [drag] running drag sequence on first sender…');

  // Reset drag counters on receiver.
  receiver.dragEventsReceived = 0;
  receiver.dragLatencies = [];

  // Only the first sender performs the drag for a deterministic expected count.
  const dragSender = senders[0];
  const sentCount  = await dragSender.runDragSequence('team-stress-node');

  // Allow in-flight drag events to arrive.
  await sleep(500);

  printDragResults({ sentCount, receiver });
}

// ------ Teardown ------

console.log('\n  [teardown] unsubscribing all channels…');

await Promise.all([
  receiver.unsubscribe(),
  ...senders.map((s) => s.unsubscribe()),
]);

console.log('  [teardown] done.\n');
process.exit(0);
