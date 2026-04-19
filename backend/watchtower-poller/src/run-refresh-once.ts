/**
 * Run dependency refresh once and exit. Use this to trigger new_version jobs now
 * without waiting for the Daily poll. Enqueues jobs to watchtower-new-version-jobs(-local).
 *
 * Usage: npm run refresh-once   (or npx tsx src/run-refresh-once.ts)
 */
import 'dotenv/config';
import { runDependencyRefresh } from './dependency-refresh';

runDependencyRefresh()
  .then((r) => {
    console.log(`Done. Processed: ${r.processed}, errors: ${r.errors}`);
    process.exit(r.errors > 0 ? 1 : 0);
  })
  .catch((err) => {
    console.error('runDependencyRefresh failed:', err);
    process.exit(1);
  });
