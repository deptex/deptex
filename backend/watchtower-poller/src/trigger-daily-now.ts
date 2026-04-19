/**
 * Reschedule the Daily poll job to run now. The next time the poller checks (within ~60s),
 * it will see the job as due and run dependency refresh + poll sweep.
 *
 * Usage: npm run trigger-daily-now   (or npx tsx src/trigger-daily-now.ts)
 * Requires: poller running in another terminal (npm run dev).
 */
import 'dotenv/config';
import { scheduleDailyPollJob } from './scheduler';

scheduleDailyPollJob(Date.now())
  .then(() => {
    console.log('Daily poll job scheduled to run now. Poller will pick it up on next check (~60s).');
    process.exit(0);
  })
  .catch((err) => {
    console.error('Failed to schedule:', err);
    process.exit(1);
  });
