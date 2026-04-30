// Test runner: invokes the GHSA arm of malicious feed-sync directly.
// Use this during the pre-merge testing pass to populate a few thousand
// real malware advisories into known_malicious_packages without spinning up
// the backend HTTP layer.
import 'dotenv/config';
import { runMaliciousFeedSync } from '../src/lib/malicious/feed-sync';

(async () => {
  const t0 = Date.now();
  console.log('Running GHSA feed-sync...');
  const result = await runMaliciousFeedSync('ghsa');
  console.log('Result:', JSON.stringify(result, null, 2));
  console.log('Duration:', ((Date.now() - t0) / 1000).toFixed(1), 's');
})().catch((e) => { console.error('FATAL', e); process.exit(1); });
