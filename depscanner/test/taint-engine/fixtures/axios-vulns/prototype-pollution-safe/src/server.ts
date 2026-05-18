declare const axios: any;

function handler(_req: any) {
  // Hard-coded config — not tainted, no flow should be emitted.
  const safeConfig = { url: '/api/test' };
  const config = axios.mergeConfig({}, safeConfig);
  return config;
}

handler({ body: { config: 'ignored' } });
