declare const axios: any;

function handler(req: any) {
  // CVE-2026-25639 family — attacker-controlled config merged into target,
  // __proto__ / constructor.prototype keys poison Object.prototype.
  const maliciousConfig = JSON.parse(req.body.config);
  const config = axios.mergeConfig({}, maliciousConfig);
  return config;
}

handler({ body: { config: '{"__proto__":{"polluted":true}}' } });
