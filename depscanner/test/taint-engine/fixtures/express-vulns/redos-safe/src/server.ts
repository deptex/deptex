declare function escapeRegExp(s: string): string;
declare function safeRegex(s: string): boolean;

// Safe #1 — pattern escaped before compilation (escapeRegExp sanitizer).
function handler(req: any) {
  const userPattern = req.query.pattern;
  const escaped = escapeRegExp(userPattern);
  const re = new RegExp(escaped);
  re.test('victim');
}

// Safe #2 — compile-only validity probe: the constructed RegExp is discarded
// (never .test/.exec'd), so it is not a ReDoS execution sink.
function probeOnly(raw: string) {
  try { new RegExp(raw); } catch { return false; }
  return true;
}

// Safe #3 — interprocedural validate-then-use: the pattern is validated by a
// safe-regex check inside a wrapper before being compiled + executed. The
// engine models the wrapper as a sanitizer on the validated argument.
function checkIndicator(raw: string): boolean {
  if (raw.length > 256) return false;
  if (!safeRegex(raw)) return false;
  return true;
}
function validatedUse(req: any) {
  const pattern = req.query.pattern;
  if (!checkIndicator(pattern)) return;
  return new RegExp(pattern).test('victim');
}

handler({ query: { pattern: '(a+)+$' } });
probeOnly('(a+)+$');
validatedUse({ query: { pattern: '(a+)+$' } });
