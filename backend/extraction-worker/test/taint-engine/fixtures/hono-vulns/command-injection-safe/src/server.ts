declare const child_process: any;
declare function shellQuote(s: string): string;

async function handler(c: any) {
  const cmd = c.req.query('cmd');
  const safe = shellQuote(cmd);
  child_process.exec(safe);
}

handler({ req: { query: (_k: string) => 'ls' } });
