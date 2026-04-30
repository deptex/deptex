declare const child_process: any;

async function handler(c: any) {
  const cmd = c.req.query('cmd');
  child_process.exec(cmd);
}

handler({ req: { query: (_k: string) => 'ls' } });
