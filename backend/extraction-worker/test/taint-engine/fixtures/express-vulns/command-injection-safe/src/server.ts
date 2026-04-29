declare const child_process: any;
declare function shellQuote(s: string): string;

function handler(req: any) {
  const cmd = req.body.cmd;
  const safe = shellQuote(cmd);
  child_process.exec(safe);
}

handler({ body: { cmd: 'ls' } });
