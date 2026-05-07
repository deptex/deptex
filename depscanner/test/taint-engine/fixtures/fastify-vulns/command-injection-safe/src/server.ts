declare const child_process: any;
declare function shellQuote(s: string): string;

async function handler(request: any, _reply: any) {
  const cmd = request.body.cmd;
  const safe = shellQuote(cmd);
  child_process.exec(safe);
}

handler({ body: { cmd: 'ls' } }, {});
