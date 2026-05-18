declare const child_process: any;

function handler(req: any) {
  const cmd = req.body.cmd;
  child_process.exec(cmd);
}

handler({ body: { cmd: 'ls' } });
