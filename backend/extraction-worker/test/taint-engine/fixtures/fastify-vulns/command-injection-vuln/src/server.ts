declare const child_process: any;

async function handler(request: any, _reply: any) {
  const cmd = request.body.cmd;
  child_process.exec(cmd);
}

handler({ body: { cmd: 'ls' } }, {});
