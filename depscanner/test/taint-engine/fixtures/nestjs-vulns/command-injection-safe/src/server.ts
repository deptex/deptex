declare const child_process: any;
declare function shellQuote(s: string): string;

class UsersController {
  create(body: any) {
    const cmd = body.cmd;
    const safe = shellQuote(cmd);
    child_process.exec(safe);
  }
}

new UsersController().create({ cmd: 'ls' });
