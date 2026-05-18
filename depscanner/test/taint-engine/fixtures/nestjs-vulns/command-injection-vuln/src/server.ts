declare const child_process: any;

class UsersController {
  // Simulated NestJS handler — body would normally be bound by @Body()
  create(body: any) {
    const cmd = body.cmd;
    child_process.exec(cmd);
  }
}

new UsersController().create({ cmd: 'ls' });
