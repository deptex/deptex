declare const winston: { info(s: string): any };

function handler(req: any) {
  const username = req.body.username;
  winston.info(username);
}

handler({ body: { username: 'alice\nADMIN: granted' } });
