declare const winston: { info(s: string): any };
declare function stripNewlines(s: string): string;

function handler(req: any) {
  const username = req.body.username;
  const safe = stripNewlines(username);
  winston.info(safe);
}

handler({ body: { username: 'alice' } });
