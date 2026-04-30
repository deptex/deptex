declare const child_process: any;
declare function shellQuote(s: string): string;

async function POST(request: any) {
  const body = await request.json();
  const safe = shellQuote(body.cmd);
  child_process.exec(safe);
}

POST({ json: async () => ({ cmd: 'ls' }) });
