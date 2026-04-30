declare const child_process: any;

// Next.js App Router POST handler shape
async function POST(request: any) {
  const body = await request.json();
  child_process.exec(body.cmd);
}

POST({ json: async () => ({ cmd: 'ls' }) });
