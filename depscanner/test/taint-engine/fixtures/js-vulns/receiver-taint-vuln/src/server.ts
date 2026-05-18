// Exercises the propagate-core.ts receiver-taint pass-through rule in JS.
//
// `req.body.cmd` is tainted by the express source spec, then the value
// flows through two 0-arg pass-through method calls (`.toString()`,
// `.trim()`) before reaching `child_process.exec`. Before the receiver
// taint rule the temp synthesised for each pass-through call lost its
// taint because the IR has no positional args; with the rule the
// receiver's taint flows through each hop to fire the command-injection
// sink.
declare const child_process: any;

function handler(req: any) {
  const raw = req.body.cmd;
  // Two pass-through hops; neither has positional args.
  const normalised = raw.toString().trim();
  child_process.exec(normalised);
}

handler({ body: { cmd: 'ls' } });
