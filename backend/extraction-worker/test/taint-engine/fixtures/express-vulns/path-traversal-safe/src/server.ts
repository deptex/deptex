declare const fs: { readFile(path: string, cb: (err: any, data: any) => void): void };
declare const path: { basename(s: string): string };

function handler(req: any) {
  const file = req.query.file;
  const safe = path.basename(file);
  fs.readFile(safe, () => {});
}

handler({ query: { file: '../../etc/passwd' } });
