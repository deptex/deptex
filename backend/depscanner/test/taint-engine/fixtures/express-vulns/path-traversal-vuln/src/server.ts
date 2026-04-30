declare const fs: { readFile(path: string, cb: (err: any, data: any) => void): void };

function handler(req: any) {
  const file = req.query.file;
  fs.readFile(file, () => {});
}

handler({ query: { file: '../../etc/passwd' } });
