declare const multer: { single(field: string): any };
declare function whitelistedFilename(s: string): string;

function handler(req: any) {
  const fieldName = req.body.field;
  const safe = whitelistedFilename(fieldName);
  const upload = multer.single(safe);
  void upload;
}

handler({ body: { field: 'avatar' } });
