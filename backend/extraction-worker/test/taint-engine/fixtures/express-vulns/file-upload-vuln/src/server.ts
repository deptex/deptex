declare const multer: { single(field: string): any };

function handler(req: any) {
  const fieldName = req.body.field;
  const upload = multer.single(fieldName);
  void upload;
}

handler({ body: { field: 'avatar' } });
