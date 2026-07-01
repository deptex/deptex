declare function require(id: string): any;

// Safe: a constant integer size is passed to nanoid, so the generated ID
// retains full entropy. No weak_crypto flow should be emitted.
function makeId(_req: any) {
  const { nanoid } = require('nanoid');
  const id = nanoid(21);
  return id;
}

makeId({ body: { size: 'ignored' } });
