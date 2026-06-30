declare function require(id: string): any;

// CVE-2024-55565 — nanoid before 5.0.9 produced predictable / non-uniform IDs
// when the size argument was a non-integer. When that size is attacker-
// controlled the generated ID becomes guessable. Tainted size → arg-0 sink.
function makeId(req: any) {
  const { nanoid } = require('nanoid');
  const size = req.body.size;
  const id = nanoid(size);
  return id;
}

makeId({ body: { size: 'NaN' } });
