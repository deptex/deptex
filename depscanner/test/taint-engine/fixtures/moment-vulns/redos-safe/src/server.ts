declare const moment: (input: string) => { isValid(): boolean };

function handler(req: any) {
  // Hard-coded date — not tainted, no flow should be emitted.
  const fixedInput = '2026-05-12';
  const m = moment(fixedInput);
  return m.isValid();
}

handler({ query: { date: 'ignored' } });
