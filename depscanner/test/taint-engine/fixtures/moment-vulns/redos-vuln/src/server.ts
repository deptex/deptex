declare const moment: (input: string) => { isValid(): boolean };

function handler(req: any) {
  const userInput = req.query.date;
  const m = moment(userInput);
  return m.isValid();
}

handler({ query: { date: '2026-05-12' } });
