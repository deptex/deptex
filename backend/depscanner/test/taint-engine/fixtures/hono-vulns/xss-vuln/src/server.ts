async function handler(c: any) {
  const bio = c.req.query('bio');
  return c.html(`<div class="bio">${bio}</div>`);
}

handler({ req: { query: () => '<script>' }, html: (x: string) => x });
