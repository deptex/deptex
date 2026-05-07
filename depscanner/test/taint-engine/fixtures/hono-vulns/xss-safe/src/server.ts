declare function escapeHtml(s: string): string;

async function handler(c: any) {
  const bio = c.req.query('bio');
  const safe = escapeHtml(bio);
  return c.html(`<div class="bio">${safe}</div>`);
}

handler({ req: { query: () => '<script>' }, html: (x: string) => x });
