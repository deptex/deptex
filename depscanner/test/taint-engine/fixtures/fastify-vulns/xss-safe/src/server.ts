declare function escapeHtml(s: string): string;

async function handler(request: any, reply: any) {
  const bio = request.query.bio;
  const safe = escapeHtml(bio);
  reply.send(`<div class="bio">${safe}</div>`);
}

handler({ query: { bio: '<script>' } }, { send: () => undefined });
