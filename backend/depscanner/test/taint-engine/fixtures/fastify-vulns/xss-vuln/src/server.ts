async function handler(request: any, reply: any) {
  const bio = request.query.bio;
  reply.send(`<div class="bio">${bio}</div>`);
}

handler({ query: { bio: '<script>' } }, { send: () => undefined });
