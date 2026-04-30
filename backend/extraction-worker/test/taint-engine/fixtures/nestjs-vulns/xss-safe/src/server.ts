declare const res: { send: (body: string) => void };
declare function escapeHtml(s: string): string;

class ProfileController {
  show(query: any) {
    const bio = query.bio;
    const safe = escapeHtml(bio);
    res.send(`<div class="bio">${safe}</div>`);
  }
}

new ProfileController().show({ bio: '<script>' });
