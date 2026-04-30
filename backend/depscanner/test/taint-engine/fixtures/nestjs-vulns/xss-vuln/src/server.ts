declare const res: { send: (body: string) => void };

class ProfileController {
  show(query: any) {
    const bio = query.bio;
    res.send(`<div class="bio">${bio}</div>`);
  }
}

new ProfileController().show({ bio: '<script>' });
