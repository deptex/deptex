'use server';

export async function echoAction(formData: FormData): Promise<{ html: string }> {
  // REACHABLE: user-controlled FormData value returned for
  // dangerouslySetInnerHTML on the client. Classic Next.js server-action
  // XSS shape — looks safe because it's "server-side" but the trust
  // boundary is the client render.
  const msg = String(formData.get('msg') ?? '');
  return { html: `<div class="echo">${msg}</div>` };
}
