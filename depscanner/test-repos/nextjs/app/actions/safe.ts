'use server';

export async function safeAction(): Promise<{ html: string }> {
  // UNREACHABLE: literal string, no user taint.
  return { html: '<div class="echo">welcome</div>' };
}
