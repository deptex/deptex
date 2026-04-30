declare const NextResponse: { json: (body: unknown) => unknown };
declare function escapeHtml(s: string): string;

async function GET(request: any) {
  const bio = request.nextUrl.searchParams.get('bio');
  const safe = escapeHtml(bio);
  return NextResponse.json({ html: `<div class="bio">${safe}</div>` });
}

GET({ nextUrl: { searchParams: { get: () => '<script>' } } });
