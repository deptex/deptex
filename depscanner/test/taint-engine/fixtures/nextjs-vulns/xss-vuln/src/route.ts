declare const NextResponse: { json: (body: unknown) => unknown };

async function GET(request: any) {
  const bio = request.nextUrl.searchParams.get('bio');
  return NextResponse.json({ html: `<div class="bio">${bio}</div>` });
}

GET({ nextUrl: { searchParams: { get: () => '<script>' } } });
