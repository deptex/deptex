import { NextRequest, NextResponse } from 'next/server';

// REACHABLE: open_redirect. ?to= becomes the Location header verbatim,
// so `?to=https://evil.example` redirects the victim off-site.
export async function GET(request: NextRequest) {
  const to = request.nextUrl.searchParams.get('to') ?? '/';
  return NextResponse.redirect(to);
}
