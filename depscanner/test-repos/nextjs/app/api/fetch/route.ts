import { NextRequest, NextResponse } from 'next/server';

// REACHABLE: ssrf. ?url= is fetched server-side, so an attacker can pivot to
// internal services (169.254.169.254, localhost, etc.).
export async function GET(request: NextRequest) {
  const url = request.nextUrl.searchParams.get('url') ?? 'https://example.com';
  await fetch(url);
  return NextResponse.json({ ok: true });
}
