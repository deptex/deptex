import { NextRequest, NextResponse } from 'next/server';
import * as http from 'http';

// REACHABLE: ssrf. ?target= is passed to http.get with no allowlist.
export async function GET(request: NextRequest) {
  const target = request.nextUrl.searchParams.get('target') ?? 'http://localhost';
  http.get(target, () => { /* ignore response */ });
  return NextResponse.json({ ok: true });
}
