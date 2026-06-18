import { NextRequest, NextResponse } from 'next/server';

// REACHABLE: ReDoS. ?q= is compiled into a RegExp, so a catastrophic pattern
// (or a pathological input against it) can hang the event loop.
export async function GET(request: NextRequest) {
  const q = request.nextUrl.searchParams.get('q') ?? '';
  new RegExp(q); // compiled but unused — the sink is the construction
  return NextResponse.json({ ok: true });
}
