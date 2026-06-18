import { NextRequest, NextResponse } from 'next/server';

// REACHABLE: code injection. The request body's `expr` is eval'd directly.
export async function POST(request: NextRequest) {
  const body = await request.json();
  eval(body.expr);
  return NextResponse.json({ ok: true });
}
