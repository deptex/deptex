import { NextRequest, NextResponse } from 'next/server';
import { redirect } from 'next/navigation';

// REACHABLE: open_redirect via next/navigation's bare redirect().
export async function GET(request: NextRequest) {
  const next = request.nextUrl.searchParams.get('next') ?? '/';
  redirect(next);
  return NextResponse.json({ ok: true });
}
