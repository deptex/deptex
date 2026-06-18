import { NextRequest, NextResponse } from 'next/server';
import * as vm from 'vm';

// REACHABLE: code injection. ?code= is executed in a vm context — vm is NOT a
// security boundary, so this is RCE.
export async function GET(request: NextRequest) {
  const code = request.nextUrl.searchParams.get('code') ?? '1+1';
  vm.runInNewContext(code);
  return NextResponse.json({ ok: true });
}
