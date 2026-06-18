import { NextRequest, NextResponse } from 'next/server';
import _ from 'lodash';

// REACHABLE DEPENDENCY CVE: lodash@4.17.20 is vulnerable to CVE-2021-23337
// (command/code injection via _.template). The ?tpl= query param flows straight
// into _.template, which compiles it as executable code — so the engine
// confirms the lodash CVE is actually reachable from this app (not just
// "imported"), promoting it to a top-priority reachable dependency finding.
export async function GET(request: NextRequest) {
  const tpl = request.nextUrl.searchParams.get('tpl') ?? '';
  _.template(tpl);
  return NextResponse.json({ ok: true });
}
