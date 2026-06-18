import { NextRequest, NextResponse } from 'next/server';

// REACHABLE: prototype_pollution. The untrusted JSON body is merged into a
// target object; a `__proto__` key poisons Object.prototype.
export async function POST(request: NextRequest) {
  const body = await request.json();
  const target: Record<string, unknown> = {};
  Object.assign(target, body);
  return NextResponse.json({ target });
}
