import { NextRequest, NextResponse } from 'next/server';
import * as fs from 'fs';

// REACHABLE: path_traversal. ?name= is read from disk with no normalization,
// so `?name=../../etc/passwd` escapes the intended directory.
export async function GET(request: NextRequest) {
  const name = request.nextUrl.searchParams.get('name') ?? 'readme.txt';
  fs.readFileSync(`./uploads/${name}`, 'utf8');
  return NextResponse.json({ ok: true });
}
