import { NextRequest, NextResponse } from 'next/server';
import * as child_process from 'child_process';

// REACHABLE: command_injection. ?host= flows unsanitized into a shell command.
export async function GET(request: NextRequest) {
  const host = request.nextUrl.searchParams.get('host') ?? 'localhost';
  const out = child_process.execSync(`ping -c 1 ${host}`).toString();
  return NextResponse.json({ out });
}
