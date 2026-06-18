import { NextRequest, NextResponse } from 'next/server';
import { db } from '../../lib/db';

// REACHABLE: sql_injection. ?id= is concatenated straight into SQL.
export async function GET(request: NextRequest) {
  const id = request.nextUrl.searchParams.get('id') ?? '';
  const rows = db.query(`SELECT * FROM users WHERE id = '${id}'`);
  return NextResponse.json({ rows });
}
