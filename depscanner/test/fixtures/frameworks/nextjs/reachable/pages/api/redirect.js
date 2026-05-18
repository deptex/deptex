// CVE-2024-21505 — next 14.x SSRF via redirect responses leaking internal state.
// API route handler reads user-supplied URL and issues redirect through next/server.

import { NextResponse } from 'next/server';

export default function handler(req, res) {
  const target = req.query.to;
  // Sink: redirect to user-controlled URL via next/server's NextResponse.
  return NextResponse.redirect(target);
}
