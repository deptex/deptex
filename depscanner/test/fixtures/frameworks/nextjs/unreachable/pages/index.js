// Pure static page — no API routes, no NextResponse.redirect, no SSRF surface.
// Vulnerable next@14.0.0 is in the tree but unreachable from any handler.

export default function Home() {
  return null;
}
