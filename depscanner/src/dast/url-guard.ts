// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// DO NOT EDIT — synced from backend/src/lib/url-guard.ts via
//   scripts/sync-dast-openapi.ts
//
// The depscanner can't `import` from `backend/src/lib/` (separate package
// boundary in CI + Fly). This duplicate is enforced byte-identical via a CI
// step that re-runs the sync script and fails on `git diff --exit-code`.
// To change the SSRF guard, edit `backend/src/lib/url-guard.ts` and re-run
// the sync script.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

import { promises as dns } from 'dns';
import ipaddr from 'ipaddr.js';

/**
 * SSRF defense for the DAST scan target URL.
 *
 * Layered with two other checks:
 *   - queue_scan_job (plpgsql): blocks literal-IP loopback / RFC1918 / link-local
 *     / IMDS / Fly internal at the DB boundary even if the route handler is
 *     bypassed.
 *   - depscanner pipeline pre-flight: re-runs validateExternalUrl right before
 *     ZAP boots, defeating DNS-rebind between PUT /config and the actual scan.
 *
 * This module is the primary gate. It resolves the hostname (so an attacker
 * can't smuggle 127.0.0.1 via a domain) and rejects every host whose resolved
 * IP falls in a blocked class.
 */

export type UrlGuardResult =
  | { valid: true; resolved: { host: string; addresses: string[] } }
  | { valid: false; reason: string };

const ALLOWED_SCHEMES = new Set(['http:', 'https:']);

// Hostnames that should fail without DNS — internal Fly + obvious literals.
const BLOCKED_HOST_PATTERNS: RegExp[] = [
  /\.internal$/i,
  /\.fly\.dev\.internal$/i,
];

const BLOCKED_HOST_LITERALS = new Set([
  'localhost',
  'broadcasthost',
  'ip6-localhost',
  'ip6-loopback',
]);

/**
 * Block-list for resolved IPs. ipaddr.js range names cover most classes; we
 * add IMDS (169.254.169.254) and the Fly 6PN /16 (fdaa::/16) explicitly.
 */
function isIpBlocked(ip: ipaddr.IPv4 | ipaddr.IPv6): { blocked: boolean; reason?: string } {
  // IPv6 transition mechanisms tunnel an IPv4 destination inside an IPv6
  // address. The Linux kernel routes them to the underlying IPv4 host, so an
  // attacker can use `::ffff:169.254.169.254` to reach AWS IMDS — ipaddr.js
  // classifies that as range='ipv4Mapped' which is NOT in our standard set.
  // Recurse on the inner IPv4 so the existing block-list catches these.
  if (ip.kind() === 'ipv6') {
    const v6 = ip as ipaddr.IPv6;

    if (v6.isIPv4MappedAddress()) {
      const inner = v6.toIPv4Address();
      const innerResult = isIpBlocked(inner);
      if (innerResult.blocked) {
        return {
          blocked: true,
          reason: `IPv4-mapped IPv6 wraps blocked ${innerResult.reason}`,
        };
      }
      // Even when the inner IPv4 is public, mapped form has no legitimate
      // scan-target use case (operators would type the IPv4 directly).
      // Reject outright to remove the bypass surface.
      return {
        blocked: true,
        reason: `IPv4-mapped IPv6 ${ip.toString()} — use the IPv4 form instead`,
      };
    }

    // 6to4 (2002::/16) — embeds a public IPv4 in parts[1..2] high/low octets.
    // No legitimate web-app scan target uses 6to4; reject outright.
    if (v6.parts[0] === 0x2002) {
      return {
        blocked: true,
        reason: `6to4 transition address ${ip.toString()}`,
      };
    }

    // Teredo (2001::/32) — UDP-tunneled IPv4. Same rationale.
    if (v6.parts[0] === 0x2001 && v6.parts[1] === 0x0000) {
      return {
        blocked: true,
        reason: `Teredo transition address ${ip.toString()}`,
      };
    }
  }

  const range = ip.range();

  // ipaddr.js named ranges that always block
  const BLOCKED_RANGES = new Set([
    'unspecified',     // 0.0.0.0, ::
    'broadcast',       // 255.255.255.255
    'loopback',        // 127/8, ::1
    'private',         // 10/8, 172.16/12, 192.168/16
    'linkLocal',       // 169.254/16, fe80::/10
    'uniqueLocal',     // fc00::/7
    'carrierGradeNat', // 100.64/10
    'reserved',        // 240/4 etc
    'multicast',       // 224/4, ff00::/8
  ]);

  if (BLOCKED_RANGES.has(range)) {
    return { blocked: true, reason: `${range} address ${ip.toString()}` };
  }

  // IMDS (169.254.169.254) — already covered by linkLocal above, but be explicit.
  if (ip.kind() === 'ipv4' && ip.toString() === '169.254.169.254') {
    return { blocked: true, reason: 'IMDS endpoint 169.254.169.254' };
  }

  // Fly 6PN — fdaa::/16. ipaddr.js classifies this as uniqueLocal which
  // blocks above; the explicit check is documentation for the audit trail.
  if (ip.kind() === 'ipv6') {
    const v6 = ip as ipaddr.IPv6;
    const first = v6.parts[0];
    if (first === 0xfdaa) {
      return { blocked: true, reason: 'Fly 6PN address fdaa::/16' };
    }
  }

  return { blocked: false };
}

export async function validateExternalUrl(rawUrl: string): Promise<UrlGuardResult> {
  if (typeof rawUrl !== 'string' || rawUrl.length === 0) {
    return { valid: false, reason: 'target_url is empty' };
  }

  // Cap the input to a sane size before parsing.
  if (rawUrl.length > 2048) {
    return { valid: false, reason: 'target_url exceeds 2048 chars' };
  }

  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { valid: false, reason: 'target_url is not a valid URL' };
  }

  if (!ALLOWED_SCHEMES.has(parsed.protocol)) {
    return {
      valid: false,
      reason: `scheme ${parsed.protocol} not allowed (http or https only)`,
    };
  }

  // URL.hostname returns IPv6 wrapped in brackets ('[::1]'); strip them before
  // handing to ipaddr.js or DNS.
  let host = parsed.hostname.toLowerCase();
  if (host.startsWith('[') && host.endsWith(']')) {
    host = host.slice(1, -1);
  }
  if (host === '') {
    return { valid: false, reason: 'target_url missing host' };
  }

  if (BLOCKED_HOST_LITERALS.has(host)) {
    return { valid: false, reason: `host ${host} is a reserved alias` };
  }

  for (const pattern of BLOCKED_HOST_PATTERNS) {
    if (pattern.test(host)) {
      return { valid: false, reason: `host ${host} matches blocked pattern ${pattern}` };
    }
  }

  // If host is already an IP literal, validate directly without DNS.
  if (ipaddr.isValid(host)) {
    const ip = ipaddr.parse(host);
    const { blocked, reason } = isIpBlocked(ip);
    if (blocked) {
      return { valid: false, reason: reason ?? 'literal IP rejected' };
    }
    return { valid: true, resolved: { host, addresses: [ip.toString()] } };
  }

  // Otherwise resolve every A + AAAA record and reject if ANY falls in a
  // blocked class. dns.lookup returns the OS-resolved address, but we want
  // the full set so a hostname can't smuggle a single private record past us.
  let records: { address: string; family: number }[];
  try {
    records = await dns.lookup(host, { all: true, verbatim: true });
  } catch (e: any) {
    return { valid: false, reason: `DNS resolution failed: ${e?.code ?? e?.message ?? 'unknown'}` };
  }

  if (records.length === 0) {
    return { valid: false, reason: `no DNS records for ${host}` };
  }

  const addresses: string[] = [];
  for (const r of records) {
    if (!ipaddr.isValid(r.address)) {
      return { valid: false, reason: `DNS returned malformed address ${r.address}` };
    }
    const ip = ipaddr.parse(r.address);
    const { blocked, reason } = isIpBlocked(ip);
    if (blocked) {
      return { valid: false, reason: `host ${host} resolved to ${reason}` };
    }
    addresses.push(ip.toString());
  }

  return { valid: true, resolved: { host, addresses } };
}
