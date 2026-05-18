import { promises as dns } from 'dns';
import ipaddr from 'ipaddr.js';
import { parseImageHost } from './trivy';

/**
 * Scan-time SSRF defense. Layered with the create-time check in
 * backend/src/lib/image-ref-guard.ts and backend/src/lib/url-guard.ts.
 *
 * Re-runs the same private-IP / loopback / IMDS / Fly 6PN block list at
 * scan time, defeating DNS rebinding between cred/configured-image creation
 * (when the host resolved to a public IP) and the actual crane / Trivy /
 * registry-auth fetch (when the same hostname could resolve to 169.254.169.254).
 */

export type HostGuardResult =
  | { valid: true; host: string; addresses: string[] }
  | { valid: false; reason: string };

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

function isIpBlocked(ip: ipaddr.IPv4 | ipaddr.IPv6): { blocked: boolean; reason?: string } {
  const range = ip.range();
  const BLOCKED_RANGES = new Set([
    'unspecified', 'broadcast', 'loopback', 'private', 'linkLocal',
    'uniqueLocal', 'carrierGradeNat', 'reserved', 'multicast',
  ]);
  if (BLOCKED_RANGES.has(range)) {
    return { blocked: true, reason: `${range} address ${ip.toString()}` };
  }
  if (ip.kind() === 'ipv4' && ip.toString() === '169.254.169.254') {
    return { blocked: true, reason: 'IMDS endpoint 169.254.169.254' };
  }
  if (ip.kind() === 'ipv6') {
    const v6 = ip as ipaddr.IPv6;
    if (v6.parts[0] === 0xfdaa) {
      return { blocked: true, reason: 'Fly 6PN address fdaa::/16' };
    }
  }
  return { blocked: false };
}

/**
 * Extract the registry host from an image reference. Delegates to the single
 * shared host parser in trivy.ts so case-normalization is consistent across
 * every call site (a near-duplicate parser here previously dropped
 * `GHCR.IO/...`).
 */
export function extractImageRefHost(rawRef: string): string {
  return parseImageHost(rawRef).host;
}

export async function validateScanTimeHost(rawHostOrRef: string, mode: 'imageRef' | 'host'): Promise<HostGuardResult> {
  const host = (mode === 'imageRef' ? extractImageRefHost(rawHostOrRef) : rawHostOrRef).toLowerCase();
  if (!host) return { valid: false, reason: 'host is empty' };

  if (BLOCKED_HOST_LITERALS.has(host)) {
    return { valid: false, reason: `host ${host} is a reserved alias` };
  }
  for (const pattern of BLOCKED_HOST_PATTERNS) {
    if (pattern.test(host)) {
      return { valid: false, reason: `host ${host} matches blocked pattern ${pattern}` };
    }
  }

  if (ipaddr.isValid(host)) {
    const ip = ipaddr.parse(host);
    const { blocked, reason } = isIpBlocked(ip);
    if (blocked) return { valid: false, reason: reason ?? 'literal IP rejected' };
    return { valid: true, host, addresses: [ip.toString()] };
  }

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
  return { valid: true, host, addresses };
}
