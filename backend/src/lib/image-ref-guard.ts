import { promises as dns } from 'dns';
import ipaddr from 'ipaddr.js';

/**
 * SSRF defense for docker image references.
 *
 * Image refs are not URLs (`docker.io/library/nginx:1.27`), so url-guard's
 * URL parser can't be used directly. This module:
 *
 *   1. Extracts the registry host segment from a docker pull string.
 *   2. Rejects literal IPs in private / loopback / link-local / IMDS / Fly 6PN
 *      ranges, and host literals that match `*.internal` etc.
 *   3. Resolves the hostname and rejects if any A/AAAA record falls in a
 *      blocked class.
 *
 * Layered with a scan-time re-check inside the depscanner orchestrator
 * (defeats DNS rebinding between create-time and scan-time).
 */

export type ImageRefGuardResult =
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
    'unspecified',
    'broadcast',
    'loopback',
    'private',
    'linkLocal',
    'uniqueLocal',
    'carrierGradeNat',
    'reserved',
    'multicast',
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
 * Extract the registry host from an image reference. Docker reference grammar:
 *   <host[:port]>/<path>:<tag>     OR
 *   <host[:port]>/<path>@<digest>  OR
 *   <path>:<tag>                   (defaults to docker.io)
 *   <path>:<tag>@<digest>
 *
 * The host is the segment before the first `/` if and only if it contains a `.`,
 * a `:`, or equals `localhost`. Otherwise the ref is a Docker Hub short-name
 * and the canonical host is `docker.io`.
 */
export function extractImageRefHost(rawRef: string): string {
  const ref = rawRef.trim();
  const slash = ref.indexOf('/');
  if (slash === -1) return 'docker.io';
  const candidate = ref.slice(0, slash);
  if (candidate === 'localhost' || candidate.includes('.') || candidate.includes(':')) {
    // strip optional :port for host classification
    const colon = candidate.lastIndexOf(':');
    if (colon !== -1 && /^\d+$/.test(candidate.slice(colon + 1))) {
      return candidate.slice(0, colon);
    }
    return candidate;
  }
  return 'docker.io';
}

export async function validateImageRefHost(rawRef: string): Promise<ImageRefGuardResult> {
  if (typeof rawRef !== 'string' || rawRef.length === 0) {
    return { valid: false, reason: 'image_reference is empty' };
  }
  if (rawRef.length > 1024) {
    return { valid: false, reason: 'image_reference exceeds 1024 chars' };
  }

  const host = extractImageRefHost(rawRef).toLowerCase();
  if (host === '') {
    return { valid: false, reason: 'image_reference missing registry host' };
  }

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
    if (blocked) {
      return { valid: false, reason: reason ?? 'literal IP rejected' };
    }
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
