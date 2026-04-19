import { createHash, randomBytes } from 'crypto';
import dns from 'dns';
import { promisify } from 'util';

const resolveTxt = promisify(dns.resolveTxt);

export interface OrgSSOProvider {
  id: string;
  organization_id: string;
  provider_type: string;
  sso_url: string;
  certificate: string;
  entity_id: string;
  domain: string;
}

export interface SAMLProfile {
  email: string;
  nameID: string;
  displayName?: string;
  firstName?: string;
  lastName?: string;
  groups?: string[];
}

export function createSAMLInstance(config: OrgSSOProvider) {
  const { SAML } = require('@node-saml/node-saml');
  return new SAML({
    callbackUrl: `${process.env.API_BASE_URL || `http://localhost:${process.env.PORT || 3001}`}/api/sso/callback`,
    entryPoint: config.sso_url,
    issuer: 'deptex-app',
    cert: config.certificate,
    wantAssertionsSigned: true,
    wantAuthnResponseSigned: true,
  });
}

export async function generateAuthRequest(saml: any): Promise<string> {
  return saml.getAuthorizeUrlAsync('', '', {});
}

export async function validateResponse(saml: any, body: Record<string, unknown>): Promise<SAMLProfile | null> {
  try {
    const result = await saml.validatePostResponseAsync(body);
    if (!result?.profile) return null;

    const p = result.profile;
    return {
      email: p.email || p.nameID || '',
      nameID: p.nameID || '',
      displayName: p.displayName || undefined,
      firstName: p.firstName || undefined,
      lastName: p.lastName || undefined,
      groups: p.groups || p['memberOf'] || [],
    };
  } catch {
    return null;
  }
}

export function generateDomainVerificationToken(): string {
  return randomBytes(16).toString('hex');
}

export async function verifyDomain(domain: string, expectedToken: string): Promise<boolean> {
  try {
    const records = await resolveTxt(domain);
    const flat = records.flat();
    return flat.some((txt) => txt.includes(`deptex-domain-verify=${expectedToken}`));
  } catch {
    return false;
  }
}

export function generateBypassToken(): { raw: string; hash: string } {
  const raw = randomBytes(32).toString('hex');
  const hash = createHash('sha256').update(raw).digest('hex');
  return { raw, hash };
}

export function generateSCIMToken(): { raw: string; prefix: string; hash: string } {
  const hex = randomBytes(24).toString('hex');
  const raw = `scim_${hex}`;
  const prefix = raw.substring(0, 13);
  const hash = createHash('sha256').update(raw).digest('hex');
  return { raw, prefix, hash };
}
