import { ExternalLink } from 'lucide-react';
import type { IaCHardeningGroup } from './VulnerabilityExpandableTable';
import { iacRuleInfo, checkovRuleDocUrl } from './infra-format';

/**
 * Expanded card for the collapsed "Container hardening" finding. The individual
 * k8s hardening checks (drop NET_RAW, restrict the SA token, set seccomp,
 * NetworkPolicy, resource limits…) are each a missing-control nudge with an
 * empty card on their own, so we list them here as one set: each best-practice
 * not applied, its impact, and a link to the rule. Defense-in-depth hygiene
 * (CIS/SOC2), not exploitable holes — the card states what's missing; applying
 * them is the deployment owner's / Aegis's job.
 */
export default function IaCHardeningGroupCard({ group }: { group: IaCHardeningGroup }) {
  return (
    <div className="space-y-3">
      <p className="text-sm text-foreground-secondary leading-relaxed">
        This deployment is missing <span className="text-foreground font-medium">{group.total}</span>{' '}
        defense-in-depth hardening best-practices. They map to CIS / SOC2 and shrink the blast radius of a
        compromise — worth applying, but none is an exploitable hole on its own, so they&apos;re set aside here.
      </p>
      <ul className="space-y-2">
        {group.members.map((m) => {
          const info = iacRuleInfo(m.rule_id, m.severity, m.message);
          const url = m.rule_doc_url || checkovRuleDocUrl(m.rule_id);
          return (
            <li key={m.id} className="text-xs">
              {url ? (
                <a
                  href={url}
                  target="_blank"
                  rel="noreferrer"
                  className="text-foreground font-medium hover:underline inline-flex items-center gap-1"
                  onClick={(e) => e.stopPropagation()}
                >
                  {m.message ?? m.rule_id}
                  <ExternalLink className="h-3 w-3 text-muted-foreground" />
                </a>
              ) : (
                <span className="text-foreground font-medium">{m.message ?? m.rule_id}</span>
              )}
              <div className="text-muted-foreground mt-0.5">{info.impact}</div>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
