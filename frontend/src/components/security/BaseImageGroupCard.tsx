import type { ContainerImageGroup } from './VulnerabilityExpandableTable';

/**
 * Expanded card for the collapsed "out-of-date base image" finding. The
 * individual OS-package CVEs are noise on their own (you upgrade the image, you
 * don't patch them one by one), so the card just states the issue: which base
 * image, and how many CVEs it's behind. The upgrade recommendation lives in the
 * Scanners tab / Aegis — the finding describes the problem, not the fix.
 */
export default function BaseImageGroupCard({ group }: { group: ContainerImageGroup }) {
  return (
    <p className="text-sm text-foreground-secondary leading-relaxed">
      The <code className="text-foreground">{group.image_reference}</code> base image is out of date and
      carries <span className="text-foreground font-medium">{group.total.toLocaleString()}</span> known
      OS-package {group.total === 1 ? 'CVE' : 'CVEs'}. These come from the image, not your code — they&apos;re
      fixed by upgrading the base image, not patched one by one.
    </p>
  );
}
