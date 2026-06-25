/**
 * HeroFindingsTable — the REAL findings table, embedded (founder 2026-06-17).
 *
 * Mounts the actual <VulnerabilityExpandableTable> — the component the org
 * Findings page renders — fed the shared heroDemo findings (org-wide, mixed
 * types across projects), so it matches the app and inherits future changes.
 * Click-to-expand works via the table's `fetchDetail` DI prop (heroFindingDetail):
 * reachable vulns carry a real Source→Sink trace, unreachable ones resolve to the
 * auto-ignored status, and secret / SAST / IaC / container rows expand purely
 * from their row data. `hideRefineToggle` keeps the auto-ignored rows visible
 * (dimmed) without the Open/All toggle. See [[feedback_landing_use_real_components]].
 */
import VulnerabilityExpandableTable from "../security/VulnerabilityExpandableTable";
import { HERO_ORG_ID, heroFindings, heroFindingDetail, heroTrackerLinks } from "./heroDemo";

export default function HeroFindingsTable() {
  return (
    <div className="custom-scrollbar h-full overflow-y-auto px-4 py-4">
      <VulnerabilityExpandableTable
        organizationId={HERO_ORG_ID}
        rows={heroFindings}
        canManageFindings={false}
        demo
        trackerLinks={heroTrackerLinks}
        fetchDetail={heroFindingDetail}
        hideRefineToggle
        hideTypeFilter
      />
    </div>
  );
}
