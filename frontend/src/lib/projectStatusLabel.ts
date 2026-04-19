import type { Project } from './api';
import { isExtractionOngoing } from './extractionStatus';

/** Policy-as-code project status + extraction state for badges (Projects list, Org Compliance). */
export function projectStatusLabel(project: Project): {
  label: string;
  inProgress: boolean;
  isError: boolean;
  statusColor?: string;
} {
  const status = project.repo_status;
  if (isExtractionOngoing(status || '', project.extraction_step ?? null)) {
    const step = project.extraction_step;
    const labels: Record<string, string> = {
      queued: 'Creating',
      cloning: 'Creating',
      sbom: 'Creating',
      deps_synced: 'Creating',
      ast_parsing: 'Creating',
      scanning: 'Creating',
      uploading: 'Creating',
      completed: 'Creating',
    };
    const label = step
      ? (labels[step] ?? 'Creating')
      : status === 'analyzing' || status === 'finalizing'
        ? 'Analyzing'
        : 'Creating';
    return { label, inProgress: true, isError: false };
  }
  if (status === 'error') return { label: 'Failed', inProgress: false, isError: true };
  if (project.status_name) {
    return { label: project.status_name, inProgress: false, isError: false, statusColor: project.status_color };
  }
  return {
    label: project.is_compliant !== false ? 'COMPLIANT' : 'NOT COMPLIANT',
    inProgress: false,
    isError: false,
  };
}
