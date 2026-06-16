// Shared formatting + knowledge for IaC / container findings — the analog of
// dast-format.ts. Checkov community checks ship no severity, no long
// description, and no per-rule doc URL, so we supply that context here: a
// real impact line, whether the rule is a genuine security hole vs a hardening
// nit, a priority score with actual spread, the YAML key to highlight, and a
// doc link. Keyed by rule id, with severity-based fallbacks for unknown rules.

export interface IaCRuleInfo {
  /** The config key to highlight in the manifest (e.g. `privileged:`). Undefined
   *  when the violation is a MISSING field (nothing to point at). */
  token?: string;
  /** True = a real escape/exposure risk (kept Open). False = a hardening /
   *  hygiene best-practice that fires on nearly every manifest (auto-ignored,
   *  like passive DAST checks). */
  critical: boolean;
  /** Priority score (0-100) with real spread, so "privileged" doesn't tie with
   *  "set a CPU request". */
  score: number;
  /** One-line, plain-English "why it matters". */
  impact: string;
}

// Per-rule knowledge for the Kubernetes Checkov rules we see in practice. The
// security-critical set is intentionally narrow: rules where a DANGEROUS VALUE
// IS PRESENT in the manifest (privileged: true, host namespaces) — so they're a
// real escape/exposure risk AND there's an exact line to highlight. Everything
// else — including "missing-hardening" defense-in-depth like seccomp, dropped
// capabilities, network policy — is a best-practice nit: auto-ignored, scored
// lower, and (because the violation is an ABSENT field) has no line to flag.
const K8S_RULES: Record<string, IaCRuleInfo> = {
  // --- security-critical: a dangerous value is set, kept Open, highlightable ---
  CKV_K8S_16: { token: 'privileged:', critical: true, score: 82, impact: 'A privileged container shares the host kernel — a breakout escapes straight onto the node.' },
  CKV_K8S_20: { token: 'allowPrivilegeEscalation:', critical: true, score: 76, impact: 'allowPrivilegeEscalation lets a process gain more privileges than its parent, defeating dropped-capability hardening.' },
  CKV_K8S_23: { token: 'runAsNonRoot:', critical: true, score: 70, impact: 'Admitting containers as root means a breakout starts with full root on the node.' },
  CKV_K8S_19: { token: 'hostNetwork', critical: true, score: 72, impact: 'Sharing the host network exposes the node’s interfaces and localhost-only services to the container.' },
  CKV_K8S_17: { token: 'hostPID', critical: true, score: 70, impact: 'Sharing the host PID namespace lets the container see and signal every process on the node.' },
  CKV_K8S_18: { token: 'hostIPC', critical: true, score: 68, impact: 'Sharing the host IPC namespace breaks isolation of shared memory with the node.' },
  // hostPath host-mount — surfaced by Trivy (Checkov community misses it). The
  // worst k8s misconfig: a node directory (or `/`) mounted into the container.
  // Trivy stores the id dash-form (`KSV-0023`); cover both forms.
  'KSV-0023': { token: 'hostPath:', critical: true, score: 88, impact: 'A hostPath volume mounts a node directory into the container — mounting a sensitive path (or `/`) gives full read/write access to the host filesystem and a trivial escape onto the node.' },
  KSV023: { token: 'hostPath:', critical: true, score: 88, impact: 'A hostPath volume mounts a node directory into the container — mounting a sensitive path (or `/`) gives full read/write access to the host filesystem and a trivial escape onto the node.' },
  'AVD-KSV-0023': { token: 'hostPath:', critical: true, score: 88, impact: 'A hostPath volume mounts a node directory into the container — mounting a sensitive path (or `/`) gives full read/write access to the host filesystem and a trivial escape onto the node.' },
  // KSV-0121 — a disallowed volume type (hostPath etc.) is mounted.
  'KSV-0121': { token: 'hostPath:', critical: true, score: 80, impact: 'A disallowed volume type (such as hostPath) is mounted, exposing the node’s filesystem or devices to the container.' },
  // --- defense-in-depth / hygiene: a control is MISSING, auto-ignored ---
  // All scored in the low (grey) band: they're set-aside best-practice nudges,
  // so the number should read as low-priority, not amber "moderate". The spread
  // is kept (token theft > capabilities > resource limits) for relative
  // ordering within the set-aside tail.
  CKV_K8S_38: { critical: false, score: 36, impact: 'The service-account token is auto-mounted, handing cluster API credentials to a compromised pod.' },
  CKV_K8S_28: { critical: false, score: 34, impact: 'The container doesn’t drop the NET_RAW capability, which lets it forge packets (ARP spoofing, raw sockets).' },
  CKV_K8S_37: { critical: false, score: 33, impact: 'Linux capabilities aren’t restricted — a compromised container keeps more host privileges than it needs.' },
  CKV2_K8S_6: { critical: false, score: 34, impact: 'No NetworkPolicy is associated, so a compromised pod can reach every other pod in the cluster.' },
  CKV_K8S_31: { critical: false, score: 32, impact: 'No seccomp profile is set, so the container can issue any syscall to the host kernel.' },
  CKV_K8S_22: { critical: false, score: 31, impact: 'The root filesystem is writable, so an attacker could drop and execute new binaries at runtime.' },
  CKV_K8S_29: { critical: false, score: 30, impact: 'No securityContext is set, so the pod runs with permissive Kubernetes defaults.' },
  CKV_K8S_14: { token: 'image:', critical: false, score: 30, impact: 'A floating / `latest` image tag means the deployed image can change without review.' },
  CKV_K8S_43: { token: 'image:', critical: false, score: 28, impact: 'Pinning images by tag instead of digest lets the underlying image change without notice.' },
  CKV_K8S_40: { token: 'runAsUser', critical: false, score: 26, impact: 'Running as a low UID can collide with host users; run as a high UID (>10000).' },
  CKV_K8S_13: { critical: false, score: 24, impact: 'No memory limit — a memory leak can OOM-kill neighbouring pods on the node.' },
  CKV_K8S_11: { critical: false, score: 22, impact: 'No CPU limit — one workload can monopolise the node’s CPU.' },
  CKV_K8S_10: { critical: false, score: 20, impact: 'No CPU request — the scheduler can’t reserve CPU, risking noisy-neighbour starvation.' },
  CKV_K8S_12: { critical: false, score: 20, impact: 'No memory request — the scheduler can over-commit the node’s memory.' },
  CKV_K8S_8: { critical: false, score: 18, impact: 'No liveness probe — a wedged container keeps receiving traffic instead of being restarted.' },
  CKV_K8S_9: { critical: false, score: 18, impact: 'No readiness probe — traffic is routed to the pod before it is ready to serve.' },
  CKV_K8S_21: { token: 'namespace:', critical: false, score: 18, impact: 'Running in the default namespace weakens isolation and RBAC scoping.' },
};

/**
 * Resolve rule knowledge for an IaC finding — the per-rule entry when known,
 * else a severity-based fallback so new/unmapped rules still behave sensibly.
 */
export function iacRuleInfo(
  ruleId: string | null | undefined,
  severity: string | null | undefined,
  message: string | null | undefined,
): IaCRuleInfo {
  const hit = ruleId ? K8S_RULES[ruleId] : undefined;
  if (hit) return hit;
  const sev = (severity ?? '').toUpperCase();
  return {
    token: undefined,
    // Only HIGH/CRITICAL unmapped rules stay Open; the long tail of MEDIUM
    // hardening checks is set aside.
    critical: sev === 'HIGH' || sev === 'CRITICAL',
    score: sev === 'CRITICAL' ? 88 : sev === 'HIGH' ? 66 : sev === 'LOW' ? 28 : 44,
    impact: iacImpactLine(message),
  };
}

/** The config key to highlight in the manifest, or null. */
export function iacViolationToken(ruleId: string | null | undefined): string | null {
  return (ruleId ? K8S_RULES[ruleId]?.token : undefined) ?? null;
}

/**
 * A doc link for an IaC rule. Trivy/Aqua rules (AVD / KSV ids) have stable
 * per-rule AVD pages. Checkov community rules (CKV ids) have no per-rule public
 * page — Prisma Cloud's pages sit behind non-derivable bc-k8s-N slugs
 * (CKV_K8S_28 maps to bc-k8s-27, so the number doesn't even line up) — but the official Checkov
 * Policy Index lists every check (with its description + a link to the source
 * implementation), so we link there per IaC type rather than leaving a dead
 * plain-text rule id.
 */
export function checkovRuleDocUrl(ruleId: string | null | undefined): string | null {
  if (!ruleId) return null;
  // Trivy/Aqua rules: `AVD-KSV-0023` or the short `KSV023` both have stable AVD
  // pages (the AVD slug is the lowercased id, dashes stripped).
  if (/^AVD-/i.test(ruleId) || /^KSV/i.test(ruleId)) {
    return `https://avd.aquasec.com/misconfig/${ruleId.toLowerCase()}`;
  }
  // Checkov community rules → the canonical Policy Index for the matching IaC
  // type (the page lists the rule + links to its source check).
  if (/^CKV2?_/i.test(ruleId)) {
    if (/_K8S_/i.test(ruleId)) return 'https://www.checkov.io/5.Policy%20Index/kubernetes.html';
    if (/_DOCKER_/i.test(ruleId)) return 'https://www.checkov.io/5.Policy%20Index/dockerfile.html';
    if (/_AWS_/i.test(ruleId)) return 'https://www.checkov.io/5.Policy%20Index/terraform.html';
    return 'https://www.checkov.io/5.Policy%20Index/all.html';
  }
  return null;
}

/**
 * A concise, plain-English impact line for an IaC misconfiguration, keyed off
 * the Checkov check name when the rule isn't in the table above. Covers the
 * common hardening classes; falls back to a generic-but-honest sentence so
 * every finding has a real description, never just its file path. (Note:
 * escalation is checked before "privileged" so allowPrivilegeEscalation doesn't
 * collide with the privileged-container line.)
 */
export function iacImpactLine(message: string | null | undefined): string {
  const m = (message ?? '').toLowerCase();
  if (/escalat/.test(m)) return 'allowPrivilegeEscalation lets a process gain more privileges than its parent — defeats dropped-capability hardening.';
  if (/privileg/.test(m)) return 'A privileged container shares the host kernel — a breakout escapes straight onto the node.';
  if (/run as root|runasnonroot|as root|non-root/.test(m)) return 'Running as root means a container compromise inherits full host privileges.';
  if (/net_raw|capabilit/.test(m)) return 'Extra Linux capabilities widen what a compromised container can do to the host.';
  if (/network ?policy/.test(m)) return 'With no NetworkPolicy, a compromised pod can reach every other pod in the cluster.';
  if (/digest/.test(m)) return 'Pinning images by tag instead of digest lets the underlying image change without review.';
  if (/latest|tag/.test(m)) return 'A floating / `latest` image tag means the deployed image can change without notice.';
  if (/cpu|memory|\blimit|request/.test(m)) return 'Missing resource limits let one workload starve every other pod on the node.';
  if (/read.?only.*root|readonlyroot|read-only root/.test(m)) return 'A writable root filesystem lets an attacker drop and execute new binaries at runtime.';
  if (/seccomp|apparmor/.test(m)) return 'Without a seccomp/AppArmor profile the container can issue any syscall to the kernel.';
  if (/host ?(pid|ipc|network|path)/.test(m)) return 'Sharing a host namespace breaks the isolation boundary between the pod and the node.';
  if (/probe|liveness|readiness|health/.test(m)) return 'Missing health probes let a wedged container keep serving traffic instead of restarting.';
  if (/service ?account|automount/.test(m)) return 'Auto-mounting the service-account token hands cluster API credentials to a compromised pod.';
  if (/secret/.test(m)) return 'Secrets handled this way can leak to anyone who can read the manifest or image.';
  return 'A security misconfiguration in this infrastructure manifest — review the flagged resource below.';
}
