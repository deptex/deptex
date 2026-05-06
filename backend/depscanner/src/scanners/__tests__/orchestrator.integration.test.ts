import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { detectInfraTypes } from '../detect-infra';
import { IAC_FRAMEWORKS, type IaCFramework } from '../types';

const MULTI_IAC_FIXTURE = path.join(__dirname, 'fixtures', 'multi-iac-fixture');

describe('orchestrator integration — multi-iac fixture', () => {
  it('detects all nine canonical frameworks plus the kustomize-as-kubernetes alias', () => {
    const detected = detectInfraTypes(MULTI_IAC_FIXTURE);
    // Every value in IAC_FRAMEWORKS should fire at least once.
    for (const f of IAC_FRAMEWORKS) {
      expect(detected).toContain(f as IaCFramework);
    }
    // detected is a deduped set — it should match IAC_FRAMEWORKS exactly.
    expect(detected.slice().sort()).toEqual([...IAC_FRAMEWORKS].sort());
  });

  it('produces no value outside the canonical 9-element set (no rogue kustomize)', () => {
    const detected = detectInfraTypes(MULTI_IAC_FIXTURE);
    // 'kustomize' must not surface — kustomization.yaml maps to kubernetes.
    expect(detected).not.toContain('kustomize');
    for (const value of detected) {
      expect(IAC_FRAMEWORKS).toContain(value);
    }
  });

  it('returns a stable deduped + sorted list (idempotent across calls)', () => {
    const a = detectInfraTypes(MULTI_IAC_FIXTURE);
    const b = detectInfraTypes(MULTI_IAC_FIXTURE);
    expect(a).toEqual(b);
    expect(a).toEqual([...a].sort());
    expect(new Set(a).size).toBe(a.length);
  });

  it('co-detects helm + kubernetes when the chart ships templates with k8s manifests', () => {
    // The fixture's charts/web has both Chart.yaml and templates/deployment.yaml;
    // both frameworks must surface so Checkov runs both rule packs.
    const detected = detectInfraTypes(MULTI_IAC_FIXTURE);
    expect(detected).toEqual(expect.arrayContaining(['helm', 'kubernetes']));
  });

  it('classifies an ARM template with CFN-shaped keys as ARM, not cloudformation', () => {
    // The fixture's ambiguous/ JSON has both an ARM $schema and a `Resources:`
    // block with `Type: AWS::*` strings. ARM precedence is enforced because
    // the JSON branch runs the ARM sniffer first; without that, the file
    // would also fire the CFN detector and create a phantom-CFN scan target.
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'deptex-arm-cfn-'));
    fs.writeFileSync(
      path.join(tmp, 'mixed.json'),
      fs.readFileSync(
        path.join(MULTI_IAC_FIXTURE, 'ambiguous', 'arm-with-cfn-markers.json'),
        'utf8'
      )
    );
    expect(detectInfraTypes(tmp)).toEqual(['arm']);
  });
});
