import { resolveDepscannerImage } from '../fly-machines';
import type { FlyMachine } from '../fly-machines';

// resolveDepscannerImage replaces the old throw-if-unset pin: deploys no longer
// need a manual FLY_DEPSCANNER_IMAGE re-pin because the image is resolved from
// the live deployment. These tests pin the resolution order so the dispatcher's
// burst path can never silently regress to `:latest`.

const machine = (id: string, image?: string): FlyMachine => ({
  id,
  name: id,
  state: 'stopped',
  region: 'ewr',
  config: image ? { image } : {},
});

describe('resolveDepscannerImage', () => {
  const ORIG = process.env.FLY_DEPSCANNER_IMAGE;
  afterEach(() => {
    if (ORIG === undefined) delete process.env.FLY_DEPSCANNER_IMAGE;
    else process.env.FLY_DEPSCANNER_IMAGE = ORIG;
  });

  it('prefers the explicit FLY_DEPSCANNER_IMAGE pin over the live machine image', async () => {
    process.env.FLY_DEPSCANNER_IMAGE = 'registry.fly.io/deptex-depscanner@sha256:pinned';
    const img = await resolveDepscannerImage([machine('m1', 'registry.fly.io/deptex-depscanner@sha256:live')]);
    expect(img).toBe('registry.fly.io/deptex-depscanner@sha256:pinned');
  });

  it('auto-resolves from a live machine image when the pin is unset (no manual re-pin needed)', async () => {
    delete process.env.FLY_DEPSCANNER_IMAGE;
    const img = await resolveDepscannerImage([
      machine('m0'), // persistent machine carrying no image (skipped)
      machine('m1', 'registry.fly.io/deptex-depscanner@sha256:live'),
    ]);
    expect(img).toBe('registry.fly.io/deptex-depscanner@sha256:live');
  });

  it('throws when the pin is unset and no machine carries an image — never gambles on :latest', async () => {
    delete process.env.FLY_DEPSCANNER_IMAGE;
    await expect(resolveDepscannerImage([])).rejects.toThrow(/Cannot resolve a depscanner image/);
  });
});
