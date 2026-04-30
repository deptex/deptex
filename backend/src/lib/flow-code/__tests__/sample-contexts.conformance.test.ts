import { EVENT_SCHEMAS, EVENT_TYPES } from '../event-schemas';
import { SAMPLE_CONTEXTS, findSchemaViolations } from '../sample-contexts';

describe('sample-contexts conformance', () => {
  it('every event type in EVENT_SCHEMAS has a sample context', () => {
    const missing = EVENT_TYPES.filter((t) => !(t in SAMPLE_CONTEXTS));
    expect(missing).toEqual([]);
  });

  it('no orphan sample contexts (every sample maps to a known schema)', () => {
    const orphans = Object.keys(SAMPLE_CONTEXTS).filter((t) => !(t in EVENT_SCHEMAS));
    expect(orphans).toEqual([]);
  });

  // One per-schema test so failures call out which event type drifted.
  for (const eventType of EVENT_TYPES) {
    it(`sample for "${eventType}" satisfies its schema`, () => {
      const sample = SAMPLE_CONTEXTS[eventType];
      const schema = EVENT_SCHEMAS[eventType];
      expect(sample).toBeDefined();
      expect(schema).toBeDefined();
      const violations = findSchemaViolations(sample, schema.fields);
      expect(violations).toEqual([]);
    });
  }
});
