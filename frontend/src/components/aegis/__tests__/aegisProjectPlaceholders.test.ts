import { describe, it, expect } from 'vitest';
import { splitAegisEmbedSegments } from '../aegisProjectPlaceholders';

const UUID = '5ff8b1c6-19f6-4a72-a06e-74b9ff90c4c4';

describe('splitAegisEmbedSegments', () => {
  it('parses a bare project embed', () => {
    const segs = splitAegisEmbedSegments(`Before <project>${UUID}</project> after`);
    expect(segs).toEqual([
      { type: 'text', value: 'Before ' },
      { type: 'project', id: UUID },
      { type: 'text', value: ' after' },
    ]);
  });

  it('consumes symmetric backticks wrapped around an embed (observed dogfood glitch)', () => {
    const segs = splitAegisEmbedSegments(`**Project:** \`<project>${UUID}</project>\`\n\nMore text`);
    expect(segs).toEqual([
      { type: 'text', value: '**Project:** ' },
      { type: 'project', id: UUID },
      { type: 'text', value: '\n\nMore text' },
    ]);
  });

  it('consumes symmetric bold markers around an embed', () => {
    const segs = splitAegisEmbedSegments(`See **<project>${UUID}</project>** here`);
    expect(segs).toEqual([
      { type: 'text', value: 'See ' },
      { type: 'project', id: UUID },
      { type: 'text', value: ' here' },
    ]);
  });

  it('leaves asymmetric wrappers alone (only strips matched pairs)', () => {
    const segs = splitAegisEmbedSegments(`tick \`<project>${UUID}</project> no closing`);
    expect(segs).toEqual([
      { type: 'text', value: 'tick `' },
      { type: 'project', id: UUID },
      { type: 'text', value: ' no closing' },
    ]);
  });

  it('flags invalid UUIDs as embed_invalid', () => {
    const segs = splitAegisEmbedSegments('<project>not-a-uuid</project>');
    expect(segs).toHaveLength(1);
    expect(segs[0]).toMatchObject({ type: 'embed_invalid', tag: 'project' });
  });

  it('groups adjacent member embeds into a members_group', () => {
    const a = '11111111-1111-1111-1111-111111111111';
    const b = '22222222-2222-2222-2222-222222222222';
    const segs = splitAegisEmbedSegments(`Members:\n<member>${a}</member>\n<member>${b}</member>`);
    expect(segs).toEqual([
      { type: 'text', value: 'Members:\n' },
      { type: 'members_group', ids: [a, b] },
    ]);
  });

  it('still groups members when each embed is backtick-wrapped', () => {
    const a = '11111111-1111-1111-1111-111111111111';
    const b = '22222222-2222-2222-2222-222222222222';
    const segs = splitAegisEmbedSegments(`Members: \`<member>${a}</member>\` \`<member>${b}</member>\``);
    expect(segs).toEqual([
      { type: 'text', value: 'Members: ' },
      { type: 'members_group', ids: [a, b] },
    ]);
  });
});
