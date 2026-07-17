// The task agent is a coding agent scoped to ONE cloned repo — read/edit/run/PR
// only, no Deptex platform tools. A platform question ("how many members in my
// org?") has no tool to answer it, so the prompt must steer the agent to
// REDIRECT to the main Aegis chat rather than give a bare "I can't see that".
// These pin that guidance so it isn't silently dropped, and confirm it carries
// into resume runs (where free-text follow-ups actually arrive).

import { AGENT_SYSTEM, buildResumeSystem } from '../agent/brief';

describe('agent system prompt — off-scope redirect guidance', () => {
  it('AGENT_SYSTEM tells the agent it has no org/platform data and to redirect to the main Aegis chat', () => {
    expect(AGENT_SYSTEM).toMatch(/do NOT have access to Deptex platform data/i);
    // Names the kind of thing it can't answer (so the model recognises one).
    expect(AGENT_SYSTEM).toMatch(/organization members/i);
    // The redirect target — a normal, non-task Aegis conversation.
    expect(AGENT_SYSTEM).toMatch(/normal Aegis chat/i);
    // Not a bare denial: it must explain its actual remit.
    expect(AGENT_SYSTEM).toMatch(/fix agent scoped to this repository/i);
    // A redirect is a completed answer, never a failure.
    expect(AGENT_SYSTEM).toMatch(/never "failed"/i);
  });

  it('AGENT_SYSTEM pins the committed-secret playbook: removal, never replacement', () => {
    // The PR #19 dogfood incident: the agent "fixed" a committed private key by
    // generating a NEW key and committing that — still a leaked secret, and the
    // next scan re-flags it. The rule must name removal + gitignore + rotation
    // and forbid generating replacement secrets.
    expect(AGENT_SYSTEM).toMatch(/committed secret .* fixed by REMOVAL, never replacement/i);
    expect(AGENT_SYSTEM).toMatch(/NEVER generate or commit a new secret/i);
    expect(AGENT_SYSTEM).toMatch(/\.gitignore/);
    expect(AGENT_SYSTEM).toMatch(/rotated because it remains in git history/i);
  });

  it('the guidance carries into every resume-mode system prompt (follow-ups are where these questions land)', () => {
    const variants = [
      buildResumeSystem({ prNumber: 16 }, false, 'main'), // open prior PR (amend)
      buildResumeSystem(null, true, 'main'), // prior completed, PR merged/closed
      buildResumeSystem(null, false, 'main'), // prior attempt, no standing PR
    ];
    for (const sys of variants) {
      expect(sys).toMatch(/do NOT have access to Deptex platform data/i);
      expect(sys).toMatch(/normal Aegis chat/i);
    }
  });
});
