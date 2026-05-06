/**
 * severityForMaintainerSignal calibration tests.
 *
 * Walks the full ladder critical → null and asserts the highest-matching rule wins.
 */
import { severityForMaintainerSignal } from '../malicious/severity';
import type { MaintainerSignals } from '../malicious/maintainer-signals';

const QUIET: MaintainerSignals = {
  account_age_days: 1000,
  install_script_present: false,
  email_changed_in_last_30d: false,
  maintainer_changed_in_last_30d: false,
  signing_setup_changed: false,
  new_postinstall_added: false,
};

describe('severityForMaintainerSignal — critical', () => {
  it('new account + install hook = critical (Shai-Hulud-class)', () => {
    const f = severityForMaintainerSignal({
      ...QUIET,
      account_age_days: 5,
      install_script_present: true,
    });
    expect(f?.severity).toBe('critical');
    expect(f?.rule_id).toBe('maintainer:new_account_with_install_script');
  });

  it('email changed + new postinstall added = critical (account-takeover)', () => {
    const f = severityForMaintainerSignal({
      ...QUIET,
      email_changed_in_last_30d: true,
      new_postinstall_added: true,
      install_script_present: true,
    });
    expect(f?.severity).toBe('critical');
    expect(f?.rule_id).toBe('maintainer:email_changed_with_new_postinstall');
  });

  it('maintainer changed + new postinstall added = critical (ownership-transfer)', () => {
    const f = severityForMaintainerSignal({
      ...QUIET,
      maintainer_changed_in_last_30d: true,
      new_postinstall_added: true,
      install_script_present: true,
    });
    expect(f?.severity).toBe('critical');
    expect(f?.rule_id).toBe('maintainer:maintainer_changed_with_new_postinstall');
  });
});

describe('severityForMaintainerSignal — high', () => {
  it('new postinstall added (alone, established package) = high', () => {
    const f = severityForMaintainerSignal({
      ...QUIET,
      new_postinstall_added: true,
      install_script_present: true,
    });
    expect(f?.severity).toBe('high');
    expect(f?.rule_id).toBe('maintainer:new_postinstall_added');
  });

  it('signing setup changed (alone) = high', () => {
    const f = severityForMaintainerSignal({
      ...QUIET,
      signing_setup_changed: true,
    });
    expect(f?.severity).toBe('high');
    expect(f?.rule_id).toBe('maintainer:signing_setup_changed');
  });
});

describe('severityForMaintainerSignal — medium', () => {
  it('email changed alone = medium', () => {
    const f = severityForMaintainerSignal({
      ...QUIET,
      email_changed_in_last_30d: true,
    });
    expect(f?.severity).toBe('medium');
    expect(f?.rule_id).toBe('maintainer:email_changed');
  });

  it('maintainer changed alone = medium', () => {
    const f = severityForMaintainerSignal({
      ...QUIET,
      maintainer_changed_in_last_30d: true,
    });
    expect(f?.severity).toBe('medium');
    expect(f?.rule_id).toBe('maintainer:maintainer_changed');
  });

  it('new account alone (no install hook) = medium', () => {
    const f = severityForMaintainerSignal({
      ...QUIET,
      account_age_days: 5,
      install_script_present: false,
    });
    expect(f?.severity).toBe('medium');
    expect(f?.rule_id).toBe('maintainer:new_account');
  });
});

describe('severityForMaintainerSignal — null', () => {
  it('returns null when no signal is interesting', () => {
    expect(severityForMaintainerSignal(QUIET)).toBeNull();
  });

  it('returns null on missing account_age (and no other signals)', () => {
    expect(severityForMaintainerSignal({ ...QUIET, account_age_days: null })).toBeNull();
  });
});

describe('severityForMaintainerSignal — narrative is injection-clean', () => {
  it('messages do not include registry-supplied strings (no template substitution from signals)', () => {
    const f = severityForMaintainerSignal({
      ...QUIET,
      email_changed_in_last_30d: true,
      new_postinstall_added: true,
      install_script_present: true,
    });
    expect(f).not.toBeNull();
    // Message should not contain any of the registry-controlled signal field names
    // (those are diagnostic labels exposed via `signals`, not template substitutions).
    expect(f?.message).not.toContain('@');
    expect(f?.message).not.toContain('IGNORE PREVIOUS');
  });
});
