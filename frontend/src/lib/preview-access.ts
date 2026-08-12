// Pre-launch curtain for the login screen.
//
// Deptex isn't ready for strangers yet: the app behind sign-in is mid-build, so
// anyone curious who signs up sees a broken product. Until launch the login
// screen shows a construction notice instead of the OAuth buttons.
//
// This is a curtain, not a lock. Sign-up is a direct browser->Supabase Auth
// call, so anything enforced here is client-side and bypassable by someone
// determined. That's fine — it exists to stop casual visitors from wandering
// into an unfinished app, not to withstand attack.
//
// Getting in: visit /login?access=deptex-preview once. The grant is remembered
// in localStorage, so it survives reloads and later visits to a bare /login.
// Visiting /login?access=anything-else revokes it again (handy for checking the
// notice renders, and for handing a browser back to its owner).
//
// An existing signed-in session is unaffected either way: PublicRoute sends
// authenticated users straight to /organizations without rendering /login.

const STORAGE_KEY = 'deptex_preview_access';
const ACCESS_KEY = 'deptex-preview';

/**
 * Resolve whether this browser may see the real sign-in buttons.
 * Pass `window.location.search`; call once on mount (it has a write side effect).
 */
export function resolvePreviewAccess(search: string): boolean {
  let requested: string | null = null;
  try {
    requested = new URLSearchParams(search).get('access');
  } catch {
    requested = null;
  }

  if (requested === ACCESS_KEY) {
    writeGrant(true);
    return true;
  }
  if (requested !== null) {
    // An explicit wrong key revokes a previous grant.
    writeGrant(false);
    return false;
  }

  try {
    return localStorage.getItem(STORAGE_KEY) === '1';
  } catch {
    // Private mode / storage disabled: fall back to showing the notice.
    return false;
  }
}

function writeGrant(granted: boolean): void {
  try {
    if (granted) localStorage.setItem(STORAGE_KEY, '1');
    else localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Storage unavailable — the caller still gets the right answer for this page view.
  }
}
