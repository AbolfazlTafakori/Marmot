// Per-browser preferences (language, theme). Storage can be unavailable
// (private windows, blocked site data), so every access is guarded and the
// panel works without it.

const prefix = 'marmot.';

export function readPref(key: string): string | null {
  try {
    return window.localStorage.getItem(prefix + key);
  } catch {
    return null;
  }
}

export function writePref(key: string, value: string): void {
  try {
    window.localStorage.setItem(prefix + key, value);
  } catch {
    // Not remembered; the choice still applies for this visit.
  }
}
