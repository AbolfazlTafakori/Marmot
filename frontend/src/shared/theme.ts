import { useSyncExternalStore } from 'react';
import { readPref, writePref } from './prefs';

export type ThemeChoice = 'system' | 'light' | 'dark';

// One shared store, so every component sees the same choice and only one
// listener follows the OS setting.
let choice: ThemeChoice = initial();
const listeners = new Set<() => void>();

function initial(): ThemeChoice {
  const v = readPref('theme');
  return v === 'light' || v === 'dark' ? v : 'system';
}

function systemDark(): boolean {
  return typeof window.matchMedia === 'function' && window.matchMedia('(prefers-color-scheme: dark)').matches;
}

function apply(): void {
  const dark = choice === 'dark' || (choice === 'system' && systemDark());
  document.documentElement.dataset.theme = dark ? 'dark' : 'light';
}

if (typeof window.matchMedia === 'function') {
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
    if (choice === 'system') apply();
  });
}

export function setTheme(c: ThemeChoice): void {
  choice = c;
  writePref('theme', c);
  apply();
  listeners.forEach((l) => {
    l();
  });
}

function subscribe(l: () => void): () => void {
  listeners.add(l);
  return () => listeners.delete(l);
}

/** The light/dark choice; "system" follows the OS and its later changes. */
export function useTheme(): [ThemeChoice, (c: ThemeChoice) => void] {
  return [useSyncExternalStore(subscribe, () => choice), setTheme];
}
