import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import { I18nContext, type I18n, type Locale } from './context';
import { makeFormat } from './format';
import { en, fa, type Messages } from './messages';
import { readPref, writePref } from '../prefs';

const catalogs: Record<Locale, Messages> = { en, fa };

/** Persian is the default; the choice is remembered per browser. */
export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(() => (readPref('locale') === 'en' ? 'en' : 'fa'));

  useEffect(() => {
    const root = document.documentElement;
    root.lang = locale;
    root.dir = locale === 'fa' ? 'rtl' : 'ltr';
  }, [locale]);

  const setLocale = useCallback((l: Locale) => {
    writePref('locale', l);
    setLocaleState(l);
  }, []);

  const value = useMemo<I18n>(
    () => ({ locale, m: catalogs[locale], f: makeFormat(locale, catalogs[locale]), setLocale }),
    [locale, setLocale],
  );
  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}
