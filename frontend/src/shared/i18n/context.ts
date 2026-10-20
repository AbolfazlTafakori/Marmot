import { createContext } from 'react';
import type { Format } from './format';
import type { Messages } from './messages';

export type Locale = 'fa' | 'en';

export interface I18n {
  locale: Locale;
  m: Messages;
  f: Format;
  setLocale: (l: Locale) => void;
}

export const I18nContext = createContext<I18n | null>(null);
