import type { Messages } from './messages';

export interface Format {
  num: (n: number, maxFraction?: number) => string;
  bytes: (n: number) => string;
  bits: (bps: number) => string;
  ms: (ms: number) => string;
  /** A percentage given in percent units: pct(2.5) is 2.5 %. */
  pct: (percent: number) => string;
  duration: (sec: number) => string;
  dateTime: (iso: string) => string;
  time: (iso: string) => string;
}

/**
 * Number and date formatting for a locale. Persian uses Persian digits and
 * the Persian calendar, as Iranian readers expect; English uses Latin
 * digits and the Gregorian calendar.
 */
export function makeFormat(locale: 'fa' | 'en', m: Messages): Format {
  const tag = locale === 'fa' ? 'fa-IR' : 'en-GB';
  const numFmt = (max: number) => new Intl.NumberFormat(tag, { maximumFractionDigits: max });
  const dtFmt = new Intl.DateTimeFormat(tag, { dateStyle: 'medium', timeStyle: 'short' });
  const tFmt = new Intl.DateTimeFormat(tag, { hour: '2-digit', minute: '2-digit' });
  const num = (n: number, maxFraction = 0) => numFmt(maxFraction).format(n);
  const pctFmt = new Intl.NumberFormat(tag, { style: 'percent', maximumFractionDigits: 1 });

  const scaled = (n: number, units: readonly string[], base: number) => {
    let i = 0;
    let v = n;
    while (Math.abs(v) >= base && i < units.length - 1) {
      v /= base;
      i++;
    }
    return `${num(v, i === 0 ? 0 : 1)} ${units[i] ?? ''}`;
  };

  return {
    num,
    bytes: (n) => scaled(n, m.units.bytes, 1024),
    bits: (bps) => scaled(bps, m.units.bitRate, 1000),
    ms: (v) => `${num(v, v < 10 ? 1 : 0)} ${m.units.ms}`,
    pct: (p) => pctFmt.format(p / 100),
    duration: (sec) => {
      const d = Math.floor(sec / 86400);
      const h = Math.floor((sec % 86400) / 3600);
      const min = Math.floor((sec % 3600) / 60);
      const parts: string[] = [];
      if (d) parts.push(`${num(d)} ${m.units.d}`);
      if (h || d) parts.push(`${num(h)} ${m.units.h}`);
      if (!d && (h || min)) parts.push(`${num(min)} ${m.units.m}`);
      if (!d && !h) parts.push(`${num(Math.floor(sec % 60))} ${m.units.s}`);
      return parts.join(' ');
    },
    dateTime: (iso) => dtFmt.format(new Date(iso)),
    time: (iso) => tFmt.format(new Date(iso)),
  };
}
