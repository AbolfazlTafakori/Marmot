import { makeFormat } from './format';
import { en, fa } from './messages';
import { fill } from './useI18n';

function leaves(o: unknown, prefix = ''): [string, unknown][] {
  if (typeof o !== 'object' || o === null || Array.isArray(o)) return [[prefix, o]];
  return Object.entries(o).flatMap(([k, v]) => leaves(v, prefix ? `${prefix}.${k}` : k));
}

describe('catalogs', () => {
  it('Persian covers exactly the English keys', () => {
    expect(leaves(fa).map(([k]) => k)).toEqual(leaves(en).map(([k]) => k));
  });

  const faStrings = leaves(fa).flatMap(([k, v]) =>
    Array.isArray(v) ? v.map((x: string) => [k, x] as const) : [[k, String(v)] as const],
  );

  it.each(faStrings)('%s follows Persian orthography', (_key, text) => {
    expect(text).not.toMatch(/[يك]/); // Arabic yeh/kaf instead of ی/ک
    expect(text).not.toMatch(/—/); // no em dash in Persian prose
    expect(text).not.toMatch(/[٠-٩]/); // no Arabic-Indic digits
    // A line starting with a Latin word renders left-to-right in RTL UI.
    if (/[؀-ۿ]/.test(text)) expect(text).not.toMatch(/^[A-Za-z]/);
  });
});

describe('format', () => {
  const fFa = makeFormat('fa', fa);
  const fEn = makeFormat('en', en);

  it('uses Persian digits in Persian', () => {
    expect(fFa.num(1234)).toBe('۱٬۲۳۴');
    expect(fEn.num(1234)).toBe('1,234');
  });

  it('scales bytes', () => {
    expect(fEn.bytes(0)).toBe('0 B');
    expect(fEn.bytes(1536)).toBe('1.5 KB');
    expect(fEn.bytes(5 * 1024 ** 3)).toBe('5 GB');
    expect(fFa.bytes(1024 * 1024)).toBe('۱ مگابایت');
  });

  it('formats durations and rates', () => {
    expect(fEn.duration(45)).toBe('45 s');
    expect(fEn.duration(125)).toBe('2 m 5 s');
    expect(fEn.duration(3 * 3600 + 120)).toBe('3 h 2 m');
    expect(fEn.duration(2 * 86400 + 3600)).toBe('2 d 1 h');
    expect(fEn.ms(4.25)).toBe('4.3 ms');
    expect(fEn.bits(2_500_000)).toBe('2.5 Mbit/s');
    expect(fFa.bits(2_500_000)).toBe('۲٫۵ مگابیت بر ثانیه');
    expect(fEn.pct(2.5)).toBe('2.5%');
    expect(fFa.pct(2.5)).toBe('۲٫۵٪');
  });

  it('fills placeholders', () => {
    expect(fill('peer {id} of {n}', { id: 'k1', n: 2 })).toBe('peer k1 of 2');
    expect(fill('keep {missing}', {})).toBe('keep {missing}');
  });
});
