/** Joins class names, skipping falsy ones. */
export const cx = (...c: (string | false | null | undefined)[]) => c.filter(Boolean).join(' ');
