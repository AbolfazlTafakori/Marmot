import {
  cloneElement,
  isValidElement,
  useId,
  useState,
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
} from 'react';
import { ApiError } from '../api/client';
import { useI18n } from '../i18n/useI18n';
import { cx } from './cx';

type Variant = 'primary' | 'secondary' | 'danger' | 'ghost';
const variants: Record<Variant, string> = {
  primary: 'bg-sky-700 text-white hover:bg-sky-800 disabled:bg-sky-700/50',
  secondary:
    'border border-stone-300 bg-white text-stone-800 hover:bg-stone-100 dark:border-stone-700 dark:bg-stone-900 dark:text-stone-100 dark:hover:bg-stone-800',
  danger: 'bg-red-700 text-white hover:bg-red-800 disabled:bg-red-700/50',
  ghost: 'text-stone-700 hover:bg-stone-200/70 dark:text-stone-300 dark:hover:bg-stone-800',
};

export function Button({
  variant = 'primary',
  busy,
  className,
  children,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; busy?: boolean }) {
  return (
    <button
      type="button"
      {...rest}
      disabled={rest.disabled ?? busy}
      className={cx(
        'inline-flex items-center justify-center gap-2 rounded-md px-3.5 py-1.5 text-sm font-medium transition-colors disabled:cursor-not-allowed',
        variants[variant],
        className,
      )}
    >
      {busy && <Spinner small />}
      {children}
    </button>
  );
}

export function Spinner({ small }: { small?: boolean }) {
  return (
    <span
      aria-hidden
      className={cx(
        'inline-block animate-spin rounded-full border-2 border-current border-e-transparent',
        small ? 'size-3.5' : 'size-5',
      )}
    />
  );
}

export function Loading() {
  const { m } = useI18n();
  return (
    <p className="flex items-center gap-2 py-6 text-sm text-stone-500" role="status">
      <Spinner /> {m.common.loading}
    </p>
  );
}

export function Card({
  title,
  actions,
  children,
  className,
}: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section
      className={cx(
        'min-w-0 rounded-lg border border-stone-200 bg-white p-4 dark:border-stone-800 dark:bg-stone-900',
        className,
      )}
    >
      {(title ?? actions) && (
        <header className="mb-3 flex flex-wrap items-center justify-between gap-2">
          {title && <h2 className="text-base font-semibold">{title}</h2>}
          {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  );
}

export function PageHeader({ title, actions }: { title: string; actions?: ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
      <h1 className="text-xl font-bold">{title}</h1>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </div>
  );
}

const fieldBase =
  'w-full rounded-md border border-stone-300 bg-white px-2.5 py-1.5 text-sm text-stone-900 placeholder:text-stone-400 focus:border-sky-600 focus:outline-none dark:border-stone-700 dark:bg-stone-950 dark:text-stone-100';

/**
 * A labelled control. The hint is linked with aria-describedby rather than
 * placed inside the label, so the control's accessible name stays short.
 */
export function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  const hintId = useId();
  const control =
    hint && isValidElement<{ 'aria-describedby'?: string }>(children)
      ? cloneElement(children, { 'aria-describedby': hintId })
      : children;
  return (
    <div>
      <label className="block">
        <span className="mb-1 block text-sm font-medium">{label}</span>
        {control}
      </label>
      {hint && (
        <p id={hintId} className="mt-1 text-xs text-stone-500">
          {hint}
        </p>
      )}
    </div>
  );
}

/** A text input; ltr for addresses, ports, keys and codes. */
export function Input({
  ltr,
  className,
  ...rest
}: InputHTMLAttributes<HTMLInputElement> & { ltr?: boolean }) {
  return (
    <input
      {...rest}
      dir={ltr ? 'ltr' : undefined}
      className={cx(fieldBase, ltr && 'text-start font-mono', className)}
    />
  );
}

export function Select({ className, ...rest }: SelectHTMLAttributes<HTMLSelectElement>) {
  return <select {...rest} className={cx(fieldBase, className)} />;
}

/**
 * Inline Latin content (IP, port, key) isolated from the RTL flow.
 * Identifiers stay on one line; with wrap, long lists may break.
 */
export function Ltr({
  children,
  mono = true,
  wrap = false,
}: {
  children: ReactNode;
  mono?: boolean;
  wrap?: boolean;
}) {
  return (
    <bdi className={cx('ltr', wrap ? 'break-all' : 'whitespace-nowrap', mono && 'font-mono text-[0.92em]')}>
      {children}
    </bdi>
  );
}

type Tone = 'good' | 'warn' | 'bad' | 'neutral';
const tones: Record<Tone, string> = {
  good: 'bg-emerald-50 text-emerald-800 ring-emerald-600/30 dark:bg-emerald-950 dark:text-emerald-300',
  warn: 'bg-amber-50 text-amber-800 ring-amber-600/30 dark:bg-amber-950 dark:text-amber-300',
  bad: 'bg-red-50 text-red-800 ring-red-600/30 dark:bg-red-950 dark:text-red-300',
  neutral: 'bg-stone-100 text-stone-700 ring-stone-500/30 dark:bg-stone-800 dark:text-stone-300',
};
const dots: Record<Tone, string> = {
  good: 'bg-emerald-600',
  warn: 'bg-amber-500',
  bad: 'bg-red-600',
  neutral: 'bg-stone-400',
};

/** A state with a text label; the colour is never the only signal. */
export function Badge({ tone, children }: { tone: Tone; children: ReactNode }) {
  return (
    <span
      className={cx(
        'inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset',
        tones[tone],
      )}
    >
      <span aria-hidden className={cx('size-1.5 rounded-full', dots[tone])} />
      {children}
    </span>
  );
}

export function Alert({ tone, children }: { tone: 'error' | 'warning' | 'success'; children: ReactNode }) {
  const style = {
    error: 'border-red-300 bg-red-50 text-red-900 dark:border-red-900 dark:bg-red-950 dark:text-red-200',
    warning:
      'border-amber-300 bg-amber-50 text-amber-900 dark:border-amber-900 dark:bg-amber-950 dark:text-amber-200',
    success:
      'border-emerald-300 bg-emerald-50 text-emerald-900 dark:border-emerald-900 dark:bg-emerald-950 dark:text-emerald-200',
  }[tone];
  return (
    <div
      role={tone === 'error' ? 'alert' : 'status'}
      className={cx('rounded-md border px-3 py-2 text-sm', style)}
    >
      {children}
    </div>
  );
}

/** Shows an API error in the interface language when its code is known. */
export function ErrorMessage({ error }: { error: unknown }) {
  const { m } = useI18n();
  if (!error) return null;
  const known = m.errors as Record<string, string>;
  let text = m.common.error;
  if (error instanceof ApiError) text = known[error.code] ?? error.message;
  else if (error instanceof Error) text = error.message;
  return <Alert tone="error">{text}</Alert>;
}

export function Table({
  head,
  children,
  empty,
}: {
  head: ReactNode[];
  children: ReactNode;
  empty?: boolean;
}) {
  const { m } = useI18n();
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-stone-200 text-start text-xs text-stone-500 dark:border-stone-800">
            {head.map((h, i) => (
              <th key={i} scope="col" className="px-2 py-2 text-start font-medium whitespace-nowrap">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-stone-100 dark:divide-stone-800">
          {empty ? (
            <tr>
              <td colSpan={head.length} className="px-2 py-6 text-center text-stone-500">
                {m.common.none}
              </td>
            </tr>
          ) : (
            children
          )}
        </tbody>
      </table>
    </div>
  );
}

export function Td({ children, className }: { children?: ReactNode; className?: string }) {
  return <td className={cx('px-2 py-2 align-middle', className)}>{children}</td>;
}

export function CopyButton({ text }: { text: string }) {
  const { m } = useI18n();
  const [done, setDone] = useState(false);
  return (
    <Button
      variant="secondary"
      onClick={() => {
        void navigator.clipboard.writeText(text).then(() => {
          setDone(true);
          window.setTimeout(() => {
            setDone(false);
          }, 1500);
        });
      }}
    >
      {done ? m.common.copied : m.common.copy}
    </Button>
  );
}

/** Saved-with-warnings notice for ApplyWarnings. */
export function ApplyWarnings({ warnings }: { warnings?: string[] | null }) {
  const { m } = useI18n();
  if (!warnings?.length) return null;
  return (
    <Alert tone="warning">
      <p>{m.common.warnings}</p>
      <ul className="mt-1 list-disc ps-5">
        {warnings.map((w) => (
          <li key={w}>
            <Ltr mono={false}>{w}</Ltr>
          </li>
        ))}
      </ul>
    </Alert>
  );
}
