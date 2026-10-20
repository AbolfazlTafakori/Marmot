import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';
import { api, ApiError, call } from '@/shared/api/client';
import { meKey } from '@/shared/auth/context';
import { useI18n } from '@/shared/i18n/useI18n';
import { Button, ErrorMessage, Field, Input } from '@/shared/ui';

export function LoginPage() {
  const { m, locale, setLocale } = useI18n();
  const qc = useQueryClient();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [totp, setTotp] = useState('');
  const [needTotp, setNeedTotp] = useState(false);

  const login = useMutation({
    mutationFn: () =>
      call(api.POST('/auth/login', { body: { username, password, ...(needTotp && totp ? { totp } : {}) } })),
    onSuccess: (me) => {
      qc.setQueryData(meKey, me);
    },
    onError: (e) => {
      if (e instanceof ApiError && e.code === 'totp_required') setNeedTotp(true);
    },
  });

  const submit = (e: FormEvent) => {
    e.preventDefault();
    login.mutate();
  };
  // Asking for the code is a step, not a failure; do not show it as an error.
  const shownError =
    login.error instanceof ApiError && login.error.code === 'totp_required' ? null : login.error;

  return (
    <div className="grid min-h-dvh place-items-center p-4">
      <form
        onSubmit={submit}
        className="w-full max-w-sm space-y-4 rounded-lg border border-stone-200 bg-white p-6 shadow-sm dark:border-stone-800 dark:bg-stone-900"
      >
        <div>
          <p className="text-2xl font-bold">{m.app.name}</p>
          <h1 className="text-sm text-stone-500">{m.login.title}</h1>
        </div>
        <Field label={m.login.username}>
          <Input
            ltr
            autoComplete="username"
            required
            autoFocus
            value={username}
            onChange={(e) => {
              setUsername(e.target.value);
            }}
          />
        </Field>
        <Field label={m.login.password}>
          <Input
            ltr
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => {
              setPassword(e.target.value);
            }}
          />
        </Field>
        {needTotp && (
          <Field label={m.login.totp} hint={m.login.totpHint}>
            <Input
              ltr
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="[0-9]{6}"
              maxLength={6}
              required
              autoFocus
              value={totp}
              onChange={(e) => {
                setTotp(e.target.value.replace(/\D/g, ''));
              }}
            />
          </Field>
        )}
        <ErrorMessage error={shownError} />
        <Button type="submit" className="w-full" busy={login.isPending}>
          {m.login.submit}
        </Button>
        <button
          type="button"
          className="block w-full text-center text-xs text-stone-500 underline-offset-2 hover:underline"
          onClick={() => {
            setLocale(locale === 'fa' ? 'en' : 'fa');
          }}
        >
          {locale === 'fa' ? 'English' : 'فارسی'}
        </button>
      </form>
    </div>
  );
}
