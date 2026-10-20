import { useMutation, useQueryClient } from '@tanstack/react-query';
import QRCode from 'qrcode';
import { useEffect, useState, type FormEvent } from 'react';
import { api, call } from '@/shared/api/client';
import { meKey, useAuth } from '@/shared/auth/context';
import { useI18n } from '@/shared/i18n/useI18n';
import { useTheme, type ThemeChoice } from '@/shared/theme';
import { Alert, Button, Card, ErrorMessage, Field, Input, PageHeader, Select } from '@/shared/ui';

export function SettingsPage() {
  const { m, locale, setLocale } = useI18n();
  const [theme, setTheme] = useTheme();
  const { me } = useAuth();
  const qc = useQueryClient();
  const logout = useMutation({
    mutationFn: () => call(api.POST('/auth/logout')),
    onSettled: () => {
      qc.clear();
      qc.setQueryData(meKey, null);
    },
  });

  return (
    <>
      <PageHeader title={m.settings.title} />
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title={m.settings.language}>
          <div className="space-y-3">
            <Field label={m.settings.language}>
              <Select
                value={locale}
                onChange={(e) => {
                  setLocale(e.target.value === 'en' ? 'en' : 'fa');
                }}
              >
                <option value="fa">فارسی</option>
                <option value="en">English</option>
              </Select>
            </Field>
            <Field label={m.settings.theme}>
              <Select
                value={theme}
                onChange={(e) => {
                  setTheme(e.target.value as ThemeChoice);
                }}
              >
                {(['system', 'light', 'dark'] as const).map((t) => (
                  <option key={t} value={t}>
                    {m.settings.themes[t]}
                  </option>
                ))}
              </Select>
            </Field>
            <Button
              variant="secondary"
              busy={logout.isPending}
              onClick={() => {
                logout.mutate();
              }}
            >
              {m.nav.logout}
            </Button>
          </div>
        </Card>
        {me && <TwoFactor enabled={me.totpEnabled} />}
      </div>
    </>
  );
}

/** TOTP enrolment: start (QR code), confirm with a code; or turn off. */
function TwoFactor({ enabled }: { enabled: boolean }) {
  const { m } = useI18n();
  const qc = useQueryClient();
  const [uri, setUri] = useState<string | null>(null);
  const [qr, setQr] = useState<string | null>(null);
  const [code, setCode] = useState('');

  useEffect(() => {
    if (!uri) {
      setQr(null);
      return;
    }
    void QRCode.toDataURL(uri, { margin: 1, width: 200 }).then(setQr);
  }, [uri]);

  const refreshMe = () => qc.invalidateQueries({ queryKey: meKey });
  const start = useMutation({
    mutationFn: () => call(api.POST('/auth/totp')),
    onSuccess: (r) => {
      setUri(r.uri);
    },
  });
  const confirm = useMutation({
    mutationFn: () => call(api.PUT('/auth/totp', { body: { code } })),
    onSuccess: () => {
      setUri(null);
      setCode('');
      void refreshMe();
    },
  });
  const disable = useMutation({
    mutationFn: () => call(api.DELETE('/auth/totp', { params: { query: { code } } })),
    onSuccess: () => {
      setCode('');
      void refreshMe();
    },
  });

  const codeInput = (
    <Field label={m.settings.code}>
      <Input
        ltr
        inputMode="numeric"
        autoComplete="one-time-code"
        pattern="[0-9]{6}"
        maxLength={6}
        required
        className="max-w-32"
        value={code}
        onChange={(e) => {
          setCode(e.target.value.replace(/\D/g, ''));
        }}
      />
    </Field>
  );
  const submit = (fn: () => void) => (e: FormEvent) => {
    e.preventDefault();
    fn();
  };

  return (
    <Card title={m.settings.twoFactor}>
      <div className="space-y-3 text-sm">
        <Alert tone={enabled ? 'success' : 'warning'}>
          {enabled ? m.settings.twoFactorOn : m.settings.twoFactorOff}
        </Alert>
        <ErrorMessage error={start.error ?? confirm.error ?? disable.error} />
        {enabled ? (
          <form
            onSubmit={submit(() => {
              disable.mutate();
            })}
            className="space-y-3"
          >
            {codeInput}
            <Button type="submit" variant="danger" busy={disable.isPending}>
              {m.settings.disable}
            </Button>
          </form>
        ) : uri ? (
          <form
            onSubmit={submit(() => {
              confirm.mutate();
            })}
            className="space-y-3"
          >
            <p>{m.settings.scan}</p>
            {qr && <img src={qr} alt="" width={200} height={200} className="rounded bg-white p-1" />}
            {codeInput}
            <Button type="submit" busy={confirm.isPending}>
              {m.settings.confirm}
            </Button>
          </form>
        ) : (
          <Button
            busy={start.isPending}
            onClick={() => {
              start.mutate();
            }}
          >
            {m.settings.enable}
          </Button>
        )}
      </div>
    </Card>
  );
}
