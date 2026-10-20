import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { api, ApiError, call, validationOf, type Schemas } from '@/shared/api/client';
import { useAuth } from '@/shared/auth/context';
import { useI18n } from '@/shared/i18n/useI18n';
import {
  Alert,
  ApplyWarnings,
  Button,
  Card,
  CopyButton,
  ErrorMessage,
  Field,
  Loading,
  Ltr,
  PageHeader,
} from '@/shared/ui';
import { ValidationIssues } from '@/shared/ui/ValidationIssues';

const configKey = ['config'] as const;

/** Raw marmot.toml editing with validation, plus this node's identity. */
export function ConfigPage() {
  const { m } = useI18n();
  const { can } = useAuth();
  const qc = useQueryClient();
  const doc = useQuery({ queryKey: configKey, queryFn: () => call(api.GET('/config')) });
  const identity = useQuery({ queryKey: ['identity'], queryFn: () => call(api.GET('/node/identity')) });
  const [text, setText] = useState<string | null>(null);
  const [checked, setChecked] = useState<Schemas['ValidationResult'] | null>(null);
  const [warnings, setWarnings] = useState<string[] | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (doc.data && text === null) setText(doc.data.toml);
  }, [doc.data, text]);

  const validate = useMutation({
    mutationFn: (toml: string) =>
      call(api.POST('/config/validate', { body: { toml, version: doc.data?.version ?? '' } })),
    onSuccess: setChecked,
  });
  const save = useMutation({
    mutationFn: (toml: string) =>
      call(api.PUT('/config', { body: { toml, version: doc.data?.version ?? '' } })),
    onSuccess: (d) => {
      setWarnings(d.warnings ?? null);
      setSaved(true);
      setChecked(null);
      qc.setQueryData(configKey, d);
      void qc.invalidateQueries();
    },
  });
  const reloadNode = useMutation({ mutationFn: () => call(api.POST('/node/reload')) });

  const reloadFromDisk = () => {
    setText(null);
    setSaved(false);
    save.reset();
    void doc.refetch();
  };
  const conflict = save.error instanceof ApiError && save.error.status === 409;
  const writable = can('operator');

  return (
    <>
      <PageHeader title={m.config.title} />
      <div className="space-y-4">
        <Card title={m.config.identity}>
          <ErrorMessage error={identity.error} />
          {identity.data ? (
            <div className="space-y-3 text-sm">
              <Field label={m.config.publicKey}>
                <div className="flex flex-wrap items-center gap-2">
                  <Ltr wrap>{identity.data.publicKey}</Ltr>
                  <CopyButton text={identity.data.publicKey} />
                </div>
              </Field>
              <Field label={m.config.joinToken} hint={m.config.joinTokenHint}>
                <div className="flex flex-wrap items-start gap-2">
                  <code
                    dir="ltr"
                    className="block max-h-20 flex-1 overflow-y-auto rounded bg-stone-100 p-2 text-xs break-all dark:bg-stone-800"
                  >
                    {identity.data.joinToken}
                  </code>
                  <CopyButton text={identity.data.joinToken} />
                </div>
              </Field>
            </div>
          ) : (
            <Loading />
          )}
        </Card>

        <Card
          title={m.config.editor}
          actions={
            writable && (
              <>
                <Button variant="ghost" onClick={reloadFromDisk}>
                  {m.config.reload}
                </Button>
                <Button
                  variant="secondary"
                  busy={reloadNode.isPending}
                  onClick={() => {
                    reloadNode.mutate();
                  }}
                >
                  {m.config.applyFromDisk}
                </Button>
              </>
            )
          }
        >
          <div className="space-y-3">
            <ErrorMessage error={doc.error} />
            {conflict && <Alert tone="warning">{m.config.conflict}</Alert>}
            <ValidationIssues result={validationOf(save.error) ?? validationOf(reloadNode.error)} />
            {!conflict && !validationOf(save.error) && <ErrorMessage error={save.error} />}
            <ApplyWarnings warnings={warnings} />
            {saved && !warnings?.length && <Alert tone="success">{m.common.saved}</Alert>}
            {checked?.valid && checked.issues.length === 0 && <Alert tone="success">{m.config.valid}</Alert>}
            <ValidationIssues result={checked} />
            {text === null ? (
              <Loading />
            ) : (
              <textarea
                dir="ltr"
                spellCheck={false}
                readOnly={!writable}
                aria-label={m.config.editor}
                rows={24}
                value={text}
                onChange={(e) => {
                  setText(e.target.value);
                  setSaved(false);
                }}
                className="w-full rounded-md border border-stone-300 bg-stone-50 p-3 font-mono text-xs leading-relaxed dark:border-stone-700 dark:bg-stone-950"
              />
            )}
            {writable && text !== null && (
              <div className="flex gap-2">
                <Button
                  variant="secondary"
                  busy={validate.isPending}
                  onClick={() => {
                    validate.mutate(text);
                  }}
                >
                  {m.config.validate}
                </Button>
                <Button
                  busy={save.isPending}
                  onClick={() => {
                    save.mutate(text);
                  }}
                >
                  {m.common.save}
                </Button>
              </div>
            )}
          </div>
        </Card>
      </div>
    </>
  );
}
