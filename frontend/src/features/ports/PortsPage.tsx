import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { api, call, validationOf, type Schemas } from '@/shared/api/client';
import { useAuth } from '@/shared/auth/context';
import { useI18n } from '@/shared/i18n/useI18n';
import {
  Alert,
  ApplyWarnings,
  Button,
  Card,
  ErrorMessage,
  Input,
  Loading,
  PageHeader,
  Select,
  Td,
  Table,
} from '@/shared/ui';
import { ValidationIssues } from '@/shared/ui/ValidationIssues';

type Rule = Schemas['PortRule'];
type Proto = Rule['protocols'][number];

interface Draft {
  port: string;
  class: Rule['class'];
  tcp: boolean;
  udp: boolean;
  targetPort: string;
}

const toDraft = (r: Rule): Draft => ({
  port: String(r.port),
  class: r.class,
  tcp: r.protocols.includes('tcp'),
  udp: r.protocols.includes('udp'),
  targetPort: r.targetPort && r.targetPort !== r.port ? String(r.targetPort) : '',
});

const toRule = (d: Draft): Rule => {
  const protocols: Proto[] = [];
  if (d.tcp) protocols.push('tcp');
  if (d.udp) protocols.push('udp');
  const port = Number(d.port);
  return { port, class: d.class, protocols, ...(d.targetPort ? { targetPort: Number(d.targetPort) } : {}) };
};

const steeringKey = ['steering'] as const;

/** The user-facing ports Marmot carries. Unlisted ports are never touched. */
export function PortsPage() {
  const { m } = useI18n();
  const { can } = useAuth();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: steeringKey, queryFn: () => call(api.GET('/steering')) });
  const [drafts, setDrafts] = useState<Draft[] | null>(null);
  const [warnings, setWarnings] = useState<string[] | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (q.data && drafts === null) setDrafts(q.data.ports.map(toDraft));
  }, [q.data, drafts]);

  const save = useMutation({
    mutationFn: (ports: Rule[]) => call(api.PUT('/steering', { body: { ports } })),
    onSuccess: (v) => {
      setWarnings(v.warnings ?? null);
      setSaved(true);
      setDrafts(v.ports.map(toDraft));
      qc.setQueryData(steeringKey, v);
    },
  });

  const writable = can('operator');
  const set = (i: number, patch: Partial<Draft>) => {
    setSaved(false);
    setDrafts((d) => (d ?? []).map((x, n) => (n === i ? { ...x, ...patch } : x)));
  };

  return (
    <>
      <PageHeader title={m.ports.title} />
      <div className="space-y-4">
        <p className="max-w-3xl text-sm text-stone-600 dark:text-stone-400">{m.ports.bypass}</p>
        <ErrorMessage error={q.error} />
        <ValidationIssues result={validationOf(save.error)} />
        {!validationOf(save.error) && <ErrorMessage error={save.error} />}
        <ApplyWarnings warnings={warnings} />
        {saved && !warnings?.length && <Alert tone="success">{m.common.saved}</Alert>}
        <Card>
          {!drafts ? (
            <Loading />
          ) : (
            <>
              <Table
                head={[m.ports.port, m.ports.class, m.ports.protocols, m.ports.targetPort, '']}
                empty={drafts.length === 0}
              >
                {drafts.map((d, i) => (
                  <tr key={i}>
                    <Td>
                      <Input
                        ltr
                        type="number"
                        min={1}
                        max={65535}
                        required
                        disabled={!writable}
                        aria-label={m.ports.port}
                        className="min-w-24 max-w-28"
                        value={d.port}
                        onChange={(e) => {
                          set(i, { port: e.target.value });
                        }}
                      />
                    </Td>
                    <Td>
                      <Select
                        disabled={!writable}
                        aria-label={m.ports.class}
                        className="min-w-32"
                        value={d.class}
                        onChange={(e) => {
                          set(i, { class: e.target.value as Rule['class'] });
                        }}
                      >
                        <option value="tunneled">{m.ports.classes.tunneled}</option>
                        <option value="vip">{m.ports.classes.vip}</option>
                      </Select>
                    </Td>
                    <Td>
                      <div className="flex gap-3">
                        {(['tcp', 'udp'] as const).map((p) => (
                          <label key={p} className="inline-flex items-center gap-1.5">
                            <input
                              type="checkbox"
                              aria-label={p.toUpperCase()}
                              disabled={!writable}
                              checked={d[p]}
                              onChange={(e) => {
                                set(i, { [p]: e.target.checked });
                              }}
                            />
                            <span className="font-mono text-xs uppercase">{p}</span>
                          </label>
                        ))}
                      </div>
                    </Td>
                    <Td>
                      <Input
                        ltr
                        type="number"
                        min={1}
                        max={65535}
                        disabled={!writable}
                        aria-label={m.ports.targetPort}
                        title={m.ports.targetHint}
                        placeholder={d.port}
                        className="min-w-24 max-w-28"
                        value={d.targetPort}
                        onChange={(e) => {
                          set(i, { targetPort: e.target.value });
                        }}
                      />
                    </Td>
                    <Td className="text-end">
                      {writable && (
                        <Button
                          variant="ghost"
                          onClick={() => {
                            setSaved(false);
                            setDrafts(drafts.filter((_, n) => n !== i));
                          }}
                        >
                          {m.common.delete}
                        </Button>
                      )}
                    </Td>
                  </tr>
                ))}
              </Table>
              <p className="mt-2 text-xs text-stone-500">{m.ports.targetHint}</p>
              {writable && (
                <div className="mt-4 flex flex-wrap gap-2">
                  <Button
                    variant="secondary"
                    onClick={() => {
                      setSaved(false);
                      setDrafts([
                        ...drafts,
                        { port: '', class: 'tunneled', tcp: true, udp: false, targetPort: '' },
                      ]);
                    }}
                  >
                    {m.ports.add}
                  </Button>
                  <Button
                    busy={save.isPending}
                    onClick={() => {
                      save.mutate(drafts.map(toRule));
                    }}
                  >
                    {m.common.save}
                  </Button>
                </div>
              )}
            </>
          )}
        </Card>
      </div>
    </>
  );
}
