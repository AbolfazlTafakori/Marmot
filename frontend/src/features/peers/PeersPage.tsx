import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Fragment, useState, type FormEvent } from 'react';
import { api, call, validationOf, type Schemas } from '@/shared/api/client';
import { useAuth } from '@/shared/auth/context';
import { fill, useI18n } from '@/shared/i18n/useI18n';
import { stateTone } from '@/shared/peerState';
import {
  ApplyWarnings,
  Badge,
  Button,
  Card,
  ErrorMessage,
  Field,
  Input,
  Loading,
  Ltr,
  PageHeader,
  Td,
  Table,
} from '@/shared/ui';
import { cx } from '@/shared/ui/cx';
import { ValidationIssues } from '@/shared/ui/ValidationIssues';
import { PeerForm } from './PeerForm';
import { PathsTable } from './PathsTable';

type Peer = Schemas['Peer'];
type PeerView = Schemas['PeerView'];

const peersKey = ['peers'] as const;

export function PeersPage() {
  const { m, f } = useI18n();
  const { can } = useAuth();
  const qc = useQueryClient();
  const peers = useQuery({
    queryKey: peersKey,
    queryFn: () => call(api.GET('/peers')),
    refetchInterval: 10000,
  });
  const [mode, setMode] = useState<'closed' | 'token' | 'manual'>('closed');
  const [editing, setEditing] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const [token, setToken] = useState('');
  const [weight, setWeight] = useState('1');
  const [warnings, setWarnings] = useState<string[] | null>(null);

  const done = (v: PeerView) => {
    setWarnings(v.warnings ?? null);
    setMode('closed');
    setEditing(null);
    setToken('');
    void qc.invalidateQueries({ queryKey: peersKey });
  };
  const create = useMutation({
    mutationFn: (body: Peer | Schemas['JoinRequest']) => call(api.POST('/peers', { body })),
    onSuccess: done,
  });
  const update = useMutation({
    mutationFn: (p: Peer) =>
      call(api.PUT('/peers/{peerId}', { params: { path: { peerId: p.id } }, body: p })),
    onSuccess: done,
  });
  const remove = useMutation({
    mutationFn: (id: string) => call(api.DELETE('/peers/{peerId}', { params: { path: { peerId: id } } })),
    onSuccess: () => void qc.invalidateQueries({ queryKey: peersKey }),
  });

  const submitToken = (e: FormEvent) => {
    e.preventDefault();
    create.mutate({ joinToken: token.trim(), weight: Number(weight) || 1 });
  };
  const writable = can('operator');
  const pending = create.isPending || update.isPending;
  const mutationError = create.error ?? update.error ?? remove.error;

  return (
    <>
      <PageHeader
        title={m.peers.title}
        actions={
          writable &&
          mode === 'closed' && (
            <Button
              onClick={() => {
                setMode('token');
                create.reset();
              }}
            >
              {m.peers.add}
            </Button>
          )
        }
      />
      <div className="space-y-4">
        <ApplyWarnings warnings={warnings} />
        {mode !== 'closed' && (
          <Card
            title={m.peers.add}
            actions={
              <div
                className="flex rounded-md border border-stone-300 p-0.5 text-xs dark:border-stone-700"
                role="group"
              >
                {(['token', 'manual'] as const).map((k) => (
                  <button
                    key={k}
                    type="button"
                    aria-pressed={mode === k}
                    className={cx(
                      'rounded px-2 py-0.5',
                      mode === k ? 'bg-sky-700 text-white' : 'text-stone-600 dark:text-stone-300',
                    )}
                    onClick={() => {
                      setMode(k);
                    }}
                  >
                    {k === 'token' ? m.peers.byToken : m.peers.manual}
                  </button>
                ))}
              </div>
            }
          >
            <div className="space-y-3">
              <ValidationIssues result={validationOf(create.error)} />
              {!validationOf(create.error) && <ErrorMessage error={create.error} />}
              {mode === 'token' ? (
                <form onSubmit={submitToken} className="space-y-3">
                  <Field label={m.peers.joinToken} hint={m.peers.joinHint}>
                    <textarea
                      dir="ltr"
                      required
                      rows={3}
                      value={token}
                      onChange={(e) => {
                        setToken(e.target.value);
                      }}
                      className="w-full rounded-md border border-stone-300 bg-white px-2.5 py-1.5 font-mono text-xs dark:border-stone-700 dark:bg-stone-950"
                    />
                  </Field>
                  <Field label={m.peers.weight}>
                    <Input
                      ltr
                      type="number"
                      min={1}
                      max={100}
                      className="max-w-24"
                      value={weight}
                      onChange={(e) => {
                        setWeight(e.target.value);
                      }}
                    />
                  </Field>
                  <div className="flex gap-2">
                    <Button type="submit" busy={pending}>
                      {m.common.add}
                    </Button>
                    <Button
                      variant="secondary"
                      onClick={() => {
                        setMode('closed');
                      }}
                    >
                      {m.common.cancel}
                    </Button>
                  </div>
                </form>
              ) : (
                <PeerForm
                  busy={pending}
                  onSubmit={(p) => {
                    create.mutate(p);
                  }}
                  onCancel={() => {
                    setMode('closed');
                  }}
                />
              )}
            </div>
          </Card>
        )}

        {mutationError && !validationOf(mutationError) && mode === 'closed' && (
          <ErrorMessage error={mutationError} />
        )}
        <ValidationIssues result={mode === 'closed' ? validationOf(update.error ?? remove.error) : null} />

        <Card>
          <ErrorMessage error={peers.error} />
          {!peers.data ? (
            <Loading />
          ) : (
            <Table
              head={[m.peers.id, '', m.peers.weight, m.peers.endpoints, m.status.rtt, '']}
              empty={peers.data.length === 0}
            >
              {peers.data.map((p) => (
                <Fragment key={p.id}>
                  <tr>
                    <Td>
                      <Ltr>{p.id}</Ltr>
                    </Td>
                    <Td>
                      {p.health && (
                        <Badge tone={stateTone[p.health.state]}>{m.status.states[p.health.state]}</Badge>
                      )}
                    </Td>
                    <Td>{f.num(p.weight)}</Td>
                    <Td>
                      {p.endpoints.length === 0 ? (
                        <span className="text-xs text-stone-500">{m.peers.inboundOnly}</span>
                      ) : (
                        p.endpoints.map((e, i) => (
                          <div key={i}>
                            <Ltr wrap>
                              {e.transport} {(p.ipv4Pool ?? []).join(',')}:{(e.ports ?? []).join(',')}
                              {e.portRange ?? ''}
                            </Ltr>
                          </div>
                        ))
                      )}
                    </Td>
                    <Td>{p.health?.rttMs ? f.ms(p.health.rttMs) : '–'}</Td>
                    <Td className="text-end whitespace-nowrap">
                      <Button
                        variant="ghost"
                        aria-expanded={open === p.id}
                        onClick={() => {
                          setOpen(open === p.id ? null : p.id);
                        }}
                      >
                        {m.peers.paths}
                      </Button>
                      {writable && (
                        <>
                          <Button
                            variant="ghost"
                            onClick={() => {
                              setEditing(editing === p.id ? null : p.id);
                              update.reset();
                            }}
                          >
                            {m.common.edit}
                          </Button>
                          <Button
                            variant="ghost"
                            className="text-red-700 dark:text-red-400"
                            onClick={() => {
                              if (window.confirm(fill(m.peers.confirmDelete, { id: p.id })))
                                remove.mutate(p.id);
                            }}
                          >
                            {m.common.delete}
                          </Button>
                        </>
                      )}
                    </Td>
                  </tr>
                  {editing === p.id && (
                    <tr>
                      <td colSpan={6} className="bg-stone-50 p-3 dark:bg-stone-950">
                        <ValidationIssues result={validationOf(update.error)} />
                        <PeerForm
                          initial={p}
                          busy={update.isPending}
                          onSubmit={(np) => {
                            update.mutate(np);
                          }}
                          onCancel={() => {
                            setEditing(null);
                          }}
                        />
                      </td>
                    </tr>
                  )}
                  {open === p.id && (
                    <tr>
                      <td colSpan={6} className="bg-stone-50 p-3 dark:bg-stone-950">
                        <PathsTable peerId={p.id} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </Table>
          )}
        </Card>
      </div>
    </>
  );
}
