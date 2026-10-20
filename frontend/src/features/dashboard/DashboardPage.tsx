import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { useLive } from '@/app/live';
import { api, call } from '@/shared/api/client';
import { statusKey } from '@/shared/hooks/useLiveEvents';
import { useI18n } from '@/shared/i18n/useI18n';
import { stateTone } from '@/shared/peerState';
import { Badge, Card, ErrorMessage, Loading, Ltr, PageHeader, Td, Table } from '@/shared/ui';
import { cx } from '@/shared/ui/cx';
import { TrafficChart } from './TrafficChart';

type Range = '1h' | '24h' | '7d' | '30d';

export function DashboardPage() {
  const { m, f } = useI18n();
  const { events } = useLive();
  const [range, setRange] = useState<Range>('24h');
  // The WebSocket keeps this fresh; polling is only the fallback.
  const status = useQuery({
    queryKey: statusKey,
    queryFn: () => call(api.GET('/node/status')),
    refetchInterval: 15000,
  });
  const traffic = useQuery({
    queryKey: ['traffic', range],
    queryFn: () => call(api.GET('/stats/traffic', { params: { query: { range } } })),
    refetchInterval: 60000,
  });

  const s = status.data;
  return (
    <>
      <PageHeader title={m.nav.dashboard} />
      <ErrorMessage error={status.error} />
      {!s ? (
        <Loading />
      ) : (
        <div className="space-y-4">
          <dl className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            <Stat
              label={m.status.node}
              value={<Ltr>{s.nodeId}</Ltr>}
              sub={`${m.roles.node[s.role]} · ${m.status.version} ${s.version}`}
            />
            <Stat label={m.status.uptime} value={f.duration(s.uptimeSec)} />
            <Stat
              label={m.status.sessions}
              value={f.num(s.sessions)}
              sub={`${m.status.streams}: ${f.num(s.streams)}`}
            />
            <Stat
              label={m.status.bytesIn}
              value={f.bytes(s.bytesIn)}
              sub={`${m.status.bytesOut}: ${f.bytes(s.bytesOut)}`}
            />
          </dl>

          <Card
            title={m.traffic.title}
            actions={
              <div
                className="flex rounded-md border border-stone-300 p-0.5 text-xs dark:border-stone-700"
                role="group"
              >
                {(['1h', '24h', '7d', '30d'] as const).map((r) => (
                  <button
                    key={r}
                    type="button"
                    aria-pressed={range === r}
                    className={cx(
                      'rounded px-2 py-0.5',
                      range === r ? 'bg-sky-700 text-white' : 'text-stone-600 dark:text-stone-300',
                    )}
                    onClick={() => {
                      setRange(r);
                    }}
                  >
                    {m.traffic.ranges[r]}
                  </button>
                ))}
              </div>
            }
          >
            <ErrorMessage error={traffic.error} />
            {traffic.data ? <TrafficChart points={traffic.data.points} /> : <Loading />}
          </Card>

          <div className="grid gap-4 lg:grid-cols-2">
            <Card title={m.status.peers}>
              <Table head={[m.peers.id, '', m.status.activePaths, m.status.rtt]} empty={s.peers.length === 0}>
                {s.peers.map((p) => (
                  <tr key={p.id}>
                    <Td>
                      <Ltr>{p.id}</Ltr>
                    </Td>
                    <Td>
                      <Badge tone={stateTone[p.state]}>{m.status.states[p.state]}</Badge>
                    </Td>
                    <Td>{f.num(p.activePaths)}</Td>
                    <Td>{p.rttMs ? f.ms(p.rttMs) : '–'}</Td>
                  </tr>
                ))}
              </Table>
            </Card>
            <Card title={m.events.title}>
              {events.length === 0 ? (
                <p className="py-6 text-center text-sm text-stone-500">{m.events.empty}</p>
              ) : (
                <ol className="max-h-72 space-y-1.5 overflow-y-auto text-sm">
                  {events.map((e, i) => (
                    <li key={`${e.at}-${i}`} className="flex gap-2">
                      <time className="shrink-0 text-xs text-stone-500 tabular-nums">{f.time(e.at)}</time>
                      <span>
                        <span className="font-medium">{m.events.types[e.type]}</span>
                        <EventDetail data={e.data} />
                      </span>
                    </li>
                  ))}
                </ol>
              )}
            </Card>
          </div>
        </div>
      )}
    </>
  );
}

function Stat({ label, value, sub }: { label: string; value: React.ReactNode; sub?: string }) {
  return (
    <div className="min-w-0 rounded-lg border border-stone-200 bg-white p-3 dark:border-stone-800 dark:bg-stone-900">
      <dt className="text-xs text-stone-500">{label}</dt>
      <dd className="mt-1 text-lg font-semibold tabular-nums">{value}</dd>
      {sub && <dd className="text-xs text-stone-500">{sub}</dd>}
    </div>
  );
}

/** The interesting fields of an event, kept LTR (ids, addresses, reasons). */
function EventDetail({ data }: { data?: Record<string, unknown> }) {
  if (!data) return null;
  const parts = ['peer', 'transport', 'remote', 'state', 'message', 'reason', 'error']
    .map((k) => data[k])
    .filter((v): v is string | number => typeof v === 'string' || typeof v === 'number');
  if (parts.length === 0) return null;
  return (
    <>
      {' '}
      <Ltr mono={false}>
        <span className="text-stone-500">{parts.join(' · ')}</span>
      </Ltr>
    </>
  );
}
