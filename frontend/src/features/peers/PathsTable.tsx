import { useQuery } from '@tanstack/react-query';
import { api, call } from '@/shared/api/client';
import { useI18n } from '@/shared/i18n/useI18n';
import { Badge, ErrorMessage, Loading, Ltr, Td, Table } from '@/shared/ui';

/** Live paths to one peer: role, route, RTT and average throughput. */
export function PathsTable({ peerId }: { peerId: string }) {
  const { m, f } = useI18n();
  const q = useQuery({
    queryKey: ['paths', peerId],
    queryFn: () => call(api.GET('/peers/{peerId}/paths', { params: { path: { peerId } } })),
    refetchInterval: 3000,
  });
  if (q.error) return <ErrorMessage error={q.error} />;
  if (!q.data) return <Loading />;
  return (
    <Table
      head={['', m.peers.transport, m.peers.local, m.peers.remote, m.status.rtt, m.peers.throughput]}
      empty={q.data.length === 0}
    >
      {q.data.map((p) => (
        <tr key={p.id}>
          <Td>
            <Badge tone={p.role === 'active' ? 'good' : 'neutral'}>{m.peers.pathRole[p.role]}</Badge>
          </Td>
          <Td>
            <Ltr>{p.transport}</Ltr>
          </Td>
          <Td>
            <Ltr>{p.local}</Ltr>
          </Td>
          <Td>
            <Ltr>{p.remote}</Ltr>
          </Td>
          <Td>{p.rttMs ? f.ms(p.rttMs) : '–'}</Td>
          <Td>{f.bits(p.throughputBps)}</Td>
        </tr>
      ))}
    </Table>
  );
}
