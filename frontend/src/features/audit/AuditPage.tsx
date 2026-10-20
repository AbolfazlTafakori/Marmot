import { useInfiniteQuery } from '@tanstack/react-query';
import { api, call } from '@/shared/api/client';
import { useI18n } from '@/shared/i18n/useI18n';
import { Button, Card, ErrorMessage, Loading, Ltr, PageHeader, Td, Table } from '@/shared/ui';

/** Who changed what, newest first, paged by cursor. */
export function AuditPage() {
  const { m, f } = useI18n();
  const q = useInfiniteQuery({
    queryKey: ['audit'],
    queryFn: ({ pageParam }) =>
      call(
        api.GET('/audit', { params: { query: { limit: 50, ...(pageParam ? { cursor: pageParam } : {}) } } }),
      ),
    initialPageParam: '',
    getNextPageParam: (last) => last.nextCursor ?? undefined,
  });
  const items = q.data?.pages.flatMap((p) => p.items) ?? [];
  return (
    <>
      <PageHeader title={m.audit.title} />
      <Card>
        <ErrorMessage error={q.error} />
        {q.isPending ? (
          <Loading />
        ) : (
          <>
            <Table
              head={[m.audit.at, m.audit.admin, m.audit.action, m.audit.target, m.audit.ip]}
              empty={items.length === 0}
            >
              {items.map((it, i) => (
                <tr key={`${it.at}-${i}`}>
                  <Td className="whitespace-nowrap">{f.dateTime(it.at)}</Td>
                  <Td>
                    <Ltr>{it.admin}</Ltr>
                  </Td>
                  <Td>
                    <Ltr>{it.action}</Ltr>
                  </Td>
                  <Td>
                    <Ltr>{it.target}</Ltr>
                  </Td>
                  <Td>{it.sourceIp && <Ltr>{it.sourceIp}</Ltr>}</Td>
                </tr>
              ))}
            </Table>
            {q.hasNextPage && (
              <Button
                variant="secondary"
                className="mt-3"
                busy={q.isFetchingNextPage}
                onClick={() => {
                  void q.fetchNextPage();
                }}
              >
                {m.audit.more}
              </Button>
            )}
          </>
        )}
      </Card>
    </>
  );
}
