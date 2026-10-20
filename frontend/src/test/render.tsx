import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render } from '@testing-library/react';
import type { ReactElement } from 'react';
import { I18nProvider } from '@/shared/i18n/I18nProvider';

/** Renders ui inside the app's providers with a fresh query cache. */
export function renderWithProviders(ui: ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return {
    qc,
    ...render(
      <QueryClientProvider client={qc}>
        <I18nProvider>{ui}</I18nProvider>
      </QueryClientProvider>,
    ),
  };
}

/** A fetch stub answering each call with the next response in order. */
export function stubFetch(responses: { status: number; body?: unknown }[]) {
  const calls: Request[] = [];
  const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const req =
      input instanceof Request ? input : new Request(new URL(String(input), 'http://panel.test'), init);
    calls.push(req);
    const r = responses.shift() ?? { status: 500 };
    return Promise.resolve(
      new Response(r.body === undefined ? null : JSON.stringify(r.body), {
        status: r.status,
        headers: { 'Content-Type': 'application/json' },
      }),
    );
  });
  vi.stubGlobal('fetch', fetchMock);
  return calls;
}
