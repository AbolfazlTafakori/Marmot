import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderWithProviders } from '@/test/render';
import { TrafficChart } from './TrafficChart';

const points = [
  { t: '2026-10-20T10:00:00Z', bytesIn: 1024, bytesOut: 2048 },
  { t: '2026-10-20T10:01:00Z', bytesIn: 0, bytesOut: 0 },
  { t: '2026-10-20T10:02:00Z', bytesIn: 4096, bytesOut: 512 },
];

describe('TrafficChart', () => {
  it('draws one line per series with a legend and an accessible summary', () => {
    const { container } = renderWithProviders(<TrafficChart points={points} />);
    expect(container.querySelectorAll('path')).toHaveLength(2);
    expect(screen.getByRole('list', { name: 'ترافیک' })).toHaveTextContent('دریافتی');
    expect(screen.getByRole('img').getAttribute('aria-label')).toContain('۵ کیلوبایت');
  });

  it('offers the same data as a table, without empty buckets', async () => {
    const user = userEvent.setup();
    renderWithProviders(<TrafficChart points={points} />);
    await user.click(screen.getByRole('button', { name: 'نمایش به‌صورت جدول' }));
    expect(screen.getAllByRole('row')).toHaveLength(3); // header + 2 non-empty buckets
  });

  it('says so when nothing moved', () => {
    renderWithProviders(<TrafficChart points={[{ t: points[0]?.t ?? '', bytesIn: 0, bytesOut: 0 }]} />);
    expect(screen.getByText('در این بازه ترافیکی ثبت نشده است.')).toBeInTheDocument();
  });
});
