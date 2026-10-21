import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { Schemas } from '@/shared/api/client';
import { renderWithProviders } from '@/test/render';
import { PeerForm } from './PeerForm';

type Peer = Schemas['Peer'];

const peer: Peer = {
  id: 'kharej-01',
  publicKey: 'ed25519:AAAA',
  weight: 2,
  ipv4Pool: ['198.51.100.7'],
  endpoints: [
    {
      transport: 'quic',
      direction: 'outbound',
      family: 'any',
      portRange: '40000-40099',
      options: { alpn: 'doq', datagrams: false },
    },
    {
      transport: 'tls',
      direction: 'outbound',
      family: 'any',
      ports: [9443, 2083],
      options: { sni: 'cdn.example.com' },
    },
  ],
};

describe('PeerForm', () => {
  it('keeps a quic port range and its options through an edit', async () => {
    const user = userEvent.setup();
    const onSubmit = vi.fn();
    renderWithProviders(<PeerForm initial={peer} busy={false} onSubmit={onSubmit} onCancel={() => {}} />);
    expect(screen.getByDisplayValue('40000-40099')).toBeInTheDocument();
    expect(screen.getByDisplayValue('doq')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'ذخیره و اعمال' }));
    const saved = onSubmit.mock.calls[0]?.[0] as Peer;
    expect(saved.endpoints[0]).toEqual({
      transport: 'quic',
      direction: 'outbound',
      family: 'any',
      portRange: '40000-40099',
      options: { alpn: 'doq', datagrams: false },
    });
    expect(saved.endpoints[1]?.ports).toEqual([9443, 2083]);
    expect(saved.endpoints[1]?.portRange).toBeUndefined();
  });

  it('drops the alpn when the transport changes', async () => {
    const user = userEvent.setup();
    const onSubmit = vi.fn();
    renderWithProviders(<PeerForm initial={peer} busy={false} onSubmit={onSubmit} onCancel={() => {}} />);
    const transport = screen.getAllByRole('combobox')[0];
    if (!transport) throw new Error('no transport select');
    await user.selectOptions(transport, 'tls');
    await user.click(screen.getByRole('button', { name: 'ذخیره و اعمال' }));
    const saved = onSubmit.mock.calls[0]?.[0] as Peer;
    expect(saved.endpoints[0]?.options).toEqual({ datagrams: false });
  });

  it('keeps the direction and hop interval of a reverse udp endpoint', async () => {
    const user = userEvent.setup();
    const onSubmit = vi.fn();
    const reverse: Peer = {
      ...peer,
      endpoints: [
        {
          transport: 'udp',
          direction: 'inbound',
          family: 'any',
          portRange: '41000-41009',
          hopInterval: '30s',
        },
      ],
    };
    renderWithProviders(<PeerForm initial={reverse} busy={false} onSubmit={onSubmit} onCancel={() => {}} />);
    await user.click(screen.getByRole('button', { name: 'ذخیره و اعمال' }));
    const saved = onSubmit.mock.calls[0]?.[0] as Peer;
    expect(saved.endpoints[0]).toEqual({
      transport: 'udp',
      direction: 'inbound',
      family: 'any',
      portRange: '41000-41009',
      hopInterval: '30s',
    });
  });
});
