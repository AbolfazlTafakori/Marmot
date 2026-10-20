import { useState, type FormEvent } from 'react';
import type { Schemas } from '@/shared/api/client';
import { useI18n } from '@/shared/i18n/useI18n';
import { Button, Field, Input, Select } from '@/shared/ui';

type Peer = Schemas['Peer'];
type Endpoint = Schemas['Endpoint'];

interface EndpointDraft {
  transport: string;
  /** A list ("9443, 2083") or a range ("40000-40099"). */
  ports: string;
  sni: string;
  /** ws path, grpc service or quic ALPN; other transports have none. */
  extra: string;
}

// Transports in this build (Phase 3).
const transports = ['tls', 'tcp', 'ws', 'grpc', 'quic'];

/** The option each transport keeps in the extra field. */
const extraOption: Record<string, string | undefined> = { ws: 'path', grpc: 'service', quic: 'alpn' };
const extraKeys = new Set(Object.values(extraOption));

const extraPlaceholder: Record<string, string | undefined> = { grpc: 'marmot.Tunnel', quic: 'h3' };

const usesTLS = (t: string) => t !== 'tcp';

function optionString(e: Endpoint, key: string | undefined): string {
  const v = key ? e.options?.[key] : undefined;
  return typeof v === 'string' ? v : '';
}

function toDraft(e: Endpoint): EndpointDraft {
  return {
    transport: e.transport,
    ports: e.portRange ?? (e.ports ?? []).join(', '),
    sni: optionString(e, 'sni'),
    extra: optionString(e, extraOption[e.transport]),
  };
}

function fromDraft(d: EndpointDraft, base?: Endpoint): Endpoint {
  // Keep options this form does not edit; drop path/service/alpn of
  // another transport so a changed transport carries none of them.
  const options: Record<string, unknown> = Object.fromEntries(
    Object.entries(base?.options ?? {}).filter(([k]) => !extraKeys.has(k)),
  );
  if (d.sni && usesTLS(d.transport)) options.sni = d.sni;
  else delete options.sni;
  const extraKey = extraOption[d.transport];
  if (extraKey && d.extra) options[extraKey] = d.extra;
  const range = /^\s*(\d{1,5})\s*-\s*(\d{1,5})\s*$/.exec(d.ports);
  return {
    transport: d.transport,
    direction: 'outbound',
    family: base?.family ?? 'any',
    ...(range
      ? { portRange: `${range[1]}-${range[2]}` }
      : {
          ports: d.ports
            .split(/[,\s]+/)
            .filter(Boolean)
            .map(Number),
        }),
    ...(Object.keys(options).length ? { options } : {}),
  };
}

/** Add or edit a peer by hand. Editing keeps the id (renaming = re-adding). */
export function PeerForm({
  initial,
  busy,
  onSubmit,
  onCancel,
}: {
  initial?: Peer;
  busy: boolean;
  onSubmit: (p: Peer) => void;
  onCancel: () => void;
}) {
  const { m } = useI18n();
  const extraLabel = (t: string) =>
    t === 'grpc' ? m.peers.grpcService : t === 'quic' ? m.peers.quicAlpn : m.peers.wsPath;
  const [id, setId] = useState(initial?.id ?? '');
  const [publicKey, setPublicKey] = useState(initial?.publicKey ?? '');
  const [weight, setWeight] = useState(String(initial?.weight ?? 1));
  const [pool, setPool] = useState((initial?.ipv4Pool ?? []).join(', '));
  const [pool6, setPool6] = useState((initial?.ipv6Pool ?? []).join(', '));
  const [endpoints, setEndpoints] = useState<EndpointDraft[]>((initial?.endpoints ?? []).map(toDraft));

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const ipv6Pool = pool6.split(/[,\s]+/).filter(Boolean);
    onSubmit({
      id: id.trim(),
      publicKey: publicKey.trim(),
      weight: Number(weight) || 1,
      ipv4Pool: pool.split(/[,\s]+/).filter(Boolean),
      ...(ipv6Pool.length ? { ipv6Pool } : {}),
      ...(initial?.ipv6Subnet ? { ipv6Subnet: initial.ipv6Subnet } : {}),
      endpoints: endpoints.map((d, i) => fromDraft(d, initial?.endpoints[i])),
    });
  };
  const setEp = (i: number, patch: Partial<EndpointDraft>) => {
    setEndpoints(endpoints.map((d, n) => (n === i ? { ...d, ...patch } : d)));
  };

  return (
    <form onSubmit={submit} className="space-y-3">
      <div className="grid gap-3 sm:grid-cols-[2fr_1fr]">
        <Field label={m.peers.id}>
          <Input
            ltr
            required
            pattern="[a-z0-9][a-z0-9\-]{0,62}"
            disabled={!!initial}
            value={id}
            onChange={(e) => {
              setId(e.target.value);
            }}
          />
        </Field>
        <Field label={m.peers.weight}>
          <Input
            ltr
            type="number"
            min={1}
            max={100}
            value={weight}
            onChange={(e) => {
              setWeight(e.target.value);
            }}
          />
        </Field>
      </div>
      <Field label={m.peers.publicKey}>
        <Input
          ltr
          required
          placeholder="ed25519:…"
          value={publicKey}
          onChange={(e) => {
            setPublicKey(e.target.value);
          }}
        />
      </Field>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label={m.peers.ipv4Pool} hint={m.peers.ipv4Hint}>
          <Input
            ltr
            value={pool}
            onChange={(e) => {
              setPool(e.target.value);
            }}
          />
        </Field>
        <Field label={m.peers.ipv6Pool} hint={m.peers.ipv4Hint}>
          <Input
            ltr
            value={pool6}
            onChange={(e) => {
              setPool6(e.target.value);
            }}
          />
        </Field>
      </div>
      <fieldset className="space-y-2">
        <legend className="text-sm font-medium">{m.peers.endpoints}</legend>
        {endpoints.length === 0 && <p className="text-xs text-stone-500">{m.peers.inboundOnly}</p>}
        {endpoints.map((d, i) => (
          <div key={i} className="grid items-end gap-2 sm:grid-cols-[7rem_1fr_1fr_1fr_auto]">
            <Field label={m.peers.transport}>
              <Select
                value={d.transport}
                onChange={(e) => {
                  setEp(i, { transport: e.target.value });
                }}
              >
                {transports.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </Select>
            </Field>
            <Field label={m.peers.endpointPorts}>
              <Input
                ltr
                required
                placeholder="9443, 2083 · 40000-40099"
                value={d.ports}
                onChange={(e) => {
                  setEp(i, { ports: e.target.value });
                }}
              />
            </Field>
            <Field label={m.peers.sni}>
              <Input
                ltr
                disabled={!usesTLS(d.transport)}
                value={d.sni}
                onChange={(e) => {
                  setEp(i, { sni: e.target.value });
                }}
              />
            </Field>
            <Field label={extraLabel(d.transport)}>
              <Input
                ltr
                disabled={!extraOption[d.transport]}
                placeholder={extraPlaceholder[d.transport] ?? '/'}
                value={d.extra}
                onChange={(e) => {
                  setEp(i, { extra: e.target.value });
                }}
              />
            </Field>
            <Button
              variant="ghost"
              onClick={() => {
                setEndpoints(endpoints.filter((_, n) => n !== i));
              }}
            >
              {m.common.delete}
            </Button>
          </div>
        ))}
        <Button
          variant="secondary"
          onClick={() => {
            setEndpoints([...endpoints, { transport: 'tls', ports: '', sni: '', extra: '' }]);
          }}
        >
          {m.peers.addEndpoint}
        </Button>
      </fieldset>
      <div className="flex gap-2">
        <Button type="submit" busy={busy}>
          {m.common.save}
        </Button>
        <Button variant="secondary" onClick={onCancel}>
          {m.common.cancel}
        </Button>
      </div>
    </form>
  );
}
