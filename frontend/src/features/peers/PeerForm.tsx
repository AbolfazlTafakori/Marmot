import { useState, type FormEvent } from 'react';
import type { Schemas } from '@/shared/api/client';
import { useI18n } from '@/shared/i18n/useI18n';
import { Button, Field, Input, Select } from '@/shared/ui';

type Peer = Schemas['Peer'];
type Endpoint = Schemas['Endpoint'];

interface EndpointDraft {
  transport: string;
  ports: string;
  sni: string;
}

// Transports in this build (Phase 1). Others arrive with later phases.
const transports = ['tls', 'tcp'];

function toDraft(e: Endpoint): EndpointDraft {
  const sni = e.options?.sni;
  return {
    transport: e.transport,
    ports: (e.ports ?? []).join(', '),
    sni: typeof sni === 'string' ? sni : '',
  };
}

function fromDraft(d: EndpointDraft, base?: Endpoint): Endpoint {
  const options: Record<string, unknown> = { ...(base?.options ?? {}) };
  if (d.sni) options.sni = d.sni;
  else delete options.sni;
  return {
    transport: d.transport,
    direction: 'outbound',
    family: base?.family ?? 'any',
    ports: d.ports
      .split(/[,\s]+/)
      .filter(Boolean)
      .map(Number),
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
  const [id, setId] = useState(initial?.id ?? '');
  const [publicKey, setPublicKey] = useState(initial?.publicKey ?? '');
  const [weight, setWeight] = useState(String(initial?.weight ?? 1));
  const [pool, setPool] = useState((initial?.ipv4Pool ?? []).join(', '));
  const [endpoints, setEndpoints] = useState<EndpointDraft[]>((initial?.endpoints ?? []).map(toDraft));

  const submit = (e: FormEvent) => {
    e.preventDefault();
    onSubmit({
      id: id.trim(),
      publicKey: publicKey.trim(),
      weight: Number(weight) || 1,
      ipv4Pool: pool.split(/[,\s]+/).filter(Boolean),
      ...(initial?.ipv6Pool?.length ? { ipv6Pool: initial.ipv6Pool } : {}),
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
      <Field label={m.peers.ipv4Pool} hint={m.peers.ipv4Hint}>
        <Input
          ltr
          value={pool}
          onChange={(e) => {
            setPool(e.target.value);
          }}
        />
      </Field>
      <fieldset className="space-y-2">
        <legend className="text-sm font-medium">{m.peers.endpoints}</legend>
        {endpoints.length === 0 && <p className="text-xs text-stone-500">{m.peers.inboundOnly}</p>}
        {endpoints.map((d, i) => (
          <div key={i} className="grid items-end gap-2 sm:grid-cols-[7rem_1fr_1fr_auto]">
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
                placeholder="9443, 2083"
                value={d.ports}
                onChange={(e) => {
                  setEp(i, { ports: e.target.value });
                }}
              />
            </Field>
            <Field label={m.peers.sni}>
              <Input
                ltr
                disabled={d.transport !== 'tls'}
                value={d.sni}
                onChange={(e) => {
                  setEp(i, { sni: e.target.value });
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
            setEndpoints([...endpoints, { transport: 'tls', ports: '', sni: '' }]);
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
