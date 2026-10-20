import type { Schemas } from './api/client';

type PeerState = Schemas['PeerHealth']['state'];

/** Badge tone of each peer state; the label always accompanies it. */
export const stateTone: Record<PeerState, 'good' | 'warn' | 'bad' | 'neutral'> = {
  up: 'good',
  degraded: 'warn',
  relayed: 'warn',
  down: 'bad',
};
