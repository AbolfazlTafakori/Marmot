import { createContext, useContext } from 'react';
import type { LiveEvent } from '@/shared/hooks/useLiveEvents';

export const LiveContext = createContext<{ events: LiveEvent[]; connected: boolean }>({
  events: [],
  connected: false,
});

export function useLive() {
  return useContext(LiveContext);
}
