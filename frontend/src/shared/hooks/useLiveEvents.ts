import { useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import type { Schemas } from '../api/client';

export type LiveEvent = Schemas['Event'];

export const statusKey = ['status'] as const;

const keep = 50;
const minBackoff = 1000;
const maxBackoff = 30000;

/**
 * Connects to /api/v1/ws while mounted. status.tick events refresh the
 * status query in place; other events are kept, newest first. The socket
 * reconnects with backoff, so a node restart heals by itself.
 */
export function useLiveEvents(enabled: boolean): { events: LiveEvent[]; connected: boolean } {
  const qc = useQueryClient();
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    if (!enabled) return;
    let ws: WebSocket | null = null;
    let timer = 0;
    let backoff = minBackoff;
    let stopped = false;

    const connect = () => {
      const scheme = window.location.protocol === 'https:' ? 'wss' : 'ws';
      ws = new WebSocket(`${scheme}://${window.location.host}/api/v1/ws`);
      ws.onopen = () => {
        backoff = minBackoff;
        setConnected(true);
      };
      ws.onmessage = (msg: MessageEvent<string>) => {
        let e: LiveEvent;
        try {
          e = JSON.parse(msg.data) as LiveEvent;
        } catch {
          return;
        }
        if (e.type === 'status.tick') {
          qc.setQueryData(statusKey, e.data);
          return;
        }
        setEvents((prev) => [e, ...prev].slice(0, keep));
        if (e.type === 'config.applied') void qc.invalidateQueries();
      };
      ws.onclose = () => {
        setConnected(false);
        if (stopped) return;
        timer = window.setTimeout(connect, backoff);
        backoff = Math.min(backoff * 2, maxBackoff);
      };
    };
    connect();
    return () => {
      stopped = true;
      window.clearTimeout(timer);
      ws?.close();
    };
  }, [enabled, qc]);

  return { events, connected };
}
