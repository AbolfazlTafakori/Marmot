import { useEffect, useMemo, useRef, useState } from 'react';
import type { Schemas } from '@/shared/api/client';
import { useI18n } from '@/shared/i18n/useI18n';
import { Td, Table } from '@/shared/ui';

type Point = Schemas['TrafficSeries']['points'][number];

const H = 200;
const pad = { top: 12, bottom: 22, start: 8, end: 64 };

/**
 * Received and sent bytes over time: two 2px lines on one axis, a legend,
 * end labels, a crosshair with a tooltip, and a table view. Colours are
 * dataviz palette slots 1 and 2 (validated for light and dark surfaces).
 * Time runs left to right in both languages, as on any time axis.
 */
export function TrafficChart({ points }: { points: Point[] }) {
  const { m, f, locale } = useI18n();
  // Axis text is Persian or English inside an LTR plot. Under RTL the
  // anchors swap, so text keeps its place and reads in the right order.
  const dir = locale === 'fa' ? 'rtl' : 'ltr';
  const leftEdge = dir === 'rtl' ? 'end' : 'start';
  const rightEdge = dir === 'rtl' ? 'start' : 'end';
  const [hover, setHover] = useState<number | null>(null);
  const [asTable, setAsTable] = useState(false);
  // Draw at the container's real width, so axis text keeps its size on a
  // phone instead of shrinking with a fixed viewBox.
  const box = useRef<HTMLDivElement>(null);
  const [W, setW] = useState(640);
  useEffect(() => {
    const el = box.current;
    if (!el || typeof ResizeObserver === 'undefined') return;
    const ro = new ResizeObserver(([e]) => {
      if (e) setW(Math.max(280, Math.round(e.contentRect.width)));
    });
    ro.observe(el);
    return () => {
      ro.disconnect();
    };
  }, [asTable]);

  const max = useMemo(() => Math.max(1, ...points.flatMap((p) => [p.bytesIn, p.bytesOut])), [points]);
  const total = points.reduce((s, p) => s + p.bytesIn + p.bytesOut, 0);
  if (points.length === 0 || total === 0)
    return <p className="py-8 text-center text-sm text-stone-500">{m.traffic.empty}</p>;

  const innerW = W - pad.start - pad.end;
  const innerH = H - pad.top - pad.bottom;
  const x = (i: number) =>
    pad.start + (points.length === 1 ? innerW / 2 : (i / (points.length - 1)) * innerW);
  const y = (v: number) => pad.top + innerH - (v / max) * innerH;
  const line = (key: 'bytesIn' | 'bytesOut') =>
    points.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(p[key]).toFixed(1)}`).join('');
  const last = points.length - 1;
  const lastPoint = points[last];
  const hp = hover === null ? undefined : points[hover];
  const series = [
    { key: 'bytesIn' as const, label: m.traffic.in, color: 'var(--series-in)' },
    { key: 'bytesOut' as const, label: m.traffic.out, color: 'var(--series-out)' },
  ];

  return (
    <div>
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2 text-xs">
        <ul className="flex gap-4" aria-label={m.traffic.title}>
          {series.map((s) => (
            <li key={s.key} className="flex items-center gap-1.5 text-stone-600 dark:text-stone-300">
              <span aria-hidden className="inline-block h-0.5 w-4 rounded" style={{ background: s.color }} />
              {s.label}
            </li>
          ))}
        </ul>
        <button
          type="button"
          className="text-sky-700 underline-offset-2 hover:underline dark:text-sky-400"
          onClick={() => {
            setAsTable(!asTable);
          }}
        >
          {asTable ? m.common.showChart : m.common.showTable}
        </button>
      </div>

      {asTable ? (
        <div className="max-h-72 overflow-y-auto">
          <Table head={[m.traffic.time, m.traffic.in, m.traffic.out]}>
            {points
              .filter((p) => p.bytesIn || p.bytesOut)
              .map((p) => (
                <tr key={p.t}>
                  <Td>{f.dateTime(p.t)}</Td>
                  <Td>{f.bytes(p.bytesIn)}</Td>
                  <Td>{f.bytes(p.bytesOut)}</Td>
                </tr>
              ))}
          </Table>
        </div>
      ) : (
        <div className="relative" dir="ltr" ref={box}>
          <svg
            viewBox={`0 0 ${W} ${H}`}
            width={W}
            height={H}
            className="block max-w-full"
            role="img"
            aria-label={`${m.traffic.title}: ${m.traffic.in} ${f.bytes(points.reduce((s, p) => s + p.bytesIn, 0))}, ${m.traffic.out} ${f.bytes(points.reduce((s, p) => s + p.bytesOut, 0))}`}
            onPointerLeave={() => {
              setHover(null);
            }}
            onPointerMove={(e) => {
              const r = e.currentTarget.getBoundingClientRect();
              const px = ((e.clientX - r.left) / r.width) * W;
              const i = Math.round(((px - pad.start) / innerW) * (points.length - 1));
              setHover(Math.min(last, Math.max(0, i)));
            }}
          >
            {[0, 0.5, 1].map((t) => (
              <g key={t}>
                <line
                  x1={pad.start}
                  x2={W - pad.end}
                  y1={y(max * t)}
                  y2={y(max * t)}
                  stroke="var(--chart-grid)"
                  strokeWidth={1}
                />
                <text
                  x={W - pad.end + 6}
                  y={y(max * t) + 4}
                  fontSize={11}
                  fill="var(--chart-text)"
                  direction={dir}
                  textAnchor={leftEdge}
                >
                  {f.bytes(max * t)}
                </text>
              </g>
            ))}
            {series.map((s) => (
              <path
                key={s.key}
                d={line(s.key)}
                fill="none"
                stroke={s.color}
                strokeWidth={2}
                strokeLinejoin="round"
                strokeLinecap="round"
              />
            ))}
            {lastPoint &&
              series.map((s) => (
                <circle
                  key={s.key}
                  cx={x(last)}
                  cy={y(lastPoint[s.key])}
                  r={4}
                  fill={s.color}
                  stroke="var(--chart-surface)"
                  strokeWidth={2}
                />
              ))}
            {hp && hover !== null && (
              <g>
                <line
                  x1={x(hover)}
                  x2={x(hover)}
                  y1={pad.top}
                  y2={pad.top + innerH}
                  stroke="var(--chart-text)"
                  strokeWidth={1}
                  opacity={0.4}
                />
                {series.map((s) => (
                  <circle
                    key={s.key}
                    cx={x(hover)}
                    cy={y(hp[s.key])}
                    r={4}
                    fill={s.color}
                    stroke="var(--chart-surface)"
                    strokeWidth={2}
                  />
                ))}
              </g>
            )}
            <text
              x={pad.start}
              y={H - 4}
              fontSize={11}
              fill="var(--chart-text)"
              direction={dir}
              textAnchor={leftEdge}
            >
              {points[0] ? f.time(points[0].t) : ''}
            </text>
            <text
              x={W - pad.end}
              y={H - 4}
              fontSize={11}
              fill="var(--chart-text)"
              direction={dir}
              textAnchor={rightEdge}
            >
              {lastPoint ? f.time(lastPoint.t) : ''}
            </text>
          </svg>
          {hp && hover !== null && (
            <div
              className="pointer-events-none absolute top-1 rounded-md border border-stone-200 bg-white px-2 py-1 text-xs shadow-sm dark:border-stone-700 dark:bg-stone-900"
              style={{ left: `${Math.min(70, (x(hover) / W) * 100)}%` }}
              dir="auto"
            >
              <p className="font-medium">{f.dateTime(hp.t)}</p>
              {series.map((s) => (
                <p key={s.key} className="flex items-center gap-1.5">
                  <span
                    aria-hidden
                    className="inline-block size-2 rounded-full"
                    style={{ background: s.color }}
                  />
                  {s.label}: {f.bytes(hp[s.key])}
                </p>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
