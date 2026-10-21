export interface DonutSegment {
  label: string;
  value: number;
  color: string;
}

/** Anneau de répartition (SVG pur, sans bibliothèque). */
export function DonutChart({ segments }: { segments: DonutSegment[] }) {
  const total = segments.reduce((sum, s) => sum + s.value, 0);
  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  let offset = 0;

  return (
    <div className="donut-wrap">
      <svg viewBox="0 0 140 140" className="donut" role="img" aria-label="Répartition des vulnérabilités">
        <circle cx="70" cy="70" r={radius} fill="none" style={{ stroke: "var(--line)" }} strokeWidth="18" />
        {total > 0 &&
          segments
            .filter((s) => s.value > 0)
            .map((s) => {
              const length = (s.value / total) * circumference;
              const circle = (
                <circle
                  key={s.label}
                  cx="70"
                  cy="70"
                  r={radius}
                  fill="none"
                  stroke={s.color}
                  strokeWidth="18"
                  strokeDasharray={`${length} ${circumference - length}`}
                  strokeDashoffset={-offset}
                  transform="rotate(-90 70 70)"
                />
              );
              offset += length;
              return circle;
            })}
        <text x="70" y="68" textAnchor="middle" className="donut-total">{total}</text>
        <text x="70" y="84" textAnchor="middle" className="donut-caption">Total findings</text>
      </svg>

      <ul className="legend">
        {segments.map((s) => (
          <li key={s.label}>
            <span className="dot" style={{ background: s.color }} />
            <span className="legend-label">{s.label}</span>
            <span className="legend-value">
              {s.value} ({total > 0 ? ((s.value / total) * 100).toFixed(1) : "0.0"}%)
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export interface LineSeries {
  name: string;
  color: string;
  values: number[];
}

/** Échelle à repères ronds (0, 10, 20, 30...) : au plus 5 intervalles. */
function niceScale(value: number): { max: number; count: number } {
  const steps = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000];
  const step = steps.find((s) => Math.ceil(value / s) <= 5) ?? 1000;
  const count = Math.max(2, Math.ceil(value / step));
  return { max: step * count, count };
}

/** Courbes d'évolution (SVG pur). */
export function LineChart({ labels, series }: { labels: string[]; series: LineSeries[] }) {
  const width = 440;
  const height = 210;
  const left = 34;
  const right = 12;
  const top = 14;
  const bottom = 28;
  const plotW = width - left - right;
  const plotH = height - top - bottom;

  const scale = niceScale(Math.max(1, ...series.flatMap((s) => s.values)));
  const yMax = scale.max;
  const x = (i: number) =>
    left + (labels.length <= 1 ? plotW / 2 : (i * plotW) / (labels.length - 1));
  const y = (v: number) => top + plotH - (v / yMax) * plotH;
  const ticks = Array.from({ length: scale.count + 1 }, (_, i) => i / scale.count);

  return (
    <div>
      <div className="chart-legend">
        {series.map((s) => (
          <span key={s.name}>
            <span className="dot" style={{ background: s.color }} />
            {s.name}
          </span>
        ))}
      </div>

      <svg viewBox={`0 0 ${width} ${height}`} className="line-chart" role="img" aria-label="Évolution des builds">
        {ticks.map((t) => (
          <g key={t}>
            <line x1={left} x2={width - right} y1={y(t * yMax)} y2={y(t * yMax)} style={{ stroke: "var(--line)" }} />
            <text x={left - 6} y={y(t * yMax) + 3} textAnchor="end" className="axis">
              {Math.round(t * yMax)}
            </text>
          </g>
        ))}

        {labels.map((l, i) => (
          <text key={l} x={x(i)} y={height - 8} textAnchor="middle" className="axis">
            {l}
          </text>
        ))}

        {series.map((s) => (
          <g key={s.name}>
            <polyline
              fill="none"
              stroke={s.color}
              strokeWidth="2.2"
              points={s.values.map((v, i) => `${x(i)},${y(v)}`).join(" ")}
            />
            {s.values.map((v, i) => (
              <circle key={i} cx={x(i)} cy={y(v)} r="3.4" fill="#fff" stroke={s.color} strokeWidth="2" />
            ))}
          </g>
        ))}
      </svg>
    </div>
  );
}