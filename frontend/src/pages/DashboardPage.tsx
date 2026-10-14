import { DonutChart, LineChart } from "../charts";
import { GatePill, PageHeader, StatCard } from "../components";
import { Icon } from "../icons";
import {
  SEVERITIES,
  SEVERITY_COLORS,
  SEVERITY_LABELS,
  countBySeverity,
  formatDate,
  shortSha,
} from "../ui";
import type { Workspace } from "../useWorkspace";

const WEEK_MS = 7 * 24 * 60 * 60 * 1000;

export default function DashboardPage({ ws }: { ws: Workspace }) {
  const { builds, findings, gate, latestBuild } = ws;

  const buildsThisWeek = builds.filter(
    (b) => b.created_at && Date.now() - new Date(b.created_at).getTime() <= WEEK_MS
  ).length;

  const failed = builds.filter((b) => !b.passed).length;
  const failedPercent = builds.length > 0 ? Math.round((failed * 100) / builds.length) : 0;

  const counts = countBySeverity(findings);
  const segments = SEVERITIES.map((s) => ({
    label: SEVERITY_LABELS[s],
    value: counts[s],
    color: SEVERITY_COLORS[s],
  }));

  // Les 8 derniers builds, du plus ancien au plus récent (pour la courbe).
  const recent = [...builds].reverse().slice(-8);
  const labels = recent.map((b) => `#${b.build_number}`);
  const series = [
    {
      name: "Total findings",
      color: "#1f6feb",
      values: recent.map((b) => b.critical + b.high + b.medium + b.low),
    },
    { name: "Bloquantes", color: "#e5383b", values: recent.map((b) => b.blocking) },
  ];

  return (
    <>
      <PageHeader
        title="Tableau de bord"
        subtitle="Vue d'ensemble des builds et des vulnérabilités"
      />

      <section className="stats-row">
        <StatCard
          icon="layers"
          tone="blue"
          title="Total des builds"
          value={builds.length}
          hint={`+${buildsThisWeek} cette semaine`}
          hintTone="good"
        />
        <StatCard
          icon="x"
          tone="red"
          title="Builds en échec"
          value={failed}
          hint={`${failedPercent}% des builds`}
          hintTone={failed > 0 ? "bad" : "good"}
        />
        <StatCard
          icon="alert"
          tone="blue"
          title="Total des findings"
          value={findings.length}
          hint={`${counts.critical} critique${counts.critical > 1 ? "s" : ""}`}
          hintTone={counts.critical > 0 ? "bad" : "good"}
        />
        <StatCard
          icon="shield"
          tone="green"
          title="Quality Gate"
          value={gate ? <GatePill passed={gate.passed} /> : "—"}
          hint={latestBuild !== null ? `Dernier build : #${latestBuild}` : "Projet entier"}
        />
      </section>

      <section className="grid-2">
        <article className="card">
          <h2 className="card-title">Répartition des vulnérabilités</h2>
          <DonutChart segments={segments} />
        </article>

        <article className="card">
          <h2 className="card-title">Évolution des builds</h2>
          {recent.length === 0 ? (
            <p className="muted">
              Aucun build enregistré. Le Jenkinsfile enregistre chaque build à l'étape Quality Gate
              (paramètre <code>record=true</code>).
            </p>
          ) : (
            <LineChart labels={labels} series={series} />
          )}
        </article>
      </section>

      <section className="card">
        <h2 className="card-title">Derniers builds</h2>

        <div className="table-wrap">
          <table className="table" id="builds-table">
            <thead>
              <tr>
                <th>Build #</th>
                <th>Commit</th>
                <th>Date</th>
                <th>Findings (C / H / M / L)</th>
                <th>Quality Gate</th>
              </tr>
            </thead>
            <tbody>
              {builds.length === 0 ? (
                <tr>
                  <td colSpan={5} className="table-empty">
                    <Icon name="layers" size={16} /> Aucun build enregistré pour ce projet.
                  </td>
                </tr>
              ) : (
                builds.slice(0, 5).map((b) => (
                  <tr key={b.build_number}>
                    <td className="strong">#{b.build_number}</td>
                    <td className="mono">{shortSha(b.git_commit_sha)}</td>
                    <td>{formatDate(b.created_at)}</td>
                    <td>
                      {b.critical} / {b.high} / {b.medium} / {b.low}
                    </td>
                    <td>
                      <GatePill passed={b.passed} />
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}
