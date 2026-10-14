import { useMemo, useState } from "react";

import { GatePill, PageHeader, SeverityPill } from "../components";
import { Icon } from "../icons";
import { navigate } from "../router";
import {
  SCANNER_LABELS,
  SEVERITIES,
  SEVERITY_COLORS,
  SEVERITY_LABELS,
  countBySeverity,
  fileName,
  label,
} from "../ui";
import type { Severity } from "../ui";
import type { Workspace } from "../useWorkspace";

type Scope = "all" | "latest" | "blocking";

const PAGE_SIZE = 10;

export default function FindingsPage({ ws }: { ws: Workspace }) {
  const { findings, gate, latestBuild } = ws;

  const [scope, setScope] = useState<Scope>("all");
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [scanner, setScanner] = useState("all");
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [showScan, setShowScan] = useState(false);
  const [targetPath, setTargetPath] = useState("");

  // Si l'option choisie n'existe plus (ex : le gate vient de passer), on revient à "tout".
  const effectiveScope: Scope =
    (scope === "blocking" && (!gate || gate.passed)) ||
    (scope === "latest" && latestBuild === null)
      ? "all"
      : scope;

  // 1) portée + recherche + scanner (sert aussi à calculer les compteurs de sévérité)
  const scoped = useMemo(() => {
    const blockingIds = gate?.finding_ids ?? [];
    const q = query.trim().toLowerCase();

    return findings.filter((f) => {
      if (effectiveScope === "latest" && f.jenkins_build_number !== latestBuild) return false;
      if (effectiveScope === "blocking" && !blockingIds.includes(f.id)) return false;
      if (scanner !== "all" && f.scanner_name !== scanner) return false;

      if (q) {
        const haystack = `${f.title} ${f.vulnerability_id ?? ""} ${f.file_path ?? ""}`.toLowerCase();
        if (!haystack.includes(q)) return false;
      }
      return true;
    });
  }, [findings, effectiveScope, scanner, query, gate, latestBuild]);

  const counts = countBySeverity(scoped);

  // 2) filtre de sévérité + pagination
  const visible = scoped.filter((f) => severity === "all" || f.severity === severity);
  const pageCount = Math.max(1, Math.ceil(visible.length / PAGE_SIZE));
  const currentPage = Math.min(page, pageCount);
  const rows = visible.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);

  const scanners = Array.from(new Set(findings.map((f) => f.scanner_name)));

  function change<T>(setter: (value: T) => void, value: T) {
    setter(value);
    setPage(1);
  }

  function scan(scannerName: "trivy" | "semgrep" | "gitleaks") {
    if (!targetPath.trim()) {
      ws.setError("Indiquez le chemin du projet à scanner.");
      return;
    }
    ws.runScan(scannerName, targetPath.trim());
  }

  return (
    <>
      <PageHeader
        title={
          <>
            Findings
            {effectiveScope === "latest" && latestBuild !== null ? ` - Build #${latestBuild}` : ""}
          </>
        }
        subtitle={
          effectiveScope === "latest"
            ? "Liste des vulnérabilités détectées pour ce build"
            : "Liste des vulnérabilités détectées pour ce projet"
        }
        actions={
          <button type="button" className="btn btn-primary" onClick={() => setShowScan((v) => !v)}>
            <Icon name="refresh" size={15} /> Nouveau scan
          </button>
        }
      />

      {gate && (
        <section className={`gate-strip ${gate.passed ? "ok" : "ko"}`}>
          <div>
            <GatePill passed={gate.passed} />
            <span className="gate-text">
              Quality Gate{latestBuild !== null ? ` · build #${latestBuild}` : ""} : {gate.message}
            </span>
          </div>

          {!gate.passed && gate.finding_ids.length > 0 && (
            <button type="button" className="btn btn-dark btn-sm" onClick={() => change(setScope, "blocking")}>
              Voir les {gate.finding_ids.length} bloquant{gate.finding_ids.length > 1 ? "s" : ""}
            </button>
          )}
        </section>
      )}

      {showScan && (
        <section className="card scan-card">
          <h2 className="card-title">Lancer un nouveau scan</h2>
          <p className="muted">Indiquez le chemin local du projet puis choisissez un scanner.</p>

          <input
            className="mono-input"
            placeholder="C:/Users/.../mon-projet"
            value={targetPath}
            onChange={(e) => setTargetPath(e.target.value)}
          />

          <div className="btn-row">
            {(["trivy", "semgrep", "gitleaks"] as const).map((s) => (
              <button key={s} type="button" className="btn" disabled={ws.loading} onClick={() => scan(s)}>
                {SCANNER_LABELS[s]}
              </button>
            ))}
            <button type="button" className="btn btn-dark push-right" disabled={ws.loading} onClick={() => ws.runScoring()}>
              Recalculer les scores
            </button>
          </div>
        </section>
      )}

      <section className="filter-bar">
        <select value={effectiveScope} onChange={(e) => change(setScope, e.target.value as Scope)} aria-label="Portée">
          <option value="all">Tout l'historique</option>
          {latestBuild !== null && <option value="latest">Dernier build (#{latestBuild})</option>}
          {gate && !gate.passed && <option value="blocking">Bloquent le Quality Gate</option>}
        </select>

        <select value={severity} onChange={(e) => change(setSeverity, e.target.value as Severity | "all")} aria-label="Sévérité">
          <option value="all">Toutes les sévérités</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {SEVERITY_LABELS[s]}
            </option>
          ))}
        </select>

        <select value={scanner} onChange={(e) => change(setScanner, e.target.value)} aria-label="Scanner">
          <option value="all">Tous les scans</option>
          {scanners.map((s) => (
            <option key={s} value={s}>
              {label(SCANNER_LABELS, s)}
            </option>
          ))}
        </select>

        <div className="search-box">
          <Icon name="search" size={15} />
          <input
            placeholder="Rechercher..."
            value={query}
            onChange={(e) => change(setQuery, e.target.value)}
          />
        </div>
      </section>

      <section className="severity-row">
        {SEVERITIES.map((s) => (
          <button
            key={s}
            type="button"
            className={`severity-chip ${severity === s ? "active" : ""}`}
            onClick={() => change(setSeverity, severity === s ? "all" : s)}
          >
            <span className="chip-dot" style={{ background: SEVERITY_COLORS[s] }} />
            <span className="chip-label">{SEVERITY_LABELS[s]}</span>
            <strong>{counts[s]}</strong>
          </button>
        ))}
      </section>

      {ws.loading && <p className="muted">Chargement...</p>}

      <section className="card flush">
        <div className="table-wrap">
          <table className="table" id="findings-table">
            <thead>
              <tr>
                <th>#</th>
                <th>Titre</th>
                <th>Scanner</th>
                <th>Sévérité</th>
                <th>CVSS</th>
                <th>Fichier</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 ? (
                <tr>
                  <td colSpan={7} className="table-empty">
                    Aucune vulnérabilité ne correspond aux filtres.
                  </td>
                </tr>
              ) : (
                rows.map((f) => (
                  <tr key={f.id} className="clickable" onClick={() => navigate(`/findings/${f.id}`)}>
                    <td className="muted">{f.id}</td>
                    <td className="strong">{f.title}</td>
                    <td>{label(SCANNER_LABELS, f.scanner_name)}</td>
                    <td>
                      <SeverityPill severity={f.severity} />
                    </td>
                    <td>{f.cvss_score ?? "—"}</td>
                    <td className="muted" title={f.file_path ?? ""}>
                      {fileName(f.file_path)}
                    </td>
                    <td>
                      <button
                        type="button"
                        className="btn btn-outline btn-sm"
                        onClick={(e) => {
                          e.stopPropagation();
                          navigate(`/findings/${f.id}`);
                        }}
                      >
                        Voir
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        <div className="pagination">
          <span className="muted">
            {visible.length} résultat{visible.length > 1 ? "s" : ""}
          </span>

          <div className="pager">
            <button type="button" disabled={currentPage === 1} onClick={() => setPage(currentPage - 1)} aria-label="Page précédente">
              ‹
            </button>
            {Array.from({ length: pageCount }, (_, i) => i + 1).map((n) => (
              <button key={n} type="button" className={n === currentPage ? "active" : ""} onClick={() => setPage(n)}>
                {n}
              </button>
            ))}
            <button type="button" disabled={currentPage === pageCount} onClick={() => setPage(currentPage + 1)} aria-label="Page suivante">
              ›
            </button>
          </div>
        </div>
      </section>
    </>
  );
}
