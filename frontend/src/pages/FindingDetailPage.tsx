import { useState } from "react";

import { EmptyState, ReviewPill, SeverityPill, Tabs, VerdictPill } from "../components";
import { Icon } from "../icons";
import { navigate } from "../router";
import {
  PRIORITY_LABELS,
  SCANNER_LABELS,
  STATUS_LABELS,
  fileName,
  formatDate,
  label,
  shortSha,
} from "../ui";
import type { AnalysisDetail, Finding } from "../types";
import type { Workspace } from "../useWorkspace";

function YesNo({ value }: { value: boolean }) {
  return <span className={`soft-pill ${value ? "yes" : "no"}`}>{value ? "Oui" : "Non"}</span>;
}

function CodeBlock({ code, startLine }: { code: string; startLine: number }) {
  const lines = code.replace(/\n$/, "").split("\n");

  return (
    <pre className="code-block" aria-label="Extrait de code">
      {lines.map((line, i) => (
        <div key={i} className="code-line">
          <span className="code-no">{startLine + i}</span>
          <code>{line || " "}</code>
        </div>
      ))}
    </pre>
  );
}

function AnalysisView({
  analysis,
  finding,
  ws,
  canReview,
}: {
  analysis: AnalysisDetail | undefined;
  finding: Finding;
  ws: Workspace;
  canReview: boolean;
}) {
  if (!analysis) {
    return (
      <section className="card">
        <EmptyState
          title="Aucune analyse IA"
          text="Cette vulnérabilité n'a pas encore été analysée par l'IA."
          action={
            <button type="button" className="btn btn-primary" disabled={ws.loading} onClick={() => ws.analyze(finding.id)}>
              Lancer l'analyse IA
            </button>
          }
        />
      </section>
    );
  }

  const reviewer = analysis.reviewed_by !== null
    ? ws.userNames[analysis.reviewed_by] ?? `l'utilisateur #${analysis.reviewed_by}`
    : null;

  return (
    <section className="card">
      <div className="analysis-head">
        <div>
          <p className="eyebrow">Analyse IA #{analysis.id}</p>
          <h2 className="card-title">Verdict de l'IA</h2>
        </div>
        <div className="tag-row">
          <VerdictPill verdict={analysis.ai_verdict} />
          <ReviewPill status={analysis.human_status} />
        </div>
      </div>

      <div className="analysis-cols">
        <div>
          <h3 className="mini-title">Raisonnement</h3>
          <p className="prose">{analysis.ai_reasoning}</p>

          {analysis.ai_suggested_fix && (
            <div className="fix-box">
              <h3 className="mini-title">Correctif suggéré</h3>
              <p className="prose">{analysis.ai_suggested_fix}</p>
            </div>
          )}
        </div>

        <aside className="info-stack">
          <div className="info-tile">
            <span>Priorité ajustée</span>
            <strong>
              {analysis.ai_adjusted_priority ? label(PRIORITY_LABELS, analysis.ai_adjusted_priority) : "Non définie"}
            </strong>
          </div>
          <div className="info-tile">
            <span>Modèle</span>
            <strong>{analysis.ai_model_name}</strong>
            <small>{analysis.llm_provider}</small>
          </div>
          <div className="info-tile">
            <span>Date</span>
            <strong>{formatDate(analysis.created_at)}</strong>
          </div>
        </aside>
      </div>

      <div className="review-box">
        <div>
          <h3 className="mini-title">Validation humaine</h3>
          {analysis.human_status === "en_attente" && <p className="muted">Cette analyse doit être vérifiée par un utilisateur.</p>}
          {analysis.human_status === "approuve" && <p className="text-ok">✓ Analyse approuvée{reviewer ? ` par ${reviewer}` : ""}</p>}
          {analysis.human_status === "rejete" && <p className="text-bad">✕ Analyse rejetée{reviewer ? ` par ${reviewer}` : ""}</p>}
        </div>

        {analysis.human_status === "en_attente" && canReview && (
          <div className="btn-row">
            <button type="button" className="btn btn-ok" onClick={() => ws.review(analysis.id, "approuve")}>
              <Icon name="check" size={15} /> Approuver
            </button>
            <button type="button" className="btn btn-bad" onClick={() => ws.review(analysis.id, "rejete")}>
              <Icon name="x" size={15} /> Rejeter
            </button>
          </div>
        )}
      </div>
    </section>
  );
}

export default function FindingDetailPage({
  ws,
  findingId,
  canReview,
}: {
  ws: Workspace;
  findingId: number;
  canReview: boolean;
}) {
  const [tab, setTab] = useState("details");
  const finding = ws.findings.find((f) => f.id === findingId);
  const history = ws.analyses.filter((a) => a.finding_id === findingId);
  const analysis = ws.latestAnalysis[findingId];

  const back = (
    <button type="button" className="btn btn-outline btn-sm" onClick={() => navigate("/findings")}>
      <Icon name="arrowLeft" size={14} /> Retour
    </button>
  );

  if (!finding) {
    return (
      <>
        {back}
        <section className="card" style={{ marginTop: 16 }}>
          <EmptyState title={ws.loading ? "Chargement..." : "Vulnérabilité introuvable"} />
        </section>
      </>
    );
  }

  const fixed = finding.status === "fixed" || finding.status === "false_positive" || finding.status === "accepted_risk";

  return (
    <>
      <p className="breadcrumb">Finding #{finding.id}</p>
      {back}

      <header className="detail-head">
        <SeverityPill severity={finding.severity} />
        <div>
          <h1>{finding.title}</h1>
          <p className="meta-line">
            Scanner : {label(SCANNER_LABELS, finding.scanner_name)}
            <span className="sep">|</span>
            CVSS : {finding.cvss_score ?? "—"}
            <span className="sep">|</span>
            Statut : <span className={fixed ? "text-ok" : "text-bad"}>{label(STATUS_LABELS, finding.status)}</span>
          </p>
        </div>
      </header>

      <Tabs
        tabs={[
          { id: "details", label: "Détails" },
          { id: "analysis", label: "Analyse IA" },
          { id: "history", label: "Historique", badge: history.length },
        ]}
        active={tab}
        onChange={setTab}
      />

      {tab === "details" && (
        <>
          <section className="grid-2 detail-grid">
            <article className="card">
              <h2 className="card-title">Informations générales</h2>
              <dl className="kv">
                <dt>ID</dt><dd>{finding.id}</dd>
                <dt>Vulnérabilité ID</dt><dd>{finding.vulnerability_id ?? "—"}</dd>
                <dt>Fichier</dt><dd>{fileName(finding.file_path)}</dd>
                <dt>Chemin complet</dt><dd className="break">{finding.file_path ?? "—"}</dd>
                <dt>Sévérité</dt><dd><SeverityPill severity={finding.severity} /></dd>
                <dt>CVSS Score</dt><dd>{finding.cvss_score ?? "—"}</dd>
                <dt>EPSS Score</dt><dd>{finding.epss_score !== null ? `${(finding.epss_score * 100).toFixed(2)}%` : "—"}</dd>
                <dt>In KEV</dt><dd><YesNo value={finding.in_kev} /></dd>
                <dt>Exposé</dt><dd><YesNo value={finding.is_exposed} /></dd>
                <dt>Priority Score</dt><dd>{finding.priority_score ?? "—"}</dd>
                <dt>Correctif disponible</dt><dd><YesNo value={finding.fix_available} /></dd>
                <dt>Vu au build</dt>
                <dd>
                  {finding.jenkins_build_number !== null && finding.jenkins_build_number !== undefined
                    ? `#${finding.jenkins_build_number} · ${shortSha(finding.git_commit_sha)}`
                    : "—"}
                </dd>
              </dl>
            </article>

            <article className="card">
              <h2 className="card-title">Extrait de code</h2>
              {finding.code_snippet ? (
                <CodeBlock code={finding.code_snippet} startLine={finding.line_number ?? 1} />
              ) : (
                <p className="muted">Aucun extrait de code pour ce type de vulnérabilité.</p>
              )}
            </article>
          </section>

          {finding.description && (
            <section className="card">
              <h2 className="card-title">Description</h2>
              <p className="prose">{finding.description}</p>
            </section>
          )}

          <section className="card ai-summary">
            <div>
              <h2 className="card-title">Analyse IA</h2>
              {analysis ? (
                <div className="tag-row">
                  <VerdictPill verdict={analysis.ai_verdict} />
                  <ReviewPill status={analysis.human_status} />
                </div>
              ) : (
                <p className="muted">Pas encore analysée.</p>
              )}
            </div>
            <button type="button" className="btn btn-primary" onClick={() => setTab("analysis")}>
              {analysis ? "Voir l'analyse complète" : "Analyser"}
            </button>
          </section>
        </>
      )}

      {tab === "analysis" && <AnalysisView analysis={analysis} finding={finding} ws={ws} canReview={canReview} />}

      {tab === "history" && (
        <section className="card">
          <h2 className="card-title">Historique des analyses</h2>
          {history.length === 0 ? (
            <p className="muted">Aucune analyse pour cette vulnérabilité.</p>
          ) : (
            <ul className="timeline">
              {history.map((a) => (
                <li key={a.id}>
                  <span className="timeline-dot" />
                  <div>
                    <strong>Analyse IA #{a.id}</strong>
                    <span className="muted"> · {formatDate(a.created_at)} · {a.ai_model_name}</span>
                    <div className="tag-row" style={{ marginTop: 6 }}>
                      <VerdictPill verdict={a.ai_verdict} />
                      <ReviewPill status={a.human_status} />
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </section>
      )}
    </>
  );
}