import { useState } from "react";

import { EmptyState, PageHeader, ReviewPill, SeverityPill, Tabs, VerdictPill } from "../components";
import { Icon } from "../icons";
import { navigate } from "../router";
import { PRIORITY_LABELS, formatDate, label } from "../ui";
import type { Workspace } from "../useWorkspace";

export default function AnalysesPage({
  ws,
  initialTab,
  canReview,
}: {
  ws: Workspace;
  initialTab: "all" | "pending";
  canReview: boolean;
}) {
  const [tab, setTab] = useState<string>(initialTab);

  // "À valider" : la DERNIÈRE analyse de chaque vulnérabilité, si elle attend un humain.
  const pending = ws.analyses.filter(
    (a) => ws.latestAnalysis[a.finding_id]?.id === a.id && a.human_status === "en_attente"
  );

  const list = tab === "pending" ? pending : ws.analyses;

  return (
    <>
      <PageHeader title="Analyses IA" subtitle="Historique et validation des analyses IA" />

      <Tabs
        tabs={[
          { id: "all", label: "Dernières analyses" },
          { id: "pending", label: "Validation humaine", badge: pending.length },
        ]}
        active={tab}
        onChange={setTab}
      />

      {list.length === 0 ? (
        <section className="card">
          <EmptyState
            title={tab === "pending" ? "Rien à valider" : "Aucune analyse"}
            text={
              tab === "pending"
                ? "Toutes les analyses ont été traitées par un humain."
                : "Lancez une analyse depuis la fiche d'une vulnérabilité."
            }
          />
        </section>
      ) : (
        <ol className="analysis-list">
          {list.map((a) => (
            <li key={a.id} className="card analysis-item">
              <span className="timeline-dot big" />

              <div className="analysis-body">
                <div className="analysis-line">
                  <strong>Analyse IA #{a.id}</strong>
                  <ReviewPill status={a.human_status} />
                </div>

                <button type="button" className="link" onClick={() => navigate(`/findings/${a.finding_id}`)}>
                  {a.finding_title}
                </button>

                <p className="muted small">
                  {formatDate(a.created_at)} · {a.ai_model_name} ({a.llm_provider})
                </p>

                <div className="tag-row">
                  <SeverityPill severity={a.finding_severity} />
                  <VerdictPill verdict={a.ai_verdict} />
                  {a.ai_adjusted_priority && (
                    <span className="soft-pill neutral">
                      Priorité ajustée : {label(PRIORITY_LABELS, a.ai_adjusted_priority)}
                    </span>
                  )}
                </div>

                <p className="excerpt">{a.ai_reasoning}</p>
              </div>

              <div className="analysis-actions">
                {a.human_status === "en_attente" && canReview ? (
                  <>
                    <button type="button" className="btn btn-ok btn-sm" onClick={() => ws.review(a.id, "approuve")}>
                      <Icon name="check" size={14} /> Approuver
                    </button>
                    <button type="button" className="btn btn-bad btn-sm" onClick={() => ws.review(a.id, "rejete")}>
                      <Icon name="x" size={14} /> Rejeter
                    </button>
                  </>
                ) : (
                  <button type="button" className="btn btn-outline btn-sm" onClick={() => navigate(`/findings/${a.finding_id}`)}>
                    Voir détail
                  </button>
                )}
              </div>
            </li>
          ))}
        </ol>
      )}
    </>
  );
}