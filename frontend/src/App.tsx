import {
  Fragment,
  useEffect,
  useMemo,
  useState,
} from "react";

import type { FormEvent } from "react";

import { api } from "./api";

import type {
  Project,
  Finding,
  AIAnalysis,
} from "./types";

import "./App.css";

type SeverityFilter =
  | "all"
  | "critical"
  | "high"
  | "medium"
  | "low";

type ReviewFilter =
  | "all"
  | "non_analyse"
  | "en_attente"
  | "approuve"
  | "rejete";

function App() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] =
    useState<number | null>(null);

  const [findings, setFindings] = useState<Finding[]>([]);

  const [newProjectName, setNewProjectName] = useState("");
  const [newProjectRepo, setNewProjectRepo] = useState("");

  const [targetPath, setTargetPath] = useState("");

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [analyses, setAnalyses] =
    useState<Record<number, AIAnalysis>>({});

  const [expandedFindingId, setExpandedFindingId] =
    useState<number | null>(null);

  const [severityFilter, setSeverityFilter] =
    useState<SeverityFilter>("all");

  const [reviewFilter, setReviewFilter] =
    useState<ReviewFilter>("all");

  const [showScanPanel, setShowScanPanel] =
    useState(false);

  useEffect(() => {
    loadProjects();
  }, []);

  async function loadProjects() {
    try {
      setError(null);

      const data = await api.listProjects();

      setProjects(data);
    } catch (e) {
      setError(String(e));
    }
  }

  async function loadFindings(projectId: number) {
    setLoading(true);
    setError(null);

    try {
      const data = await api.listFindings(projectId);

      data.sort(
        (a, b) =>
          (b.priority_score ?? 0) -
          (a.priority_score ?? 0)
      );

      setFindings(data);

      await loadExistingAnalyses(data);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  async function loadExistingAnalyses(
    findingList: Finding[]
  ) {
    const existing: Record<number, AIAnalysis> = {};

    await Promise.all(
      findingList.map(async (finding) => {
        try {
          const history =
            await api.listAnalyses(finding.id);

          if (history.length > 0) {
            existing[finding.id] = history[0];
          }
        } catch {
          // Une erreur d'historique ne bloque pas
          // l'affichage des findings.
        }
      })
    );

    setAnalyses(existing);
  }

  function selectProject(id: number) {
    setSelectedProjectId(id);
    setAnalyses({});
    setExpandedFindingId(null);

    loadFindings(id);
  }

  async function handleCreateProject(
    e: FormEvent
  ) {
    e.preventDefault();

    if (!newProjectName.trim()) {
      setError("Le nom du projet est obligatoire.");
      return;
    }

    try {
      setError(null);

      const project =
        await api.createProject(
          newProjectName.trim(),
          newProjectRepo.trim()
        );

      setProjects((prev) => [
        ...prev,
        project,
      ]);

      setNewProjectName("");
      setNewProjectRepo("");

      selectProject(project.id);
    } catch (e) {
      setError(String(e));
    }
  }

  async function runScan(
    scanner:
      | "trivy"
      | "semgrep"
      | "gitleaks"
  ) {
    if (
      !selectedProjectId ||
      !targetPath.trim()
    ) {
      setError(
        "Choisissez un projet et indiquez un chemin à scanner."
      );

      return;
    }

    setLoading(true);
    setError(null);

    try {
      if (scanner === "trivy") {
        await api.scanTrivy(
          selectedProjectId,
          targetPath.trim()
        );
      }

      if (scanner === "semgrep") {
        await api.scanSemgrep(
          selectedProjectId,
          targetPath.trim()
        );
      }

      if (scanner === "gitleaks") {
        await api.scanGitleaks(
          selectedProjectId,
          targetPath.trim()
        );
      }

      await loadFindings(selectedProjectId);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  async function runScoring() {
    if (!selectedProjectId) {
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const scored =
        await api.scoreProject(
          selectedProjectId
        );

      scored.sort(
        (a, b) =>
          (b.priority_score ?? 0) -
          (a.priority_score ?? 0)
      );

      setFindings(scored);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  async function runAnalysis(
    findingId: number
  ) {
    setError(null);

    try {
      const result =
        await api.analyzeFinding(findingId);

      setAnalyses((prev) => ({
        ...prev,
        [findingId]: result,
      }));

      setExpandedFindingId(findingId);
    } catch (e) {
      setError(String(e));
    }
  }

  async function reviewAnalysis(
    analysis: AIAnalysis,
    humanStatus:
      | "approuve"
      | "rejete"
  ) {
    setError(null);

    try {
      const updated =
        await api.reviewAnalysis(
          analysis.id,
          {
            human_status: humanStatus,

            // Utilisateur de test actuel.
            // Plus tard : utilisateur authentifié.
            reviewed_by: 1,
          }
        );

      setAnalyses((prev) => ({
        ...prev,
        [analysis.finding_id]: updated,
      }));
    } catch (e) {
      setError(String(e));
    }
  }

  function getHumanStatusLabel(
    status: string
  ) {
    switch (status) {
      case "en_attente":
        return "En attente";

      case "approuve":
        return "Approuvée";

      case "rejete":
        return "Rejetée";

      default:
        return status;
    }
  }

  function getSeverityLabel(
    severity: string
  ) {
    switch (severity) {
      case "critical":
        return "Critique";

      case "high":
        return "Élevée";

      case "medium":
        return "Moyenne";

      case "low":
        return "Faible";

      default:
        return severity;
    }
  }

  function getVerdictLabel(
    verdict: string
  ) {
    switch (verdict) {
      case "vraie_menace":
        return "Vraie menace";

      case "faux_positif":
        return "Faux positif";

      case "incertain":
        return "Incertain";

      default:
        return verdict;
    }
  }

  function getPriorityLabel(
    priority: string | null
  ) {
    if (!priority) {
      return "Non définie";
    }

    switch (priority) {
      case "critique_confirmee":
        return "Critique confirmée";

      case "elevee":
        return "Élevée";

      case "moyenne":
        return "Moyenne";

      case "basse":
        return "Basse";

      default:
        return priority;
    }
  }

  const selectedProject = projects.find(
    (project) =>
      project.id === selectedProjectId
  );

  const statistics = useMemo(() => {
    const critical = findings.filter(
      (f) => f.severity === "critical"
    ).length;

    const scores = findings
      .map((f) => f.priority_score)
      .filter(
        (score): score is number =>
          score !== null
      );

    const averageScore =
      scores.length > 0
        ? scores.reduce(
            (sum, score) => sum + score,
            0
          ) / scores.length
        : 0;

    const analyzed = findings.filter(
      (f) => Boolean(analyses[f.id])
    ).length;

    const kev = findings.filter(
      (f) => f.in_kev
    ).length;

    return {
      critical,
      averageScore,
      analyzed,
      kev,
    };
  }, [findings, analyses]);

  const filteredFindings = useMemo(() => {
    return findings.filter((finding) => {
      const analysis = analyses[finding.id];

      const severityMatches =
        severityFilter === "all" ||
        finding.severity === severityFilter;

      let reviewMatches = true;

      if (reviewFilter === "non_analyse") {
        reviewMatches = !analysis;
      } else if (reviewFilter !== "all") {
        reviewMatches =
          analysis?.human_status ===
          reviewFilter;
      }

      return (
        severityMatches &&
        reviewMatches
      );
    });
  }, [
    findings,
    analyses,
    severityFilter,
    reviewFilter,
  ]);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">
            V
          </div>

          <span>VulnScan</span>
        </div>

        <nav className="main-nav">
          <a
            href="#findings"
            className="nav-item active"
          >
            <span className="nav-symbol">
              ◇
            </span>

            Findings
          </a>

          <a
            href="#dashboard"
            className="nav-item"
          >
            <span className="nav-symbol">
              ▦
            </span>

            Tableau de bord
          </a>

          <a
            href="#projects"
            className="nav-item"
          >
            <span className="nav-symbol">
              ⎇
            </span>

            Projets
          </a>
        </nav>

        <div
          className="sidebar-projects"
          id="projects"
        >
          <div className="sidebar-title">
            Projets
          </div>

          <div className="project-list">
            {projects.length === 0 ? (
              <p className="sidebar-empty">
                Aucun projet
              </p>
            ) : (
              projects.map((project) => (
                <button
                  type="button"
                  key={project.id}
                  className={`project-item ${
                    project.id ===
                    selectedProjectId
                      ? "active"
                      : ""
                  }`}
                  onClick={() =>
                    selectProject(
                      project.id
                    )
                  }
                >
                  <span className="project-dot" />

                  <span className="project-name">
                    {project.name}
                  </span>
                </button>
              ))
            )}
          </div>
        </div>

        <form
          className="new-project-form"
          onSubmit={handleCreateProject}
        >
          <div className="sidebar-title">
            Nouveau projet
          </div>

          <input
            type="text"
            placeholder="Nom du projet"
            value={newProjectName}
            onChange={(e) =>
              setNewProjectName(
                e.target.value
              )
            }
          />

          <input
            type="text"
            placeholder="URL du dépôt"
            value={newProjectRepo}
            onChange={(e) =>
              setNewProjectRepo(
                e.target.value
              )
            }
          />

          <button type="submit">
            + Créer un projet
          </button>
        </form>
      </aside>

      <main className="main-content">
        {error && (
          <div className="error-banner">
            <span>!</span>
            {error}
          </div>
        )}

        {!selectedProjectId ? (
          <section className="welcome-card">
            <div className="welcome-icon">
              ◇
            </div>

            <h1>Bienvenue dans VulnScan</h1>

            <p>
              Sélectionnez un projet dans la
              barre latérale ou créez-en un
              nouveau pour commencer.
            </p>
          </section>
        ) : (
          <>
            <header
              className="page-header"
              id="findings"
            >
              <div>
                <p className="page-eyebrow">
                  Gestion des vulnérabilités
                </p>

                <h1>
                  Findings
                  <span className="project-separator">
                    —
                  </span>
                  <span className="current-project">
                    {selectedProject?.name}
                  </span>
                </h1>

                {selectedProject?.repository_url && (
                  <p className="repository-url">
                    {
                      selectedProject.repository_url
                    }
                  </p>
                )}
              </div>

              <button
                type="button"
                className="rescan-button"
                onClick={() =>
                  setShowScanPanel(
                    (previous) =>
                      !previous
                  )
                }
              >
                <span className="refresh-icon">
                  ↻
                </span>

                Relancer un scan
              </button>
            </header>

            <section
              className="stats-grid"
              id="dashboard"
            >
              <article className="stat-card">
                <p>Critiques ouvertes</p>

                <strong className="critical-number">
                  {statistics.critical}
                </strong>
              </article>

              <article className="stat-card">
                <p>Score moyen</p>

                <strong>
                  {statistics.averageScore.toFixed(
                    1
                  )}
                </strong>
              </article>

              <article className="stat-card">
                <p>Analysés par IA</p>

                <strong>
                  {statistics.analyzed}
                  <span className="stat-total">
                    /{findings.length}
                  </span>
                </strong>
              </article>

              <article className="stat-card">
                <p>Présents dans KEV</p>

                <strong>
                  {statistics.kev}
                </strong>
              </article>
            </section>

            {showScanPanel && (
              <section className="scan-panel">
                <div className="scan-panel-header">
                  <div>
                    <h2>
                      Lancer un nouveau scan
                    </h2>

                    <p>
                      Indiquez le chemin local du
                      projet puis choisissez un
                      scanner.
                    </p>
                  </div>
                </div>

                <div className="scan-path-row">
                  <input
                    className="target-path-input"
                    type="text"
                    placeholder="C:/Users/.../mon-projet"
                    value={targetPath}
                    onChange={(e) =>
                      setTargetPath(
                        e.target.value
                      )
                    }
                  />
                </div>

                <div className="scanner-buttons">
                  <button
                    type="button"
                    onClick={() =>
                      runScan("trivy")
                    }
                    disabled={loading}
                  >
                    Trivy
                  </button>

                  <button
                    type="button"
                    onClick={() =>
                      runScan("semgrep")
                    }
                    disabled={loading}
                  >
                    Semgrep
                  </button>

                  <button
                    type="button"
                    onClick={() =>
                      runScan("gitleaks")
                    }
                    disabled={loading}
                  >
                    Gitleaks
                  </button>

                  <button
                    type="button"
                    className="score-action"
                    onClick={runScoring}
                    disabled={loading}
                  >
                    Recalculer les scores
                  </button>
                </div>
              </section>
            )}

            <section className="findings-section">
              <div className="filters-row">
                <select
                  value={severityFilter}
                  onChange={(e) =>
                    setSeverityFilter(
                      e.target
                        .value as SeverityFilter
                    )
                  }
                >
                  <option value="all">
                    Toutes sévérités
                  </option>

                  <option value="critical">
                    Critique
                  </option>

                  <option value="high">
                    Élevée
                  </option>

                  <option value="medium">
                    Moyenne
                  </option>

                  <option value="low">
                    Faible
                  </option>
                </select>

                <select
                  value={reviewFilter}
                  onChange={(e) =>
                    setReviewFilter(
                      e.target
                        .value as ReviewFilter
                    )
                  }
                >
                  <option value="all">
                    Tous statuts
                  </option>

                  <option value="non_analyse">
                    Non analysé
                  </option>

                  <option value="en_attente">
                    En attente
                  </option>

                  <option value="approuve">
                    Approuvé
                  </option>

                  <option value="rejete">
                    Rejeté
                  </option>
                </select>

                <div className="results-count">
                  {filteredFindings.length} résultat
                  {filteredFindings.length > 1
                    ? "s"
                    : ""}
                </div>
              </div>

              {loading && (
                <div className="loading-bar">
                  Chargement...
                </div>
              )}

              <div className="table-wrapper">
                <table className="findings-table">
                  <thead>
                    <tr>
                      <th>
                        Sévérité
                        <br />
                        <span>Score</span>
                      </th>

                      <th>Vulnérabilité</th>

                      <th>Source</th>

                      <th>CVSS / EPSS</th>

                      <th>Statut IA</th>

                      <th>Revue</th>

                      <th />
                    </tr>
                  </thead>

                  <tbody>
                    {filteredFindings.length ===
                    0 ? (
                      <tr>
                        <td
                          colSpan={7}
                          className="empty-table"
                        >
                          Aucune vulnérabilité ne
                          correspond aux filtres.
                        </td>
                      </tr>
                    ) : (
                      filteredFindings.map(
                        (finding) => {
                          const analysis =
                            analyses[
                              finding.id
                            ];

                          const isExpanded =
                            expandedFindingId ===
                            finding.id;

                          return (
                            <Fragment
                              key={
                                finding.id
                              }
                            >
                              <tr
                                className={`finding-row ${
                                  isExpanded
                                    ? "expanded"
                                    : ""
                                }`}
                                onClick={() =>
                                  setExpandedFindingId(
                                    isExpanded
                                      ? null
                                      : finding.id
                                  )
                                }
                              >
                                <td>
                                  <span
                                    className={`risk-badge severity-${finding.severity}`}
                                  >
                                    <strong>
                                      {finding.priority_score ??
                                        "—"}
                                    </strong>

                                    <span>
                                      {getSeverityLabel(
                                        finding.severity
                                      )}
                                    </span>
                                  </span>
                                </td>

                                <td className="finding-title-cell">
                                  <div className="finding-title">
                                    {
                                      finding.title
                                    }
                                  </div>

                                  {finding.vulnerability_id && (
                                    <div className="finding-id">
                                      {
                                        finding.vulnerability_id
                                      }
                                    </div>
                                  )}

                                  {finding.file_path && (
                                    <div className="finding-file">
                                      {
                                        finding.file_path
                                      }
                                    </div>
                                  )}
                                </td>

                                <td>
                                  <span className="scanner-name">
                                    {
                                      finding.scanner_name
                                    }
                                  </span>
                                </td>

                                <td>
                                  <div className="metric-stack">
                                    <span>
                                      CVSS{" "}
                                      <strong>
                                        {finding.cvss_score ??
                                          "—"}
                                      </strong>
                                    </span>

                                    <span>
                                      EPSS{" "}
                                      <strong>
                                        {finding.epss_score !==
                                        null
                                          ? `${(
                                              finding.epss_score *
                                              100
                                            ).toFixed(
                                              2
                                            )}%`
                                          : "—"}
                                      </strong>
                                    </span>
                                  </div>
                                </td>

                                <td>
                                  {analysis ? (
                                    <span
                                      className={`verdict-small verdict-${analysis.ai_verdict}`}
                                    >
                                      {getVerdictLabel(
                                        analysis.ai_verdict
                                      )}
                                    </span>
                                  ) : (
                                    <span className="neutral-label">
                                      Non analysé
                                    </span>
                                  )}
                                </td>

                                <td>
                                  {analysis ? (
                                    <span
                                      className={`review-status review-${analysis.human_status}`}
                                    >
                                      {getHumanStatusLabel(
                                        analysis.human_status
                                      )}
                                    </span>
                                  ) : (
                                    <span className="neutral-label">
                                      —
                                    </span>
                                  )}
                                </td>

                                <td className="action-cell">
                                  <button
                                    type="button"
                                    className="analyze-button"
                                    onClick={(
                                      e
                                    ) => {
                                      e.stopPropagation();

                                      runAnalysis(
                                        finding.id
                                      );
                                    }}
                                    disabled={
                                      loading
                                    }
                                  >
                                    {analysis
                                      ? "Ré-analyser"
                                      : "Analyser"}
                                  </button>

                                  <button
                                    type="button"
                                    className="expand-button"
                                    aria-label="Afficher le détail"
                                    onClick={(
                                      e
                                    ) => {
                                      e.stopPropagation();

                                      setExpandedFindingId(
                                        isExpanded
                                          ? null
                                          : finding.id
                                      );
                                    }}
                                  >
                                    {isExpanded
                                      ? "⌃"
                                      : "⌄"}
                                  </button>
                                </td>
                              </tr>

                              {isExpanded && (
                                <tr className="detail-row">
                                  <td
                                    colSpan={7}
                                  >
                                    {!analysis ? (
                                      <div className="no-analysis">
                                        <div>
                                          <h3>
                                            Analyse IA
                                          </h3>

                                          <p>
                                            Cette
                                            vulnérabilité
                                            n'a pas encore
                                            été analysée
                                            par l'IA.
                                          </p>
                                        </div>

                                        <button
                                          type="button"
                                          onClick={() =>
                                            runAnalysis(
                                              finding.id
                                            )
                                          }
                                        >
                                          Lancer
                                          l'analyse IA
                                        </button>
                                      </div>
                                    ) : (
                                      <div className="analysis-panel">
                                        <div className="analysis-top">
                                          <div>
                                            <p className="analysis-eyebrow">
                                              Analyse IA
                                            </p>

                                            <h3>
                                              {getVerdictLabel(
                                                analysis.ai_verdict
                                              )}
                                            </h3>
                                          </div>

                                          <div className="analysis-tags">
                                            <span
                                              className={`verdict-large verdict-${analysis.ai_verdict}`}
                                            >
                                              {getVerdictLabel(
                                                analysis.ai_verdict
                                              )}
                                            </span>

                                            <span
                                              className={`review-status review-${analysis.human_status}`}
                                            >
                                              {getHumanStatusLabel(
                                                analysis.human_status
                                              )}
                                            </span>
                                          </div>
                                        </div>

                                        <div className="analysis-grid">
                                          <div className="analysis-main">
                                            <section className="analysis-block">
                                              <h4>
                                                Raisonnement
                                              </h4>

                                              <p>
                                                {
                                                  analysis.ai_reasoning
                                                }
                                              </p>
                                            </section>

                                            {analysis.ai_suggested_fix && (
                                              <section className="analysis-block fix-block">
                                                <h4>
                                                  Correctif
                                                  suggéré
                                                </h4>

                                                <p>
                                                  {
                                                    analysis.ai_suggested_fix
                                                  }
                                                </p>
                                              </section>
                                            )}
                                          </div>

                                          <aside className="analysis-side">
                                            <div className="analysis-info">
                                              <span>
                                                Priorité
                                                ajustée
                                              </span>

                                              <strong>
                                                {getPriorityLabel(
                                                  analysis.ai_adjusted_priority
                                                )}
                                              </strong>
                                            </div>

                                            <div className="analysis-info">
                                              <span>
                                                Modèle
                                              </span>

                                              <strong>
                                                {
                                                  analysis.ai_model_name
                                                }
                                              </strong>

                                              <small>
                                                {
                                                  analysis.llm_provider
                                                }
                                              </small>
                                            </div>

                                            {finding.in_kev && (
                                              <div className="kev-alert">
                                                Présente dans
                                                le catalogue
                                                KEV
                                              </div>
                                            )}

                                            {finding.fix_available && (
                                              <div className="fix-available">
                                                Correctif
                                                disponible
                                              </div>
                                            )}
                                          </aside>
                                        </div>

                                        <div className="human-review">
                                          <div>
                                            <h4>
                                              Validation
                                              humaine
                                            </h4>

                                            {analysis.human_status ===
                                              "en_attente" && (
                                              <p>
                                                Cette
                                                analyse doit
                                                être vérifiée
                                                par un
                                                utilisateur.
                                              </p>
                                            )}

                                            {analysis.human_status ===
                                              "approuve" && (
                                              <p className="approved-text">
                                                ✓ Analyse
                                                approuvée
                                                {analysis.reviewed_by !==
                                                  null &&
                                                  ` par l'utilisateur #${analysis.reviewed_by}`}
                                              </p>
                                            )}

                                            {analysis.human_status ===
                                              "rejete" && (
                                              <p className="rejected-text">
                                                ✕ Analyse
                                                rejetée
                                                {analysis.reviewed_by !==
                                                  null &&
                                                  ` par l'utilisateur #${analysis.reviewed_by}`}
                                              </p>
                                            )}
                                          </div>

                                          {analysis.human_status ===
                                            "en_attente" && (
                                            <div className="review-actions">
                                              <button
                                                type="button"
                                                className="approve-button"
                                                onClick={() =>
                                                  reviewAnalysis(
                                                    analysis,
                                                    "approuve"
                                                  )
                                                }
                                              >
                                                ✓
                                                Approuver
                                              </button>

                                              <button
                                                type="button"
                                                className="reject-button"
                                                onClick={() =>
                                                  reviewAnalysis(
                                                    analysis,
                                                    "rejete"
                                                  )
                                                }
                                              >
                                                ✕ Rejeter
                                              </button>
                                            </div>
                                          )}
                                        </div>
                                      </div>
                                    )}
                                  </td>
                                </tr>
                              )}
                            </Fragment>
                          );
                        }
                      )
                    )}
                  </tbody>
                </table>
              </div>
            </section>
          </>
        )}
      </main>
    </div>
  );
}

export default App;