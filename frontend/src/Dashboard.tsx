import { Fragment, useEffect, useMemo, useState } from "react";
import type { FormEvent } from "react";

import { api, errorMessage } from "./api";
import type {
  Project,
  Finding,
  AIAnalysis,
  User,
  QualityGateResult,
} from "./types";

type SeverityFilter = "all" | "critical" | "high" | "medium" | "low";
type ReviewFilter = "all" | "non_analyse" | "en_attente" | "approuve" | "rejete";
type ScopeFilter = "all" | "latest" | "blocking";

/**
 * Seuils du Quality Gate affichés dans l'interface.
 * À garder identiques aux paramètres du Jenkinsfile (MAX_CRITICAL / MAX_HIGH).
 */
const GATE_MAX_CRITICAL = 0;
const GATE_MAX_HIGH = 5;

const HUMAN_STATUS_LABELS: Record<string, string> = {
  en_attente: "En attente",
  approuve: "Approuvée",
  rejete: "Rejetée",
};

const SEVERITY_LABELS: Record<string, string> = {
  critical: "Critique",
  high: "Élevée",
  medium: "Moyenne",
  low: "Faible",
};

const VERDICT_LABELS: Record<string, string> = {
  vraie_menace: "Vraie menace",
  faux_positif: "Faux positif",
  incertain: "Incertain",
};

const PRIORITY_LABELS: Record<string, string> = {
  critique_confirmee: "Critique confirmée",
  elevee: "Élevée",
  moyenne: "Moyenne",
  basse: "Basse",
};

const label = (labels: Record<string, string>, key: string) => labels[key] ?? key;

interface DashboardProps {
  user: User;
  onLogout: () => void;
}

function Dashboard({ user, onLogout }: DashboardProps) {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<number | null>(null);

  const [findings, setFindings] = useState<Finding[]>([]);
  const [analyses, setAnalyses] = useState<Record<number, AIAnalysis>>({});
  const [userNames, setUserNames] = useState<Record<number, string>>({});
  const [gate, setGate] = useState<QualityGateResult | null>(null);

  const [newProjectName, setNewProjectName] = useState("");
  const [newProjectRepo, setNewProjectRepo] = useState("");
  const [targetPath, setTargetPath] = useState("");

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [expandedFindingId, setExpandedFindingId] = useState<number | null>(null);
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const [reviewFilter, setReviewFilter] = useState<ReviewFilter>("all");
  const [scopeFilter, setScopeFilter] = useState<ScopeFilter>("all");
  const [showScanPanel, setShowScanPanel] = useState(false);

  useEffect(() => {
    loadProjects();
    loadUserNames();
  }, []);

  /* ---------------- CHARGEMENTS ---------------- */

  async function loadProjects() {
    try {
      setError(null);
      setProjects(await api.listProjects());
    } catch (e) {
      setError(errorMessage(e));
    }
  }

  /** Pour afficher "approuvée par bryan" au lieu de "par l'utilisateur #3". */
  async function loadUserNames() {
    try {
      const users = await api.listUsers();
      const names: Record<number, string> = {};
      users.forEach((u) => {
        names[u.id] = u.username;
      });
      setUserNames(names);
    } catch {
      // non bloquant : on affichera l'identifiant à la place du nom
    }
  }

  function latestBuildOf(list: Finding[]): number | null {
    const builds = list
      .map((f) => f.jenkins_build_number)
      .filter((b): b is number => b !== null && b !== undefined);
    return builds.length > 0 ? Math.max(...builds) : null;
  }

  async function loadGate(projectId: number, build: number | null) {
    try {
      setGate(
        await api.getQualityGate(projectId, {
          build: build ?? undefined,
          maxCritical: GATE_MAX_CRITICAL,
          maxHigh: GATE_MAX_HIGH,
        })
      );
    } catch (e) {
      setGate(null);
      setError(errorMessage(e));
    }
  }

  async function loadFindings(projectId: number) {
    setLoading(true);
    setError(null);

    try {
      const data = await api.listFindings(projectId);
      data.sort((a, b) => (b.priority_score ?? 0) - (a.priority_score ?? 0));
      setFindings(data);

      await Promise.all([
        loadExistingAnalyses(data),
        loadGate(projectId, latestBuildOf(data)),
      ]);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  }

  async function loadExistingAnalyses(findingList: Finding[]) {
    const existing: Record<number, AIAnalysis> = {};

    await Promise.all(
      findingList.map(async (finding) => {
        try {
          const history = await api.listAnalyses(finding.id);
          if (history.length > 0) {
            existing[finding.id] = history[0];
          }
        } catch {
          // Une erreur d'historique ne bloque pas l'affichage des findings.
        }
      })
    );

    setAnalyses(existing);
  }

  /* ---------------- ACTIONS ---------------- */

  function selectProject(id: number) {
    setSelectedProjectId(id);
    setAnalyses({});
    setGate(null);
    setExpandedFindingId(null);
    setScopeFilter("all");
    loadFindings(id);
  }

  async function handleCreateProject(e: FormEvent) {
    e.preventDefault();

    if (!newProjectName.trim()) {
      setError("Le nom du projet est obligatoire.");
      return;
    }

    try {
      setError(null);
      const project = await api.createProject(newProjectName.trim(), newProjectRepo.trim());
      setProjects((prev) => [...prev, project]);
      setNewProjectName("");
      setNewProjectRepo("");
      selectProject(project.id);
    } catch (e) {
      setError(errorMessage(e));
    }
  }

  async function runScan(scanner: "trivy" | "semgrep" | "gitleaks") {
    if (!selectedProjectId || !targetPath.trim()) {
      setError("Choisissez un projet et indiquez un chemin à scanner.");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const path = targetPath.trim();
      if (scanner === "trivy") await api.scanTrivy(selectedProjectId, path);
      if (scanner === "semgrep") await api.scanSemgrep(selectedProjectId, path);
      if (scanner === "gitleaks") await api.scanGitleaks(selectedProjectId, path);

      await loadFindings(selectedProjectId);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  }

  async function runScoring() {
    if (!selectedProjectId) return;

    setLoading(true);
    setError(null);

    try {
      const scored = await api.scoreProject(selectedProjectId);
      scored.sort((a, b) => (b.priority_score ?? 0) - (a.priority_score ?? 0));
      setFindings(scored);
      await loadGate(selectedProjectId, latestBuildOf(scored));
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  }

  async function runAnalysis(findingId: number) {
    setError(null);

    try {
      const result = await api.analyzeFinding(findingId);
      setAnalyses((prev) => ({ ...prev, [findingId]: result }));
      setExpandedFindingId(findingId);
    } catch (e) {
      setError(errorMessage(e));
    }
  }

  async function reviewAnalysis(analysis: AIAnalysis, humanStatus: "approuve" | "rejete") {
    setError(null);

    try {
      // "reviewed_by" n'est plus envoyé : le serveur le déduit du jeton.
      const updated = await api.reviewAnalysis(analysis.id, { human_status: humanStatus });
      setAnalyses((prev) => ({ ...prev, [analysis.finding_id]: updated }));

      // La décision humaine peut débloquer (ou rebloquer) le Quality Gate.
      if (selectedProjectId) {
        await loadGate(selectedProjectId, latestBuild);
      }
    } catch (e) {
      setError(errorMessage(e));
    }
  }

  function reviewerName(id: number | null): string {
    if (id === null) return "";
    return ` par ${userNames[id] ?? `l'utilisateur #${id}`}`;
  }

  /* ---------------- DONNÉES CALCULÉES ---------------- */

  const selectedProject = projects.find((p) => p.id === selectedProjectId);

  const latestBuild = useMemo(() => latestBuildOf(findings), [findings]);

  const latestCommit = useMemo(() => {
    if (latestBuild === null) return null;
    return findings.find((f) => f.jenkins_build_number === latestBuild)?.git_commit_sha ?? null;
  }, [findings, latestBuild]);

  const statistics = useMemo(() => {
    const critical = findings.filter((f) => f.severity === "critical").length;

    const scores = findings
      .map((f) => f.priority_score)
      .filter((score): score is number => score !== null);

    const averageScore =
      scores.length > 0 ? scores.reduce((sum, s) => sum + s, 0) / scores.length : 0;

    const analyzed = findings.filter((f) => Boolean(analyses[f.id])).length;
    const kev = findings.filter((f) => f.in_kev).length;

    return { critical, averageScore, analyzed, kev };
  }, [findings, analyses]);

  // Si l'option choisie n'existe plus (ex : le gate vient de passer, donc plus de
  // "bloquants"), on revient à "tout l'historique" au lieu d'afficher une liste vide.
  const effectiveScope: ScopeFilter =
    (scopeFilter === "blocking" && (!gate || gate.passed)) ||
    (scopeFilter === "latest" && latestBuild === null)
      ? "all"
      : scopeFilter;

  const filteredFindings = useMemo(() => {
    const blockingIds = gate?.finding_ids ?? [];

    return findings.filter((finding) => {
      const analysis = analyses[finding.id];

      const severityMatches = severityFilter === "all" || finding.severity === severityFilter;

      let reviewMatches = true;
      if (reviewFilter === "non_analyse") {
        reviewMatches = !analysis;
      } else if (reviewFilter !== "all") {
        reviewMatches = analysis?.human_status === reviewFilter;
      }

      let scopeMatches = true;
      if (effectiveScope === "latest") {
        scopeMatches = finding.jenkins_build_number === latestBuild;
      } else if (effectiveScope === "blocking") {
        scopeMatches = blockingIds.includes(finding.id);
      }

      return severityMatches && reviewMatches && scopeMatches;
    });
  }, [findings, analyses, severityFilter, reviewFilter, effectiveScope, latestBuild, gate]);

  /* ---------------- AFFICHAGE ---------------- */

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">V</div>
          <span>VulnScan</span>
        </div>

        <nav className="main-nav">
          <a href="#findings" className="nav-item active">
            <span className="nav-symbol">◇</span>
            Findings
          </a>
          <a href="#dashboard" className="nav-item">
            <span className="nav-symbol">▦</span>
            Tableau de bord
          </a>
          <a href="#projects" className="nav-item">
            <span className="nav-symbol">⎇</span>
            Projets
          </a>
        </nav>

        <div className="sidebar-projects" id="projects">
          <div className="sidebar-title">Projets</div>

          <div className="project-list">
            {projects.length === 0 ? (
              <p className="sidebar-empty">Aucun projet</p>
            ) : (
              projects.map((project) => (
                <button
                  type="button"
                  key={project.id}
                  className={`project-item ${project.id === selectedProjectId ? "active" : ""}`}
                  onClick={() => selectProject(project.id)}
                >
                  <span className="project-dot" />
                  <span className="project-name">{project.name}</span>
                </button>
              ))
            )}
          </div>
        </div>

        <form className="new-project-form" onSubmit={handleCreateProject}>
          <div className="sidebar-title">Nouveau projet</div>

          <input
            type="text"
            placeholder="Nom du projet"
            value={newProjectName}
            onChange={(e) => setNewProjectName(e.target.value)}
          />

          <input
            type="text"
            placeholder="URL du dépôt"
            value={newProjectRepo}
            onChange={(e) => setNewProjectRepo(e.target.value)}
          />

          <button type="submit">+ Créer un projet</button>
        </form>

        <div className="user-box">
          <div className="user-info">
            <strong>{user.username}</strong>
            <span>{user.role}</span>
          </div>

          <button type="button" className="logout-button" onClick={onLogout}>
            Déconnexion
          </button>
        </div>
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
            <div className="welcome-icon">◇</div>
            <h1>Bienvenue dans VulnScan</h1>
            <p>
              Sélectionnez un projet dans la barre latérale ou créez-en un nouveau pour commencer.
            </p>
          </section>
        ) : (
          <>
            <header className="page-header" id="findings">
              <div>
                <p className="page-eyebrow">Gestion des vulnérabilités</p>

                <h1>
                  Findings
                  <span className="project-separator">—</span>
                  <span className="current-project">{selectedProject?.name}</span>
                </h1>

                {selectedProject?.repository_url && (
                  <p className="repository-url">{selectedProject.repository_url}</p>
                )}
              </div>

              <button
                type="button"
                className="rescan-button"
                onClick={() => setShowScanPanel((previous) => !previous)}
              >
                <span className="refresh-icon">↻</span>
                Relancer un scan
              </button>
            </header>

            {gate && (
              <section className={`gate-card ${gate.passed ? "gate-passed" : "gate-blocked"}`}>
                <div>
                  <p className="gate-eyebrow">
                    Quality Gate
                    {latestBuild !== null ? ` · build #${latestBuild}` : " · projet entier"}
                    {latestCommit ? ` · commit ${latestCommit.slice(0, 7)}` : ""}
                  </p>

                  <h2>{gate.passed ? "Passé" : "Bloqué"}</h2>
                  <p>{gate.message}</p>

                  <p className="gate-thresholds">
                    Seuils : {GATE_MAX_CRITICAL} critique, {GATE_MAX_HIGH} élevées au maximum.
                    Un faux positif approuvé par un humain ne compte plus.
                  </p>
                </div>

                {!gate.passed && gate.finding_ids.length > 0 && (
                  <button type="button" onClick={() => setScopeFilter("blocking")}>
                    Voir les {gate.finding_ids.length} bloquant
                    {gate.finding_ids.length > 1 ? "s" : ""}
                  </button>
                )}
              </section>
            )}

            <section className="stats-grid" id="dashboard">
              <article className="stat-card">
                <p>Critiques ouvertes</p>
                <strong className="critical-number">{statistics.critical}</strong>
              </article>

              <article className="stat-card">
                <p>Score moyen</p>
                <strong>{statistics.averageScore.toFixed(1)}</strong>
              </article>

              <article className="stat-card">
                <p>Analysés par IA</p>
                <strong>
                  {statistics.analyzed}
                  <span className="stat-total">/{findings.length}</span>
                </strong>
              </article>

              <article className="stat-card">
                <p>Présents dans KEV</p>
                <strong>{statistics.kev}</strong>
              </article>
            </section>

            {showScanPanel && (
              <section className="scan-panel">
                <div className="scan-panel-header">
                  <div>
                    <h2>Lancer un nouveau scan</h2>
                    <p>Indiquez le chemin local du projet puis choisissez un scanner.</p>
                  </div>
                </div>

                <div className="scan-path-row">
                  <input
                    className="target-path-input"
                    type="text"
                    placeholder="C:/Users/.../mon-projet"
                    value={targetPath}
                    onChange={(e) => setTargetPath(e.target.value)}
                  />
                </div>

                <div className="scanner-buttons">
                  <button type="button" onClick={() => runScan("trivy")} disabled={loading}>
                    Trivy
                  </button>
                  <button type="button" onClick={() => runScan("semgrep")} disabled={loading}>
                    Semgrep
                  </button>
                  <button type="button" onClick={() => runScan("gitleaks")} disabled={loading}>
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
              <div className="filters-row with-scope">
                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value as SeverityFilter)}
                >
                  <option value="all">Toutes sévérités</option>
                  <option value="critical">Critique</option>
                  <option value="high">Élevée</option>
                  <option value="medium">Moyenne</option>
                  <option value="low">Faible</option>
                </select>

                <select
                  value={reviewFilter}
                  onChange={(e) => setReviewFilter(e.target.value as ReviewFilter)}
                >
                  <option value="all">Tous statuts</option>
                  <option value="non_analyse">Non analysé</option>
                  <option value="en_attente">En attente</option>
                  <option value="approuve">Approuvé</option>
                  <option value="rejete">Rejeté</option>
                </select>

                <select
                  value={effectiveScope}
                  onChange={(e) => setScopeFilter(e.target.value as ScopeFilter)}
                >
                  <option value="all">Tout l'historique</option>
                  {latestBuild !== null && (
                    <option value="latest">Présents au dernier build (#{latestBuild})</option>
                  )}
                  {gate && !gate.passed && (
                    <option value="blocking">Bloquent le Quality Gate</option>
                  )}
                </select>

                <div className="results-count">
                  {filteredFindings.length} résultat{filteredFindings.length > 1 ? "s" : ""}
                </div>
              </div>

              {loading && <div className="loading-bar">Chargement...</div>}

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
                    {filteredFindings.length === 0 ? (
                      <tr>
                        <td colSpan={7} className="empty-table">
                          Aucune vulnérabilité ne correspond aux filtres.
                        </td>
                      </tr>
                    ) : (
                      filteredFindings.map((finding) => {
                        const analysis = analyses[finding.id];
                        const isExpanded = expandedFindingId === finding.id;

                        return (
                          <Fragment key={finding.id}>
                            <tr
                              className={`finding-row ${isExpanded ? "expanded" : ""}`}
                              onClick={() => setExpandedFindingId(isExpanded ? null : finding.id)}
                            >
                              <td>
                                <span className={`risk-badge severity-${finding.severity}`}>
                                  <strong>{finding.priority_score ?? "—"}</strong>
                                  <span>{label(SEVERITY_LABELS, finding.severity)}</span>
                                </span>
                              </td>

                              <td className="finding-title-cell">
                                <div className="finding-title">{finding.title}</div>

                                {finding.vulnerability_id && (
                                  <div className="finding-id">{finding.vulnerability_id}</div>
                                )}

                                {finding.file_path && (
                                  <div className="finding-file">{finding.file_path}</div>
                                )}
                              </td>

                              <td>
                                <span className="scanner-name">{finding.scanner_name}</span>
                              </td>

                              <td>
                                <div className="metric-stack">
                                  <span>
                                    CVSS <strong>{finding.cvss_score ?? "—"}</strong>
                                  </span>
                                  <span>
                                    EPSS{" "}
                                    <strong>
                                      {finding.epss_score !== null
                                        ? `${(finding.epss_score * 100).toFixed(2)}%`
                                        : "—"}
                                    </strong>
                                  </span>
                                </div>
                              </td>

                              <td>
                                {analysis ? (
                                  <span className={`verdict-small verdict-${analysis.ai_verdict}`}>
                                    {label(VERDICT_LABELS, analysis.ai_verdict)}
                                  </span>
                                ) : (
                                  <span className="neutral-label">Non analysé</span>
                                )}
                              </td>

                              <td>
                                {analysis ? (
                                  <span className={`review-status review-${analysis.human_status}`}>
                                    {label(HUMAN_STATUS_LABELS, analysis.human_status)}
                                  </span>
                                ) : (
                                  <span className="neutral-label">—</span>
                                )}
                              </td>

                              <td className="action-cell">
                                <button
                                  type="button"
                                  className="analyze-button"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    runAnalysis(finding.id);
                                  }}
                                  disabled={loading}
                                >
                                  {analysis ? "Ré-analyser" : "Analyser"}
                                </button>

                                <button
                                  type="button"
                                  className="expand-button"
                                  aria-label="Afficher le détail"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setExpandedFindingId(isExpanded ? null : finding.id);
                                  }}
                                >
                                  {isExpanded ? "⌃" : "⌄"}
                                </button>
                              </td>
                            </tr>

                            {isExpanded && (
                              <tr className="detail-row">
                                <td colSpan={7}>
                                  {!analysis ? (
                                    <div className="no-analysis">
                                      <div>
                                        <h3>Analyse IA</h3>
                                        <p>
                                          Cette vulnérabilité n'a pas encore été analysée par l'IA.
                                        </p>
                                      </div>

                                      <button type="button" onClick={() => runAnalysis(finding.id)}>
                                        Lancer l'analyse IA
                                      </button>
                                    </div>
                                  ) : (
                                    <div className="analysis-panel">
                                      <div className="analysis-top">
                                        <div>
                                          <p className="analysis-eyebrow">Analyse IA</p>
                                          <h3>{label(VERDICT_LABELS, analysis.ai_verdict)}</h3>
                                        </div>

                                        <div className="analysis-tags">
                                          <span
                                            className={`verdict-large verdict-${analysis.ai_verdict}`}
                                          >
                                            {label(VERDICT_LABELS, analysis.ai_verdict)}
                                          </span>

                                          <span
                                            className={`review-status review-${analysis.human_status}`}
                                          >
                                            {label(HUMAN_STATUS_LABELS, analysis.human_status)}
                                          </span>
                                        </div>
                                      </div>

                                      <div className="analysis-grid">
                                        <div className="analysis-main">
                                          <section className="analysis-block">
                                            <h4>Raisonnement</h4>
                                            <p>{analysis.ai_reasoning}</p>
                                          </section>

                                          {analysis.ai_suggested_fix && (
                                            <section className="analysis-block fix-block">
                                              <h4>Correctif suggéré</h4>
                                              <p>{analysis.ai_suggested_fix}</p>
                                            </section>
                                          )}
                                        </div>

                                        <aside className="analysis-side">
                                          <div className="analysis-info">
                                            <span>Priorité ajustée</span>
                                            <strong>
                                              {analysis.ai_adjusted_priority
                                                ? label(PRIORITY_LABELS, analysis.ai_adjusted_priority)
                                                : "Non définie"}
                                            </strong>
                                          </div>

                                          <div className="analysis-info">
                                            <span>Modèle</span>
                                            <strong>{analysis.ai_model_name}</strong>
                                            <small>{analysis.llm_provider}</small>
                                          </div>

                                          {finding.jenkins_build_number !== null &&
                                            finding.jenkins_build_number !== undefined && (
                                              <div className="analysis-info">
                                                <span>Vu au build</span>
                                                <strong>#{finding.jenkins_build_number}</strong>
                                                {finding.git_commit_sha && (
                                                  <small>commit {finding.git_commit_sha.slice(0, 7)}</small>
                                                )}
                                              </div>
                                            )}

                                          {finding.in_kev && (
                                            <div className="kev-alert">
                                              Présente dans le catalogue KEV
                                            </div>
                                          )}

                                          {finding.fix_available && (
                                            <div className="fix-available">Correctif disponible</div>
                                          )}
                                        </aside>
                                      </div>

                                      <div className="human-review">
                                        <div>
                                          <h4>Validation humaine</h4>

                                          {analysis.human_status === "en_attente" && (
                                            <p>Cette analyse doit être vérifiée par un utilisateur.</p>
                                          )}

                                          {analysis.human_status === "approuve" && (
                                            <p className="approved-text">
                                              ✓ Analyse approuvée{reviewerName(analysis.reviewed_by)}
                                            </p>
                                          )}

                                          {analysis.human_status === "rejete" && (
                                            <p className="rejected-text">
                                              ✕ Analyse rejetée{reviewerName(analysis.reviewed_by)}
                                            </p>
                                          )}
                                        </div>

                                        {analysis.human_status === "en_attente" && (
                                          <div className="review-actions">
                                            <button
                                              type="button"
                                              className="approve-button"
                                              onClick={() => reviewAnalysis(analysis, "approuve")}
                                            >
                                              ✓ Approuver
                                            </button>

                                            <button
                                              type="button"
                                              className="reject-button"
                                              onClick={() => reviewAnalysis(analysis, "rejete")}
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
                      })
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

export default Dashboard;
