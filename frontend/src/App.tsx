import { useState, useEffect, Fragment } from "react";
import { api } from "./api";
import type { Project, Finding, AIAnalysis } from "./types";
import "./App.css";

function App() {
  // "useState" garde en mémoire une valeur qui peut changer, et redessine
  // l'écran automatiquement à chaque fois qu'elle change.
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<number | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);

  const [newProjectName, setNewProjectName] = useState("");
  const [newProjectRepo, setNewProjectRepo] = useState("");
  const [targetPath, setTargetPath] = useState("");

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Pour chaque finding analysé, on garde son résultat ici, indexé par
  // l'id du finding. Un "Record<number, X>" est l'équivalent TypeScript
  // d'un dictionnaire Python { int: X }.
  const [analyses, setAnalyses] = useState<Record<number, AIAnalysis>>({});

  // "useEffect" avec un tableau vide [] à la fin veut dire : "exécute ce
  // code UNE SEULE FOIS, quand le composant apparaît à l'écran". C'est
  // ici qu'on charge la liste des projets au tout premier chargement.
  useEffect(() => {
    api.listProjects().then(setProjects).catch((e) => setError(String(e)));
  }, []);

  async function loadFindings(projectId: number) {
    setLoading(true);
    setError(null);
    try {
      const data = await api.listFindings(projectId);
      data.sort((a, b) => (b.priority_score ?? 0) - (a.priority_score ?? 0));
      setFindings(data);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  function selectProject(id: number) {
    setSelectedProjectId(id);
    loadFindings(id);
  }

  async function handleCreateProject(e: React.FormEvent) {
    e.preventDefault();
    if (!newProjectName.trim()) return;
    try {
      const projet = await api.createProject(newProjectName, newProjectRepo);
      setProjects((prev) => [...prev, projet]);
      setNewProjectName("");
      setNewProjectRepo("");
      selectProject(projet.id);
    } catch (e) {
      setError(String(e));
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
      if (scanner === "trivy") await api.scanTrivy(selectedProjectId, targetPath);
      if (scanner === "semgrep") await api.scanSemgrep(selectedProjectId, targetPath);
      if (scanner === "gitleaks") await api.scanGitleaks(selectedProjectId, targetPath);
      await loadFindings(selectedProjectId);
    } catch (e) {
      setError(String(e));
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
      setFindings(scored);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  async function runAnalysis(findingId: number) {
    setError(null);
    try {
      const result = await api.analyzeFinding(findingId);
      setAnalyses((prev) => ({ ...prev, [findingId]: result }));
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <div className="app">
      <aside className="sidebar">
        <h1>VulnScan</h1>

        <form onSubmit={handleCreateProject} className="new-project-form">
          <h2>Nouveau projet</h2>
          <input
            placeholder="Nom du projet"
            value={newProjectName}
            onChange={(e) => setNewProjectName(e.target.value)}
          />
          <input
            placeholder="URL du dépôt (optionnel)"
            value={newProjectRepo}
            onChange={(e) => setNewProjectRepo(e.target.value)}
          />
          <button type="submit">Créer</button>
        </form>

        <h2>Projets</h2>
        <ul className="project-list">
          {projects.map((p) => (
            <li
              key={p.id}
              className={p.id === selectedProjectId ? "active" : ""}
              onClick={() => selectProject(p.id)}
            >
              {p.name}
            </li>
          ))}
        </ul>
      </aside>

      <main className="main">
        {error && <div className="error-banner">{error}</div>}

        {selectedProjectId ? (
          <>
            <div className="scan-panel">
              <input
                className="target-path-input"
                placeholder="Chemin complet à scanner (ex: C:/Users/.../mon-projet)"
                value={targetPath}
                onChange={(e) => setTargetPath(e.target.value)}
              />
              <button onClick={() => runScan("trivy")} disabled={loading}>Scanner (Trivy)</button>
              <button onClick={() => runScan("semgrep")} disabled={loading}>Scanner (Semgrep)</button>
              <button onClick={() => runScan("gitleaks")} disabled={loading}>Scanner (Gitleaks)</button>
              <button onClick={runScoring} disabled={loading} className="score-button">
                Recalculer les scores
              </button>
            </div>

            {loading && <p>Chargement...</p>}

            <table className="findings-table">
              <thead>
                <tr>
                  <th>Score</th>
                  <th>Titre</th>
                  <th>Scanner</th>
                  <th>CVSS</th>
                  <th>EPSS</th>
                  <th>KEV</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f) => {
                  const analyse = analyses[f.id];
                  return (
                    <Fragment key={f.id}>
                      <tr>
                        <td>
                          <span className={`badge severity-${f.severity}`}>
                            {f.priority_score ?? "—"}
                          </span>
                        </td>
                        <td>{f.title}</td>
                        <td>{f.scanner_name}</td>
                        <td>{f.cvss_score ?? "—"}</td>
                        <td>{f.epss_score !== null ? (f.epss_score * 100).toFixed(2) + " %" : "—"}</td>
                        <td>{f.in_kev ? "Oui" : "Non"}</td>
                        <td>
                          <button onClick={() => runAnalysis(f.id)}>Analyser (IA)</button>
                        </td>
                      </tr>
                      {analyse && (
                        <tr className="analysis-row">
                          <td colSpan={7}>
                            <div className="analysis-box">
                              <span className={`verdict verdict-${analyse.ai_verdict}`}>
                                {analyse.ai_verdict}
                              </span>
                              <p>{analyse.ai_reasoning}</p>
                              {analyse.ai_suggested_fix && (
                                <p><strong>Correctif suggéré :</strong> {analyse.ai_suggested_fix}</p>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </>
        ) : (
          <p>Sélectionnez ou créez un projet pour commencer.</p>
        )}
      </main>
    </div>
  );
}

export default App;
