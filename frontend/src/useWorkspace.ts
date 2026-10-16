import { useCallback, useEffect, useMemo, useState } from "react";

import { api, errorMessage } from "./api";
import { latestBuildOf } from "./ui";
import type {
  AnalysisDetail,
  BuildRun,
  Finding,
  NewUser,
  UserUpdate,
  Project,
  QualityGateResult,
  User,
} from "./types";

/**
 * Seuils du Quality Gate affichés dans l'interface.
 * À garder identiques aux paramètres du Jenkinsfile (MAX_CRITICAL / MAX_HIGH).
 */
export const GATE_MAX_CRITICAL = 0;
export const GATE_MAX_HIGH = 5;

const PROJECT_KEY = "vulnscan_project";

/**
 * Toutes les données de l'application, chargées une seule fois et partagées
 * par les pages (tableau de bord, findings, analyses...).
 */
export function useWorkspace() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectId, setProjectId] = useState<number | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [analyses, setAnalyses] = useState<AnalysisDetail[]>([]);
  const [builds, setBuilds] = useState<BuildRun[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [gate, setGate] = useState<QualityGateResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  /** Recharge findings, analyses, builds et Quality Gate d'un projet. */
  const refresh = useCallback(async (id: number) => {
    setLoading(true);
    setError(null);

    try {
      const [f, a, b] = await Promise.all([
        api.listFindings(id),
        api.listProjectAnalyses(id),
        api.listBuilds(id),
      ]);

      f.sort((x, y) => (y.priority_score ?? 0) - (x.priority_score ?? 0));
      setFindings(f);
      setAnalyses(a);
      setBuilds(b);

      const latest = latestBuildOf(f);
      try {
        setGate(
          await api.getQualityGate(id, {
            build: latest ?? undefined,
            maxCritical: GATE_MAX_CRITICAL,
            maxHigh: GATE_MAX_HIGH,
          })
        );
      } catch (e) {
        setGate(null);
        setError(errorMessage(e));
      }
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  }, []);

  const selectProject = useCallback(
    (id: number) => {
      setProjectId(id);
      setFindings([]);
      setAnalyses([]);
      setBuilds([]);
      setGate(null);
      try {
        localStorage.setItem(PROJECT_KEY, String(id));
      } catch {
        // stockage indisponible : la sélection ne sera pas mémorisée
      }
      return refresh(id);
    },
    [refresh]
  );

  const loadUsers = useCallback(async () => {
    try {
      setUsers(await api.listUsers());
    } catch {
      // non bloquant : on affichera l'identifiant à la place du nom
    }
  }, []);

  useEffect(() => {
    (async () => {
      try {
        const list = await api.listProjects();
        setProjects(list);

        let saved = NaN;
        try {
          saved = Number(localStorage.getItem(PROJECT_KEY));
        } catch {
          // ignoré
        }

        const first = list.find((p) => p.id === saved) ?? list[0];
        if (first) await selectProject(first.id);
      } catch (e) {
        setError(errorMessage(e));
      }
    })();
    loadUsers();
  }, [selectProject, loadUsers]);

  /* ---------------- DONNÉES CALCULÉES ---------------- */

  const latestBuild = useMemo(() => latestBuildOf(findings), [findings]);

  const latestCommit = useMemo(
    () =>
      latestBuild === null
        ? null
        : findings.find((f) => f.jenkins_build_number === latestBuild)?.git_commit_sha ?? null,
    [findings, latestBuild]
  );

  /** Dernière analyse de chaque finding (la liste arrive de la plus récente à la plus ancienne). */
  const latestAnalysis = useMemo(() => {
    const map: Record<number, AnalysisDetail> = {};
    analyses.forEach((a) => {
      if (!(a.finding_id in map)) map[a.finding_id] = a;
    });
    return map;
  }, [analyses]);

  const pendingCount = useMemo(
    () => Object.values(latestAnalysis).filter((a) => a.human_status === "en_attente").length,
    [latestAnalysis]
  );

  const userNames = useMemo(() => {
    const names: Record<number, string> = {};
    users.forEach((u) => {
      names[u.id] = u.username;
    });
    return names;
  }, [users]);

  const project = projects.find((p) => p.id === projectId) ?? null;

  /* ---------------- ACTIONS ---------------- */

  async function run(action: () => Promise<unknown>) {
    setError(null);
    try {
      await action();
      if (projectId !== null) await refresh(projectId);
    } catch (e) {
      setError(errorMessage(e));
    }
  }

  async function createProject(name: string, repositoryUrl: string) {
    setError(null);
    try {
      const created = await api.createProject(name, repositoryUrl);
      setProjects((prev) => [...prev, created]);
      await selectProject(created.id);
      return created;
    } catch (e) {
      setError(errorMessage(e));
      return null;
    }
  }

  const runScan = (scanner: "trivy" | "semgrep" | "gitleaks", path: string) =>
    run(() => {
      if (projectId === null) return Promise.resolve();
      if (scanner === "trivy") return api.scanTrivy(projectId, path);
      if (scanner === "semgrep") return api.scanSemgrep(projectId, path);
      return api.scanGitleaks(projectId, path);
    });

  const runScoring = () =>
    run(() => (projectId === null ? Promise.resolve() : api.scoreProject(projectId)));

  const analyze = (findingId: number) => run(() => api.analyzeFinding(findingId));

  /** La décision humaine peut débloquer (ou rebloquer) le Quality Gate : on recharge tout. */
  const review = (analysisId: number, status: "approuve" | "rejete") =>
    run(() => api.reviewAnalysis(analysisId, { human_status: status }));

  /** Lève une erreur en cas d'échec (affichée dans le formulaire par la page). */
  async function createUser(user: NewUser) {
    await api.createUser(user);
    await loadUsers();
  }

  async function updateUser(id: number, data: UserUpdate) {
    await api.updateUser(id, data);
    await loadUsers();
  }

  async function deleteUser(id: number) {
    await api.deleteUser(id);
    await loadUsers();
  }

  return {
    projects,
    project,
    projectId,
    findings,
    analyses,
    builds,
    users,
    gate,
    loading,
    error,
    setError,
    latestBuild,
    latestCommit,
    latestAnalysis,
    pendingCount,
    userNames,
    selectProject,
    createProject,
    runScan,
    runScoring,
    analyze,
    review,
    createUser,
    updateUser,
    deleteUser,
  };
}

export type Workspace = ReturnType<typeof useWorkspace>;