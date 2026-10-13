import type {
  Project,
  Finding,
  AIAnalysis,
  AnalysisReview,
} from "./types";

/**
 * URL du backend FastAPI.
 */
const API_URL = "http://localhost:8000";

/**
 * Fonction générique utilisée pour les appels HTTP.
 */
async function request<T>(
  path: string,
  options?: RequestInit
): Promise<T> {
  const response = await fetch(
    `${API_URL}${path}`,
    {
      headers: {
        "Content-Type": "application/json",
      },
      ...options,
    }
  );

  if (!response.ok) {
    const body = await response.text();

    throw new Error(
      `Erreur API (${response.status}) sur ${path} : ${body}`
    );
  }

  return response.json() as Promise<T>;
}

export const api = {
  /**
   * ==================================================
   * PROJETS
   * ==================================================
   */

  listProjects: () =>
    request<Project[]>("/projects"),

  createProject: (
    name: string,
    repository_url: string
  ) =>
    request<Project>("/projects", {
      method: "POST",
      body: JSON.stringify({
        name,
        repository_url,
      }),
    }),

  /**
   * ==================================================
   * FINDINGS
   * ==================================================
   */

  listFindings: (
    projectId: number
  ) =>
    request<Finding[]>(
      `/projects/${projectId}/findings`
    ),

  /**
   * ==================================================
   * SCANNERS
   * ==================================================
   */

  scanTrivy: (
    projectId: number,
    targetPath: string
  ) =>
    request<Finding[]>(
      `/projects/${projectId}/scan/trivy`,
      {
        method: "POST",
        body: JSON.stringify({
          target_path: targetPath,
        }),
      }
    ),

  scanSemgrep: (
    projectId: number,
    targetPath: string
  ) =>
    request<Finding[]>(
      `/projects/${projectId}/scan/semgrep`,
      {
        method: "POST",
        body: JSON.stringify({
          target_path: targetPath,
        }),
      }
    ),

  scanGitleaks: (
    projectId: number,
    targetPath: string
  ) =>
    request<Finding[]>(
      `/projects/${projectId}/scan/gitleaks`,
      {
        method: "POST",
        body: JSON.stringify({
          target_path: targetPath,
        }),
      }
    ),

  /**
   * ==================================================
   * SCORING
   * ==================================================
   */

  scoreProject: (
    projectId: number
  ) =>
    request<Finding[]>(
      `/projects/${projectId}/score`,
      {
        method: "POST",
      }
    ),

  /**
   * ==================================================
   * ANALYSE IA
   * ==================================================
   */

  analyzeFinding: (
    findingId: number
  ) =>
    request<AIAnalysis>(
      `/findings/${findingId}/analyze`,
      {
        method: "POST",
      }
    ),

  /**
   * Historique des analyses IA.
   */
  listAnalyses: (
    findingId: number
  ) =>
    request<AIAnalysis[]>(
      `/findings/${findingId}/analyses`
    ),

  /**
   * ==================================================
   * HUMAN-IN-THE-LOOP
   * ==================================================
   *
   * Appelle :
   *
   * PATCH /analyses/{analysis_id}/review
   *
   * avec :
   *
   * {
   *   "human_status": "approuve",
   *   "reviewed_by": 1
   * }
   */
  reviewAnalysis: (
    analysisId: number,
    review: AnalysisReview
  ) =>
    request<AIAnalysis>(
      `/analyses/${analysisId}/review`,
      {
        method: "PATCH",
        body: JSON.stringify(review),
      }
    ),
};