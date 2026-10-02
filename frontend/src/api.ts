import type { Project, Finding, AIAnalysis } from "./types";

// L'adresse de votre API. En développement, c'est toujours localhost:8000
// (là où tourne uvicorn). Vite permet de la rendre configurable via un
// fichier .env si besoin plus tard, mais une valeur fixe suffit pour l'instant.
const API_URL = "http://localhost:8000";

// Petite fonction utilitaire : fait l'appel HTTP, vérifie que la réponse
// est valide, et renvoie le JSON déjà typé. Toutes les fonctions ci-dessous
// s'appuient dessus pour ne pas répéter la gestion d'erreur à chaque fois.
async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });

  if (!response.ok) {
    // On lit le corps de l'erreur pour avoir un message utile dans la console,
    // plutôt qu'un simple "erreur 500" sans détail.
    const body = await response.text();
    throw new Error(`Erreur API (${response.status}) sur ${path} : ${body}`);
  }

  return response.json() as Promise<T>;
}

export const api = {
  listProjects: () => request<Project[]>("/projects"),

  createProject: (name: string, repository_url: string) =>
    request<Project>("/projects", {
      method: "POST",
      body: JSON.stringify({ name, repository_url }),
    }),

  listFindings: (projectId: number) =>
    request<Finding[]>(`/projects/${projectId}/findings`),

  scanTrivy: (projectId: number, targetPath: string) =>
    request<Finding[]>(`/projects/${projectId}/scan/trivy`, {
      method: "POST",
      body: JSON.stringify({ target_path: targetPath }),
    }),

  scanSemgrep: (projectId: number, targetPath: string) =>
    request<Finding[]>(`/projects/${projectId}/scan/semgrep`, {
      method: "POST",
      body: JSON.stringify({ target_path: targetPath }),
    }),

  scanGitleaks: (projectId: number, targetPath: string) =>
    request<Finding[]>(`/projects/${projectId}/scan/gitleaks`, {
      method: "POST",
      body: JSON.stringify({ target_path: targetPath }),
    }),

  scoreProject: (projectId: number) =>
    request<Finding[]>(`/projects/${projectId}/score`, { method: "POST" }),

  analyzeFinding: (findingId: number) =>
    request<AIAnalysis>(`/findings/${findingId}/analyze`, { method: "POST" }),

  listAnalyses: (findingId: number) =>
    request<AIAnalysis[]>(`/findings/${findingId}/analyses`),
};
