import type {
  Project,
  Finding,
  AIAnalysis,
  AnalysisReview,
  User,
  NewUser,
  UserUpdate,
  AnalysisDetail,
  BuildRun,
  TokenOut,
  QualityGateResult,
  QualityGateOptions,
} from "./types";

/** URL du backend FastAPI (modifiable via VITE_API_URL dans frontend/.env). */
const API_URL: string =
  import.meta.env.VITE_API_URL ?? "http://localhost:8000";

/* ============================================================
   JETON D'AUTHENTIFICATION
   ============================================================ */

const TOKEN_KEY = "vulnscan_token";

export const auth = {
  getToken(): string | null {
    try {
      return localStorage.getItem(TOKEN_KEY);
    } catch {
      return null;
    }
  },
  setToken(token: string): void {
    localStorage.setItem(TOKEN_KEY, token);
  },
  clear(): void {
    try {
      localStorage.removeItem(TOKEN_KEY);
    } catch {
      // stockage indisponible : rien à effacer
    }
  },
  hasToken(): boolean {
    return auth.getToken() !== null;
  },
};

/** Appelée quand le serveur répond 401 alors qu'on avait un jeton (session expirée). */
let unauthorizedHandler: (() => void) | null = null;

export function setUnauthorizedHandler(handler: (() => void) | null): void {
  unauthorizedHandler = handler;
}

/* ============================================================
   ERREURS
   ============================================================ */

export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

/** Transforme le corps d'une erreur FastAPI en phrase lisible. */
function detailToText(body: string): string {
  try {
    const data = JSON.parse(body);
    const detail = data?.detail;

    if (typeof detail === "string") return detail;

    if (Array.isArray(detail)) {
      return detail.map((d) => d?.msg ?? JSON.stringify(d)).join(" ; ");
    }

    if (detail && typeof detail === "object" && typeof detail.message === "string") {
      return detail.message;
    }
  } catch {
    // le corps n'est pas du JSON : on l'affiche tel quel
  }

  return body || "Erreur inconnue.";
}

/** Message à afficher à l'utilisateur pour n'importe quelle erreur. */
export function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}

/* ============================================================
   APPELS HTTP
   ============================================================ */

const SERVER_UNREACHABLE =
  "Impossible de joindre le serveur. Vérifiez que l'API est démarrée.";

/** Envoie une requête avec le jeton, et gère la session expirée (401). */
async function send(path: string, options: RequestInit = {}): Promise<Response> {
  const headers = new Headers(options.headers);

  if (options.body !== undefined && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const token = auth.getToken();
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  let response: Response;
  try {
    response = await fetch(`${API_URL}${path}`, { ...options, headers });
  } catch {
    throw new ApiError(0, SERVER_UNREACHABLE);
  }

  // 401 avec un jeton envoyé = jeton expiré ou invalide : on déconnecte.
  if (response.status === 401 && token) {
    auth.clear();
    unauthorizedHandler?.();
  }

  return response;
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await send(path, options);

  if (!response.ok) {
    throw new ApiError(response.status, detailToText(await response.text()));
  }

  return response.json() as Promise<T>;
}

function withBuild(path: string, build?: number): string {
  return build === undefined ? path : `${path}?build=${build}`;
}

export const api = {
  /* ---------------- AUTHENTIFICATION ---------------- */

  /**
   * /auth/login attend un FORMULAIRE (x-www-form-urlencoded), pas du JSON.
   * En cas de succès, le jeton est mémorisé pour les appels suivants.
   */
  login: async (username: string, password: string): Promise<void> => {
    let response: Response;
    try {
      response = await fetch(`${API_URL}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ username, password }),
      });
    } catch {
      throw new ApiError(0, SERVER_UNREACHABLE);
    }

    if (!response.ok) {
      throw new ApiError(response.status, detailToText(await response.text()));
    }

    const data = (await response.json()) as TokenOut;
    auth.setToken(data.access_token);
  },

  me: () => request<User>("/auth/me"),

  listUsers: () => request<User[]>("/users"),

  createUser: (user: NewUser) =>
    request<User>("/users", { method: "POST", body: JSON.stringify(user) }),

  updateUser: (id: number, data: UserUpdate) =>
    request<User>(`/users/${id}`, { method: "PATCH", body: JSON.stringify(data) }),

  deleteUser: (id: number) =>
    request<{ detail: string }>(`/users/${id}`, { method: "DELETE" }),

  /* ---------------- PROJETS ---------------- */

  listProjects: () => request<Project[]>("/projects"),

  createProject: (name: string, repository_url: string) =>
    request<Project>("/projects", {
      method: "POST",
      body: JSON.stringify({ name, repository_url }),
    }),

  /* ---------------- FINDINGS ---------------- */

  /** build : ne renvoyer que les findings vus au build Jenkins N. */
  listFindings: (projectId: number, build?: number) =>
    request<Finding[]>(withBuild(`/projects/${projectId}/findings`, build)),

  /** Toutes les analyses IA du projet en UNE requête (la plus récente d'abord). */
  listProjectAnalyses: (projectId: number) =>
    request<AnalysisDetail[]>(`/projects/${projectId}/analyses`),

  /** Historique des builds Jenkins (le plus récent d'abord). */
  listBuilds: (projectId: number) =>
    request<BuildRun[]>(`/projects/${projectId}/builds`),

  /* ---------------- SCANNERS ---------------- */

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

  /* ---------------- SCORING ---------------- */

  scoreProject: (projectId: number, build?: number) =>
    request<Finding[]>(withBuild(`/projects/${projectId}/score`, build), {
      method: "POST",
    }),

  /* ---------------- ANALYSE IA ---------------- */

  analyzeFinding: (findingId: number) =>
    request<AIAnalysis>(`/findings/${findingId}/analyze`, { method: "POST" }),

  listAnalyses: (findingId: number) =>
    request<AIAnalysis[]>(`/findings/${findingId}/analyses`),

  /* ---------------- HUMAN-IN-THE-LOOP ---------------- */

  reviewAnalysis: (analysisId: number, review: AnalysisReview) =>
    request<AIAnalysis>(`/analyses/${analysisId}/review`, {
      method: "PATCH",
      body: JSON.stringify(review),
    }),

  /* ---------------- QUALITY GATE ---------------- */

  /**
   * Le serveur répond 200 si le gate est passé et 422 s'il est bloqué.
   * Pour l'interface, les DEUX sont des résultats normaux (pas des pannes).
   */
  getQualityGate: async (
    projectId: number,
    options: QualityGateOptions = {}
  ): Promise<QualityGateResult> => {
    const params = new URLSearchParams();
    if (options.build !== undefined) params.set("build", String(options.build));
    if (options.maxCritical !== undefined) params.set("max_critical", String(options.maxCritical));
    if (options.maxHigh !== undefined) params.set("max_high", String(options.maxHigh));

    const query = params.toString();
    const response = await send(
      `/projects/${projectId}/quality-gate${query ? `?${query}` : ""}`
    );
    const text = await response.text();

    if (response.ok) {
      const data = JSON.parse(text);
      return {
        passed: true,
        message: data.message,
        blocking_findings: data.blocking_findings ?? 0,
        finding_ids: [],
      };
    }

    if (response.status === 422) {
      try {
        const detail = JSON.parse(text)?.detail;
        if (detail && typeof detail === "object" && detail.passed === false) {
          return {
            passed: false,
            message: detail.message,
            blocking_findings: detail.blocking_findings ?? 0,
            finding_ids: detail.finding_ids ?? [],
          };
        }
      } catch {
        // corps illisible : on tombe sur l'erreur générique ci-dessous
      }
    }

    throw new ApiError(response.status, detailToText(text));
  },
};