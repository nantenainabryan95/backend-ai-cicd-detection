export interface Project {
  id: number;
  name: string;
  repository_url: string;
}

export interface Finding {
  id: number;
  title: string;
  scanner_name: string;
  vulnerability_id: string | null;
  file_path: string | null;
  severity: string;
  cvss_score: number | null;
  epss_score: number | null;
  in_kev: boolean;
  is_exposed: boolean;
  priority_score: number | null;
  fix_available: boolean;
  /** Dernier build Jenkins qui a vu ce finding (null si jamais scanné par Jenkins). */
  jenkins_build_number: number | null;
  git_commit_sha: string | null;
}

export interface AIAnalysis {
  id: number;
  finding_id: number;
  llm_provider: string;
  ai_model_name: string;
  ai_verdict: string;
  ai_adjusted_priority: string | null;
  ai_reasoning: string;
  ai_suggested_fix: string | null;
  human_status: string;
  reviewed_by: number | null;
}

/**
 * Données envoyées à FastAPI pour approuver ou rejeter une analyse IA.
 * "reviewed_by" n'est plus envoyé : le serveur le déduit du jeton.
 */
export interface AnalysisReview {
  human_status: "approuve" | "rejete";
}

/** Utilisateur connecté (GET /auth/me). */
export interface User {
  id: number;
  username: string;
  email: string;
  role: string;
}

/** Réponse de POST /auth/login. */
export interface TokenOut {
  access_token: string;
  token_type: string;
}

/** Résultat du Quality Gate, qu'il soit passé (200) ou bloqué (422). */
export interface QualityGateResult {
  passed: boolean;
  message: string;
  blocking_findings: number;
  finding_ids: number[];
}

export interface QualityGateOptions {
  build?: number;
  maxCritical?: number;
  maxHigh?: number;
}