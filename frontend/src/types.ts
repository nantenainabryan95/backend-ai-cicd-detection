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
  description: string | null;
  code_snippet: string | null;
  line_number: number | null;
  status: string;
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
  created_at: string | null;
}

/** Une analyse + la vulnérabilité concernée (GET /projects/{id}/analyses). */
export interface AnalysisDetail extends AIAnalysis {
  finding_title: string;
  finding_severity: string;
  scanner_name: string;
}

/** "reviewed_by" n'est plus envoyé : le serveur le déduit du jeton. */
export interface AnalysisReview {
  human_status: "approuve" | "rejete";
}

/** Instantané d'un build Jenkins (GET /projects/{id}/builds). */
export interface BuildRun {
  build_number: number;
  git_commit_sha: string | null;
  created_at: string | null;
  critical: number;
  high: number;
  medium: number;
  low: number;
  blocking: number;
  passed: boolean;
}

export interface User {
  id: number;
  username: string;
  email: string;
  role: string;
}

export interface NewUser {
  username: string;
  email: string;
  password: string;
  role: string;
}

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