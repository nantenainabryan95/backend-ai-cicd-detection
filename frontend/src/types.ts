// Ces types décrivent la forme des données renvoyées par l'API Python.
// Ils doivent rester alignés avec app/schemas.py côté backend : si vous
// ajoutez un champ côté Python, ajoutez-le ici aussi.

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
