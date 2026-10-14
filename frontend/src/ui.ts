import type { Finding } from "./types";

export const SEVERITIES = ["critical", "high", "medium", "low"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const SEVERITY_LABELS: Record<string, string> = {
  critical: "Critique",
  high: "Élevée",
  medium: "Moyenne",
  low: "Faible",
};

export const SEVERITY_COLORS: Record<string, string> = {
  critical: "#e5383b",
  high: "#f4743b",
  medium: "#f2b134",
  low: "#2fb574",
};

export const VERDICT_LABELS: Record<string, string> = {
  vraie_menace: "Vraie menace",
  faux_positif: "Faux positif",
  incertain: "Incertain",
};

export const PRIORITY_LABELS: Record<string, string> = {
  critique_confirmee: "Critique confirmée",
  elevee: "Élevée",
  moyenne: "Moyenne",
  basse: "Basse",
};

export const REVIEW_LABELS: Record<string, string> = {
  en_attente: "En attente",
  approuve: "Approuvé",
  rejete: "Rejeté",
};

export const STATUS_LABELS: Record<string, string> = {
  new: "Non corrigé",
  triaging: "En cours d'analyse",
  confirmed: "Confirmé",
  in_progress: "En cours de correction",
  fixed: "Corrigé",
  false_positive: "Faux positif",
  accepted_risk: "Risque accepté",
};

export const ROLE_LABELS: Record<string, string> = {
  admin: "Administrateur",
  appsec: "Analyste sécurité",
  tech_lead: "Tech lead",
  developer: "Développeur",
};

export const SCANNER_LABELS: Record<string, string> = {
  trivy: "Trivy",
  semgrep: "Semgrep",
  gitleaks: "Gitleaks",
};

export const label = (labels: Record<string, string>, key: string): string =>
  labels[key] ?? key;

const two = (n: number) => String(n).padStart(2, "0");

/** "15/06/2025 14:32" */
export function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return `${two(d.getDate())}/${two(d.getMonth() + 1)}/${d.getFullYear()} ${two(d.getHours())}:${two(d.getMinutes())}`;
}

export const shortSha = (sha: string | null | undefined): string =>
  sha ? sha.slice(0, 7) : "—";

export const initials = (name: string): string => name.slice(0, 2).toUpperCase();

export function fileName(path: string | null): string {
  if (!path) return "—";
  const parts = path.split(/[\\/]/);
  return parts[parts.length - 1] || path;
}

export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  findings.forEach((f) => {
    if (f.severity in counts) counts[f.severity as Severity] += 1;
  });
  return counts;
}

export function latestBuildOf(findings: Finding[]): number | null {
  const builds = findings
    .map((f) => f.jenkins_build_number)
    .filter((b): b is number => b !== null && b !== undefined);
  return builds.length > 0 ? Math.max(...builds) : null;
}
