import type { ReactNode } from "react";

import { Icon } from "./icons";
import type { IconName } from "./icons";
import {
  REVIEW_LABELS,
  SEVERITY_LABELS,
  VERDICT_LABELS,
  label,
} from "./ui";

export function SeverityPill({ severity }: { severity: string }) {
  return (
    <span className={`pill sev-${severity}`}>{label(SEVERITY_LABELS, severity)}</span>
  );
}

export function GatePill({ passed }: { passed: boolean }) {
  return (
    <span className={`gate-pill ${passed ? "ok" : "ko"}`}>
      <Icon name={passed ? "check" : "x"} size={12} />
      {passed ? "PASSÉ" : "ÉCHOUÉ"}
    </span>
  );
}

export function VerdictPill({ verdict }: { verdict: string }) {
  return <span className={`soft-pill verdict-${verdict}`}>{label(VERDICT_LABELS, verdict)}</span>;
}

export function ReviewPill({ status }: { status: string }) {
  return <span className={`soft-pill review-${status}`}>{label(REVIEW_LABELS, status)}</span>;
}

export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: ReactNode;
  subtitle?: string;
  actions?: ReactNode;
}) {
  return (
    <header className="page-head">
      <div>
        <h1>{title}</h1>
        {subtitle && <p>{subtitle}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </header>
  );
}

export function StatCard({
  icon,
  tone,
  title,
  value,
  hint,
  hintTone,
}: {
  icon: IconName;
  tone: "blue" | "red" | "green" | "amber";
  title: string;
  value: ReactNode;
  hint?: string;
  hintTone?: "good" | "bad";
}) {
  return (
    <article className="stat-card">
      <div className="stat-top">
        <span className={`stat-icon tone-${tone}`}>
          <Icon name={icon} size={18} />
        </span>
        <span className="stat-title">{title}</span>
      </div>
      <div className="stat-value">{value}</div>
      {hint && <div className={`stat-hint ${hintTone ?? ""}`}>{hint}</div>}
    </article>
  );
}

export interface TabItem {
  id: string;
  label: string;
  badge?: number;
}

export function Tabs({
  tabs,
  active,
  onChange,
}: {
  tabs: TabItem[];
  active: string;
  onChange: (id: string) => void;
}) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          type="button"
          role="tab"
          aria-selected={tab.id === active}
          className={`tab ${tab.id === active ? "active" : ""}`}
          onClick={() => onChange(tab.id)}
        >
          {tab.label}
          {tab.badge !== undefined && tab.badge > 0 && <span className="tab-badge">{tab.badge}</span>}
        </button>
      ))}
    </div>
  );
}

export function EmptyState({
  title,
  text,
  action,
}: {
  title: string;
  text?: string;
  action?: ReactNode;
}) {
  return (
    <div className="empty-state">
      <div className="empty-icon">
        <Icon name="shield" size={26} />
      </div>
      <h3>{title}</h3>
      {text && <p>{text}</p>}
      {action}
    </div>
  );
}
