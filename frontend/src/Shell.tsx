import { useState } from "react";

import { EmptyState } from "./components";
import { Icon } from "./icons";
import type { IconName } from "./icons";
import { navigate, useRoute } from "./router";
import { ROLE_LABELS, initials, label } from "./ui";
import type { User } from "./types";
import { useWorkspace } from "./useWorkspace";

import AnalysesPage from "./pages/AnalysesPage";
import DashboardPage from "./pages/DashboardPage";
import FindingDetailPage from "./pages/FindingDetailPage";
import FindingsPage from "./pages/FindingsPage";
import ProjectsPage from "./pages/ProjectsPage";
import UsersPage from "./pages/UsersPage";

const NAV: { id: string; label: string; icon: IconName }[] = [
  { id: "dashboard", label: "Tableau de bord", icon: "grid" },
  { id: "projects", label: "Projets", icon: "folder" },
  { id: "findings", label: "Findings", icon: "alert" },
  { id: "analyses", label: "Analyses IA", icon: "cpu" },
  { id: "users", label: "Utilisateurs", icon: "users" },
];

interface ShellProps {
  user: User;
  onLogout: () => void;
}

/** Cadre de l'application : barre latérale, barre du haut, et la page courante. */
function Shell({ user, onLogout }: ShellProps) {
  const ws = useWorkspace();
  const route = useRoute();
  const [menuOpen, setMenuOpen] = useState(false);

  const segments = route.split("/").filter(Boolean);
  const section = segments[0] ?? "dashboard";

  function page() {
    // Ces pages n'ont pas besoin d'un projet sélectionné.
    if (section === "projects") return <ProjectsPage ws={ws} />;
    if (section === "users") return <UsersPage ws={ws} user={user} />;

    if (ws.projectId === null) {
      return (
        <section className="card">
          <EmptyState
            title="Aucun projet sélectionné"
            text="Créez un projet ou sélectionnez-en un pour commencer."
            action={
              <button type="button" className="btn btn-primary" onClick={() => navigate("/projects")}>
                Aller aux projets
              </button>
            }
          />
        </section>
      );
    }

    if (section === "findings") {
      return segments[1] ? (
        <FindingDetailPage key={segments[1]} ws={ws} findingId={Number(segments[1])} />
      ) : (
        <FindingsPage ws={ws} />
      );
    }

    if (section === "analyses") {
      return <AnalysesPage key={segments[1] ?? "all"} ws={ws} initialTab={segments[1] === "validation" ? "pending" : "all"} />;
    }

    return <DashboardPage ws={ws} />;
  }

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="side-brand">
          <Icon name="shield" size={24} />
          <span>VulnScan</span>
        </div>

        <div className="side-user">
          <span className="avatar">{initials(user.username)}</span>
          <div>
            <strong>{user.username}</strong>
            <span>{label(ROLE_LABELS, user.role)}</span>
          </div>
        </div>

        <nav className="side-nav">
          {NAV.map((item) => (
            <button
              key={item.id}
              type="button"
              className={`nav-link ${section === item.id ? "active" : ""}`}
              onClick={() => navigate(`/${item.id}`)}
            >
              <Icon name={item.icon} size={17} />
              {item.label}
            </button>
          ))}
        </nav>

        <button type="button" className="nav-link logout" onClick={onLogout}>
          <Icon name="logout" size={17} />
          Déconnexion
        </button>
      </aside>

      <div className="main">
        <header className="topbar">
          <div className="project-picker">
            <Icon name="folder" size={15} />
            <select
              aria-label="Projet"
              value={ws.projectId ?? ""}
              onChange={(e) => ws.selectProject(Number(e.target.value))}
            >
              {ws.projects.length === 0 && <option value="">Aucun projet</option>}
              {ws.projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </div>

          <div className="topbar-right">
            <button
              type="button"
              className="icon-btn"
              aria-label="Analyses à valider"
              title="Analyses à valider"
              onClick={() => navigate("/analyses/validation")}
            >
              <Icon name="bell" size={18} />
              {ws.pendingCount > 0 && <span className="badge">{ws.pendingCount}</span>}
            </button>

            <div className="user-menu">
              <button type="button" className="user-chip" onClick={() => setMenuOpen((v) => !v)}>
                <span className="avatar sm">{initials(user.username)}</span>
                {user.username}
                <Icon name="chevronDown" size={14} />
              </button>

              {menuOpen && (
                <div className="menu">
                  <button type="button" onClick={onLogout}>
                    <Icon name="logout" size={15} /> Se déconnecter
                  </button>
                </div>
              )}
            </div>
          </div>
        </header>

        <main className="content">
          {ws.error && (
            <div className="error-banner" role="alert">
              <span>{ws.error}</span>
              <button type="button" onClick={() => ws.setError(null)} aria-label="Fermer">
                <Icon name="x" size={14} />
              </button>
            </div>
          )}

          {page()}
        </main>
      </div>
    </div>
  );
}

export default Shell;
