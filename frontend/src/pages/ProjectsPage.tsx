import { useState } from "react";
import type { FormEvent } from "react";

import { PageHeader } from "../components";
import { Icon } from "../icons";
import { navigate } from "../router";
import type { Workspace } from "../useWorkspace";

export default function ProjectsPage({ ws }: { ws: Workspace }) {
  const [name, setName] = useState("");
  const [repo, setRepo] = useState("");

  async function handleCreate(e: FormEvent) {
    e.preventDefault();

    if (!name.trim()) {
      ws.setError("Le nom du projet est obligatoire.");
      return;
    }

    const created = await ws.createProject(name.trim(), repo.trim());
    if (created) {
      setName("");
      setRepo("");
      navigate("/dashboard");
    }
  }

  return (
    <>
      <PageHeader title="Projets" subtitle="Les projets suivis par VulnScan" />

      <section className="project-grid">
        {ws.projects.map((p) => (
          <article key={p.id} className={`card project-card ${p.id === ws.projectId ? "current" : ""}`}>
            <div className="project-icon">
              <Icon name="folder" size={20} />
            </div>
            <h3>{p.name}</h3>
            <p className="muted ellipsis">{p.repository_url || "Aucun dépôt renseigné"}</p>

            <button
              type="button"
              className="btn btn-primary"
              onClick={() => {
                ws.selectProject(p.id);
                navigate("/dashboard");
              }}
            >
              {p.id === ws.projectId ? "Projet actuel" : "Ouvrir"}
            </button>
          </article>
        ))}

        <form className="card project-card new" onSubmit={handleCreate}>
          <h3>Nouveau projet</h3>

          <label htmlFor="project-name">Nom du projet</label>
          <input id="project-name" value={name} onChange={(e) => setName(e.target.value)} />

          <label htmlFor="project-repo">URL du dépôt</label>
          <input id="project-repo" value={repo} onChange={(e) => setRepo(e.target.value)} />

          <button type="submit" className="btn btn-primary">
            <Icon name="plus" size={15} /> Créer un projet
          </button>
        </form>
      </section>
    </>
  );
}
