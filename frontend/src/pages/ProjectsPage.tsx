import { useEffect, useState } from "react";
import type { FormEvent } from "react";

import { errorMessage } from "../api";
import { PageHeader } from "../components";
import { Icon } from "../icons";
import { navigate } from "../router";
import type { Project } from "../types";
import type { Workspace } from "../useWorkspace";
import { formatDate } from "../ui";

/** Seuils de tolérance du Quality Gate pour le projet ouvert. */
function GateSettingsCard({ ws, canManage }: { ws: Workspace; canManage: boolean }) {
  const [maxCritical, setMaxCritical] = useState("0");
  const [maxHigh, setMaxHigh] = useState("5");
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (ws.gateSettings) {
      setMaxCritical(String(ws.gateSettings.max_critical));
      setMaxHigh(String(ws.gateSettings.max_high));
    }
  }, [ws.gateSettings]);

  if (!ws.project) return null;

  async function handleSave(e: FormEvent) {
    e.preventDefault();
    setSaved(false);

    const critical = Number(maxCritical);
    const high = Number(maxHigh);
    if (!Number.isInteger(critical) || !Number.isInteger(high) || critical < 0 || high < 0) {
      setFormError("Les seuils doivent être des nombres entiers positifs ou nuls.");
      return;
    }

    setSaving(true);
    setFormError(null);
    try {
      await ws.saveGateSettings(critical, high);
      setSaved(true);
    } catch (err) {
      setFormError(errorMessage(err));
    } finally {
      setSaving(false);
    }
  }

  const info = ws.gateSettings;

  return (
    <form className="card" onSubmit={handleSave} style={{ marginBottom: 22 }}>
      <h2 className="card-title">Seuils du Quality Gate · {ws.project.name}</h2>
      <p className="muted">
        Le build est bloqué lorsque le nombre de vulnérabilités ouvertes dépasse ces seuils. Un paramètre
        renseigné dans le job Jenkins reste prioritaire sur ces valeurs.
      </p>

      <div className="grid-2" style={{ marginTop: 6 }}>
        <div>
          <label htmlFor="gate-critical">Critiques tolérées au maximum</label>
          <input
            id="gate-critical"
            type="number"
            min={0}
            value={maxCritical}
            disabled={!canManage}
            onChange={(e) => setMaxCritical(e.target.value)}
          />
        </div>
        <div>
          <label htmlFor="gate-high">Hautes tolérées au maximum</label>
          <input
            id="gate-high"
            type="number"
            min={0}
            value={maxHigh}
            disabled={!canManage}
            onChange={(e) => setMaxHigh(e.target.value)}
          />
        </div>
      </div>

      {formError && <div className="form-error">{formError}</div>}
      {saved && <div className="notice">Seuils enregistrés. Le Quality Gate a été recalculé.</div>}

      <p className="muted small" style={{ marginTop: 12 }}>
        {info?.is_default
          ? "Valeurs par défaut : aucun réglage enregistré pour ce projet."
          : info?.updated_at
            ? `Dernière modification : ${formatDate(info.updated_at)}${info.updated_by ? ` par ${info.updated_by}` : ""}.`
            : ""}
      </p>

      {canManage ? (
        <div className="btn-row end">
          <button type="submit" className="btn btn-primary" disabled={saving}>
            {saving ? "Enregistrement..." : "Enregistrer les seuils"}
          </button>
        </div>
      ) : (
        <p className="notice">Seuls un administrateur ou un responsable technique peuvent modifier ces seuils.</p>
      )}
    </form>
  );
}

export default function ProjectsPage({
  ws,
  canManageGate,
  isAdmin,
}: {
  ws: Workspace;
  canManageGate: boolean;
  isAdmin: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [repo, setRepo] = useState("");
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  function closeModal() {
    setOpen(false);
    setName("");
    setRepo("");
    setFormError(null);
  }

  async function handleCreate(e: FormEvent) {
    e.preventDefault();

    if (!name.trim()) {
      setFormError("Le nom du projet est obligatoire.");
      return;
    }

    setSaving(true);
    setFormError(null);
    try {
      await ws.createProject(name.trim(), repo.trim());
      closeModal();
      navigate("/dashboard");
    } catch (err) {
      setFormError(errorMessage(err));
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete(p: Project) {
    const avertissement =
      p.id === 1
        ? "\n\nAttention : le projet n°1 est celui que Jenkins utilise par défaut (paramètre PROJECT_ID)."
        : "";
    const message =
      `Supprimer le projet « ${p.name} » ?\n\n` +
      "Ses vulnérabilités, analyses IA, décisions et builds seront effacés définitivement." +
      avertissement;
    if (!window.confirm(message)) return;

    setActionError(null);
    try {
      await ws.deleteProject(p.id);
    } catch (err) {
      setActionError(errorMessage(err));
    }
  }

  return (
    <>
      <PageHeader
        title="Projets"
        subtitle="Les projets suivis par VulnScan"
        actions={
          <button type="button" className="btn btn-primary" onClick={() => setOpen(true)}>
            <Icon name="plus" size={15} /> Nouveau projet
          </button>
        }
      />

      <GateSettingsCard ws={ws} canManage={canManageGate} />

      {actionError && <div className="form-error" style={{ marginBottom: 16 }}>{actionError}</div>}

      <section className="project-grid">
        {ws.projects.map((p) => {
          const current = p.id === ws.projectId;
          return (
            <article key={p.id} className={`card project-card ${current ? "current" : ""}`}>
              <div className="project-icon">
                <Icon name="folder" size={20} />
              </div>
              <h3>{p.name}</h3>
              <p className="muted ellipsis">{p.repository_url || "Aucun dépôt renseigné"}</p>

              <div className="btn-row" style={{ marginTop: 10 }}>
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={() => {
                    ws.selectProject(p.id);
                    navigate("/dashboard");
                  }}
                >
                  {current ? "Projet actuel" : "Ouvrir"}
                </button>

                {isAdmin && (
                  <button
                    type="button"
                    className="btn btn-outline"
                    style={{ color: "var(--bad)", borderColor: "var(--bad)" }}
                    disabled={current}
                    title={current ? "Ouvrez un autre projet pour pouvoir supprimer celui-ci" : undefined}
                    onClick={() => handleDelete(p)}
                  >
                    Supprimer
                  </button>
                )}
              </div>
            </article>
          );
        })}
      </section>

      {open && (
        <div className="modal-backdrop" onClick={closeModal}>
          <form className="modal" onClick={(e) => e.stopPropagation()} onSubmit={handleCreate}>
            <h2>Nouveau projet</h2>

            {formError && <div className="form-error">{formError}</div>}

            <label htmlFor="project-name">Nom du projet</label>
            <input id="project-name" value={name} onChange={(e) => setName(e.target.value)} />

            <label htmlFor="project-repo">URL du dépôt</label>
            <input id="project-repo" value={repo} onChange={(e) => setRepo(e.target.value)} />

            <div className="btn-row end">
              <button type="button" className="btn btn-outline" onClick={closeModal}>Annuler</button>
              <button type="submit" className="btn btn-primary" disabled={saving}>
                {saving ? "Création..." : "Créer"}
              </button>
            </div>
          </form>
        </div>
      )}
    </>
  );
}