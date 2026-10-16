import { useState } from "react";
import type { FormEvent } from "react";

import { PageHeader } from "../components";
import { Icon } from "../icons";
import { ROLE_LABELS, initials, label } from "../ui";
import { errorMessage } from "../api";
import type { User } from "../types";
import type { Workspace } from "../useWorkspace";

const EMPTY_FORM = { username: "", email: "", password: "", role: "developer" };

export default function UsersPage({ ws, user }: { ws: Workspace; user: User }) {
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<User | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [form, setForm] = useState(EMPTY_FORM);
  const [formError, setFormError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const isAdmin = user.role === "admin";

  function closeModal() {
    setOpen(false);
    setEditing(null);
    setForm(EMPTY_FORM);
    setFormError(null);
  }

  function openEdit(u: User) {
    setEditing(u);
    setForm({ username: u.username, email: u.email, password: "", role: u.role });
    setFormError(null);
  }

  async function handleDelete(u: User) {
    if (!window.confirm(`Supprimer le compte « ${u.username} » ? Cette action est définitive.`)) return;
    setActionError(null);
    try {
      await ws.deleteUser(u.id);
    } catch (err) {
      setActionError(errorMessage(err));
    }
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();

    if (!form.email.trim() || (!editing && (!form.username.trim() || !form.password))) {
      setFormError("Tous les champs sont obligatoires.");
      return;
    }

    setSaving(true);
    setFormError(null);

    try {
      if (editing) {
        await ws.updateUser(editing.id, {
          email: form.email.trim(),
          role: form.role,
          password: form.password || undefined,
        });
      } else {
        await ws.createUser({ ...form, username: form.username.trim(), email: form.email.trim() });
      }
      closeModal();
    } catch (err) {
      setFormError(errorMessage(err));
    } finally {
      setSaving(false);
    }
  }

  return (
    <>
      <PageHeader
        title="Utilisateurs"
        subtitle="Gestion des comptes et des rôles"
        actions={
          isAdmin ? (
            <button type="button" className="btn btn-primary" onClick={() => setOpen(true)}>
              <Icon name="plus" size={15} /> Nouvel utilisateur
            </button>
          ) : undefined
        }
      />

      {!isAdmin && (
        <p className="notice">Seul un administrateur peut créer, modifier ou supprimer des comptes.</p>
      )}

      {actionError && <div className="form-error">{actionError}</div>}

      <section className="card flush">
        <div className="table-wrap">
          <table className="table" id="users-table">
            <thead>
              <tr>
                <th>#</th>
                <th>Nom d'utilisateur</th>
                <th>Email</th>
                <th>Rôle</th>
                {isAdmin && <th>Actions</th>}
              </tr>
            </thead>
            <tbody>
              {ws.users.map((u) => (
                <tr key={u.id}>
                  <td className="muted">{u.id}</td>
                  <td>
                    <span className="user-cell">
                      <span className="avatar sm">{initials(u.username)}</span>
                      <span className="strong">{u.username}</span>
                    </span>
                  </td>
                  <td>{u.email}</td>
                  <td>
                    <span className={`soft-pill role-${u.role}`}>{label(ROLE_LABELS, u.role)}</span>
                  </td>
                  {isAdmin && (
                    <td>
                      <span className="btn-row">
                        <button type="button" className="btn btn-outline btn-sm" onClick={() => openEdit(u)}>
                          Modifier
                        </button>
                        <button
                          type="button"
                          className="btn btn-outline btn-sm"
                          style={{ color: "#a52326", borderColor: "#f3c2c3" }}
                          disabled={u.id === user.id}
                          title={u.id === user.id ? "Vous ne pouvez pas supprimer votre propre compte" : undefined}
                          onClick={() => handleDelete(u)}
                        >
                          Supprimer
                        </button>
                      </span>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {(open || editing) && (
        <div className="modal-backdrop" onClick={closeModal}>
          <form className="modal" onClick={(e) => e.stopPropagation()} onSubmit={handleSubmit}>
            <h2>{editing ? "Modifier l'utilisateur" : "Nouvel utilisateur"}</h2>

            {formError && <div className="form-error">{formError}</div>}

            <label htmlFor="new-username">Nom d'utilisateur</label>
            <input id="new-username" disabled={!!editing} value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />

            <label htmlFor="new-email">Email</label>
            <input id="new-email" type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />

            <label htmlFor="new-password">{editing ? "Nouveau mot de passe (laisser vide pour ne pas changer)" : "Mot de passe"}</label>
            <input id="new-password" type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />

            <label htmlFor="new-role">Rôle</label>
            <select id="new-role" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
              {Object.entries(ROLE_LABELS).map(([value, text]) => (
                <option key={value} value={value}>{text}</option>
              ))}
            </select>

            <div className="btn-row end">
              <button type="button" className="btn btn-outline" onClick={closeModal}>Annuler</button>
              <button type="submit" className="btn btn-primary" disabled={saving}>
                {saving ? "Enregistrement..." : editing ? "Enregistrer" : "Créer"}
              </button>
            </div>
          </form>
        </div>
      )}
    </>
  );
}