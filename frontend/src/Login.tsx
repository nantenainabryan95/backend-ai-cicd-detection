import { useState } from "react";
import type { FormEvent } from "react";

import { api, errorMessage } from "./api";
import type { User } from "./types";

interface LoginProps {
  onLoggedIn: (user: User) => void;
  /** Message affiché au-dessus du formulaire (ex : session expirée). */
  message?: string | null;
}

function Login({ onLoggedIn, message }: LoginProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();

    if (!username.trim() || !password) {
      setError("Saisissez votre nom d'utilisateur et votre mot de passe.");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      await api.login(username.trim(), password);
      const user = await api.me();
      onLoggedIn(user);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="login-page">
      <form className="login-card" onSubmit={handleSubmit}>
        <div className="login-brand">
          <div className="brand-mark">V</div>
          <span>VulnScan</span>
        </div>

        <h1>Connexion</h1>
        <p className="login-subtitle">
          Connectez-vous pour consulter et valider les analyses.
        </p>

        {message && <div className="login-notice">{message}</div>}
        {error && <div className="login-error">{error}</div>}

        <label htmlFor="username">Nom d'utilisateur</label>
        <input
          id="username"
          type="text"
          autoComplete="username"
          autoFocus
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />

        <label htmlFor="password">Mot de passe</label>
        <input
          id="password"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />

        <button type="submit" className="login-button" disabled={loading}>
          {loading ? "Connexion..." : "Se connecter"}
        </button>
      </form>
    </div>
  );
}

export default Login;
