import { useState } from "react";
import type { FormEvent } from "react";

import { api, errorMessage } from "./api";
import { Icon } from "./icons";
import type { User } from "./types";

interface LoginProps {
  onLoggedIn: (user: User) => void;
  /** Message affiché au-dessus du formulaire (ex : session expirée). */
  message?: string | null;
}

function Login({ onLoggedIn, message }: LoginProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
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
      onLoggedIn(await api.me());
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="login-screen">
      <section className="login-hero">
        <div className="login-logo">
          <Icon name="shield" size={44} />
          <span>VulnScan</span>
        </div>
        <p className="login-tag">Analyse • Détecte • Protège</p>

        <h2>
          Plateforme de gestion
          <br />
          des vulnérabilités
        </h2>
        <p>
          Scannez vos projets, identifiez les failles, priorisez les risques avec l'IA et validez
          les analyses humaines.
        </p>
      </section>

      <form className="login-card" onSubmit={handleSubmit}>
        <h1>Connexion</h1>
        <p className="muted">Accédez à votre espace VulnScan</p>

        {message && <div className="notice">{message}</div>}
        {error && <div className="form-error">{error}</div>}

        <label htmlFor="username">Nom d'utilisateur</label>
        <div className="input-icon">
          <Icon name="user" size={16} />
          <input
            id="username"
            type="text"
            placeholder="Entrez votre nom d'utilisateur"
            autoComplete="username"
            autoFocus
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
        </div>

        <label htmlFor="password">Mot de passe</label>
        <div className="input-icon">
          <Icon name="lock" size={16} />
          <input
            id="password"
            type={showPassword ? "text" : "password"}
            placeholder="Entrez votre mot de passe"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <button
            type="button"
            className="eye"
            onClick={() => setShowPassword((v) => !v)}
            aria-label={showPassword ? "Masquer le mot de passe" : "Afficher le mot de passe"}
          >
            <Icon name={showPassword ? "eyeOff" : "eye"} size={16} />
          </button>
        </div>

        <button type="submit" className="btn btn-primary btn-block" disabled={loading}>
          {loading ? "Connexion..." : "Se connecter"}
        </button>

        <p className="login-foot">Pas encore de compte ? Contactez votre administrateur.</p>
      </form>
    </div>
  );
}

export default Login;