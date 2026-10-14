import { useEffect, useState } from "react";

import { api, auth, errorMessage, setUnauthorizedHandler } from "./api";
import type { User } from "./types";

import Login from "./Login";
import Shell from "./Shell";

import "./styles.css";

/**
 * Point d'entrée : décide quoi afficher selon l'état de connexion.
 *   - jeton en cours de vérification  -> "Chargement"
 *   - pas connecté                    -> page de connexion
 *   - connecté                        -> application (barre latérale + pages)
 */
function App() {
  const [user, setUser] = useState<User | null>(null);
  const [checking, setChecking] = useState<boolean>(auth.hasToken());
  const [sessionMessage, setSessionMessage] = useState<string | null>(null);

  useEffect(() => {
    // Appelée par api.ts quand le serveur répond 401 (jeton expiré/invalide).
    setUnauthorizedHandler(() => {
      setUser(null);
      setSessionMessage("Votre session a expiré. Reconnectez-vous.");
    });

    // Au chargement : si un jeton est mémorisé, on vérifie qu'il est encore valide.
    if (auth.hasToken()) {
      api
        .me()
        .then(setUser)
        .catch((e) => setSessionMessage(errorMessage(e)))
        .finally(() => setChecking(false));
    }

    return () => setUnauthorizedHandler(null);
  }, []);

  function handleLoggedIn(loggedUser: User) {
    setSessionMessage(null);
    setUser(loggedUser);
  }

  function handleLogout() {
    auth.clear();
    setSessionMessage(null);
    setUser(null);
  }

  if (checking) {
    return <div className="auth-loading">Chargement...</div>;
  }

  if (!user) {
    return <Login onLoggedIn={handleLoggedIn} message={sessionMessage} />;
  }

  return <Shell user={user} onLogout={handleLogout} />;
}

export default App;