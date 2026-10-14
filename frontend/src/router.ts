import { useEffect, useState } from "react";

/** Navigation par "hash" (#/findings/12) : pas de bibliothèque à installer. */
function currentPath(): string {
  const hash = window.location.hash.replace(/^#/, "");
  return hash === "" ? "/dashboard" : hash;
}

export function navigate(path: string): void {
  window.location.hash = path;
}

export function useRoute(): string {
  const [path, setPath] = useState<string>(currentPath());

  useEffect(() => {
    const onChange = () => setPath(currentPath());
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);

  return path;
}
