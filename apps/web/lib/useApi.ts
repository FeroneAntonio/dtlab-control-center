"use client";

import { useEffect, useState } from "react";
import { useAuth } from "./auth";

export function useApi<T>(
  fetcher: (token: string) => Promise<T>,
  deps: unknown[] = [],
) {
  const { token } = useAuth();
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!token) return;
    let active = true;
    Promise.resolve()
      .then(() => {
        if (!active) return null;
        setLoading(true);
        setError(null);
        return fetcher(token);
      })
      .then((d) => active && setData(d))
      .catch((e) => active && setError(e?.message ?? "Errore di rete"))
      .finally(() => active && setLoading(false));
    return () => {
      active = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token, ...deps]);

  return { data, error, loading };
}
