"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";

export default function LoginPage() {
  const { token, ready, signIn } = useAuth();
  const router = useRouter();
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (ready && token) router.replace("/");
  }, [ready, token, router]);

  const submit = async (candidate: string) => {
    setBusy(true);
    setError(null);
    try {
      await signIn(candidate);
      router.replace("/");
    } catch {
      setError("Token non valido o API non raggiungibile.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center px-4 bg-[var(--color-canvas)]">
      <div className="w-full max-w-md rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-8 shadow-[var(--shadow-pop)]">
        <div className="flex items-center gap-3 mb-6">
          <div className="h-11 w-11 rounded-xl bg-gradient-to-br from-indigo-500 to-violet-500 flex items-center justify-center text-white font-bold shadow-sm">
            DT
          </div>
          <div>
            <div className="text-lg font-semibold tracking-tight text-[var(--color-ink)]">
              DTLab Control Center
            </div>
            <div className="text-xs text-[var(--color-muted)]">Cockpit OT security · Relatech</div>
          </div>
        </div>

        <label className="text-sm font-medium text-[var(--color-ink-2)]">Token di accesso</label>
        <div className="mt-2 flex gap-2">
          <input
            type="password"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && value && submit(value)}
            placeholder="Bearer token…"
            className="flex-1 rounded-lg border border-[var(--color-border-strong)] bg-[var(--color-surface)] px-3 py-2 text-sm font-mono outline-none focus:border-[var(--color-brand)] focus:ring-2 focus:ring-indigo-100"
          />
          <button
            disabled={busy || !value}
            onClick={() => submit(value)}
            className="rounded-lg bg-[var(--color-brand)] px-4 py-2 text-sm font-semibold text-white disabled:opacity-40 hover:bg-[var(--color-brand-2)] transition"
          >
            Entra
          </button>
        </div>

        {error && <div className="mt-3 text-sm text-[var(--color-danger)]">{error}</div>}

        <p className="mt-6 border-t border-[var(--color-border)] pt-4 text-xs text-[var(--color-faint)]">
          Il token viene configurato dall’amministratore tramite secret store e non è incluso
          nel codice sorgente o nel browser.
        </p>
      </div>
    </div>
  );
}
