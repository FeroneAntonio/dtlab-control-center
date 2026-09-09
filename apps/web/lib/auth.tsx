"use client";

import { createContext, useContext, useEffect, useState } from "react";
import type { ReactNode } from "react";
import { api } from "./api";

interface AuthState {
  token: string | null;
  role: string | null;
  ready: boolean;
  signIn: (token: string) => Promise<void>;
  signOut: () => void;
}

const AuthContext = createContext<AuthState | null>(null);
const STORAGE_KEY = "dtlab.token";

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(null);
  const [role, setRole] = useState<string | null>(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    let active = true;
    async function restoreSession() {
      const stored = window.localStorage.getItem(STORAGE_KEY);
      if (!stored) {
        if (active) setReady(true);
        return;
      }
      try {
        const principal = await api.me(stored);
        if (active) {
          setToken(stored);
          setRole(principal.role);
        }
      } catch {
        window.localStorage.removeItem(STORAGE_KEY);
      } finally {
        if (active) setReady(true);
      }
    }
    void restoreSession();
    return () => {
      active = false;
    };
  }, []);

  const signIn = async (candidate: string) => {
    const principal = await api.me(candidate); // throws on invalid token
    window.localStorage.setItem(STORAGE_KEY, candidate);
    setToken(candidate);
    setRole(principal.role);
  };

  const signOut = () => {
    window.localStorage.removeItem(STORAGE_KEY);
    setToken(null);
    setRole(null);
  };

  return (
    <AuthContext.Provider value={{ token, role, ready, signIn, signOut }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth deve stare dentro AuthProvider");
  return ctx;
}
