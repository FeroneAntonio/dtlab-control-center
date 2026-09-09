import type { ReactNode } from "react";

export function Card({
  children,
  className = "",
  title,
  action,
}: {
  children: ReactNode;
  className?: string;
  title?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div
      className={`rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] shadow-[var(--shadow-card)] ${className}`}
    >
      {title && (
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-[var(--color-border)]">
          <h3 className="text-sm font-semibold text-[var(--color-ink)] tracking-tight">{title}</h3>
          {action}
        </div>
      )}
      <div className="p-5">{children}</div>
    </div>
  );
}

export function StatTile({
  label,
  value,
  hint,
  tone = "default",
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  tone?: "default" | "ok" | "warn" | "danger" | "brand";
}) {
  const toneColor = {
    default: "text-[var(--color-ink)]",
    ok: "text-[var(--color-ok)]",
    warn: "text-[var(--color-warn)]",
    danger: "text-[var(--color-danger)]",
    brand: "text-[var(--color-brand)]",
  }[tone];
  return (
    <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] shadow-[var(--shadow-card)] p-5">
      <div className="text-xs font-medium uppercase tracking-wider text-[var(--color-muted)]">
        {label}
      </div>
      <div className={`mt-2 text-3xl font-semibold tnum tracking-tight ${toneColor}`}>{value}</div>
      {hint && <div className="mt-1 text-xs text-[var(--color-faint)]">{hint}</div>}
    </div>
  );
}

const BADGE_TONES: Record<string, string> = {
  ok: "bg-[var(--color-ok-soft)] text-[var(--color-ok)] border-emerald-200",
  warn: "bg-[var(--color-warn-soft)] text-[var(--color-warn)] border-amber-200",
  danger: "bg-[var(--color-danger-soft)] text-[var(--color-danger)] border-red-200",
  brand: "bg-[var(--color-brand-soft)] text-[var(--color-brand)] border-indigo-200",
  purple: "bg-violet-50 text-violet-700 border-violet-200",
  neutral: "bg-slate-50 text-slate-600 border-slate-200",
};

export function Badge({
  children,
  tone = "neutral",
}: {
  children: ReactNode;
  tone?: keyof typeof BADGE_TONES;
}) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-xs font-medium ${BADGE_TONES[tone]}`}
    >
      {children}
    </span>
  );
}

export function Bar({ ratio, tone = "brand" }: { ratio: number; tone?: string }) {
  const color =
    {
      brand: "bg-[var(--color-brand)]",
      ok: "bg-[var(--color-ok)]",
      warn: "bg-[var(--color-warn)]",
      danger: "bg-[var(--color-danger)]",
    }[tone] ?? "bg-[var(--color-brand)]";
  return (
    <div className="h-2 w-full rounded-full bg-slate-100 overflow-hidden">
      <div
        className={`h-full rounded-full ${color} transition-all`}
        style={{ width: `${Math.round(Math.max(0, Math.min(1, ratio)) * 100)}%` }}
      />
    </div>
  );
}

export function Spinner({ label = "Caricamento…" }: { label?: string }) {
  return (
    <div className="flex items-center gap-3 text-[var(--color-muted)] text-sm py-10 justify-center">
      <div className="h-4 w-4 rounded-full border-2 border-[var(--color-brand)] border-t-transparent animate-spin" />
      {label}
    </div>
  );
}

export function ErrorNote({ message }: { message: string }) {
  return (
    <div className="rounded-xl border border-red-200 bg-[var(--color-danger-soft)] px-4 py-3 text-sm text-[var(--color-danger)]">
      {message}
    </div>
  );
}

export function PageHeader({ title, subtitle }: { title: string; subtitle?: string }) {
  return (
    <div className="mb-6">
      <h1 className="text-2xl font-semibold tracking-tight text-[var(--color-ink)]">{title}</h1>
      {subtitle && <p className="mt-1 text-sm text-[var(--color-muted)]">{subtitle}</p>}
    </div>
  );
}
