"use client";

import { useState } from "react";
import { api, downloadFile } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { useAuth } from "@/lib/auth";
import { Card, ErrorNote, PageHeader, Spinner, StatTile } from "@/components/ui";

export default function EvidencePage() {
  const { token } = useAuth();
  const manifest = useApi(api.manifest, []);
  const assets = useApi(api.assets, []);
  const [assetId, setAssetId] = useState("");

  if (manifest.loading || assets.loading) return <Spinner />;
  if (manifest.error) return <ErrorNote message={manifest.error} />;
  const m = manifest.data;

  const dl = (url: string, name: string) => token && downloadFile(url, token, name);

  return (
    <div>
      <PageHeader
        title="Evidenze e report"
        subtitle="Bundle verificabili con manifest SHA-256. L'export tecnico può contenere IP e MAC dell'ambiente: condividerlo solo con personale autorizzato."
      />

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <StatTile label="Contract" value={m?.contract_version ?? "—"} tone="brand" />
        <StatTile label="Byte" value={m ? m.byte_length.toLocaleString("it-IT") : "—"} hint="snapshot canonico" />
        <StatTile label="SHA-256" value={`#${(m?.sha256 ?? "").slice(0, 8)}`} hint="content-addressed" />
        <StatTile label="Collezioni" value={m ? Object.keys(m.record_counts).length : "—"} />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
        <Card title="Download per integrazioni">
          <div className="space-y-2">
            <button onClick={() => dl(api.exportSnapshotUrl(), "dtlab-snapshot.json")}
              className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-2.5 text-sm text-left hover:border-[var(--color-brand)] transition">
              <div className="font-medium text-[var(--color-ink)]">⬇ Snapshot canonico (JSON)</div>
              <div className="text-xs text-[var(--color-faint)]">Oggetto verificato, byte-per-byte riproducibile.</div>
            </button>
            <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-2.5 text-sm">
              <div className="font-medium text-[var(--color-ink)]">Manifest dello store</div>
              <div className="text-xs text-[var(--color-faint)] font-mono break-all mt-1">
                {m?.snapshot_id}
              </div>
              <div className="text-xs text-[var(--color-faint)] font-mono break-all">
                sha256: {m?.sha256}
              </div>
            </div>
          </div>
        </Card>

        <Card title="Evidence bundle per asset">
          <p className="text-xs text-[var(--color-muted)] mb-3">
            Il bundle raccoglie soltanto record collegati esplicitamente all&apos;asset selezionato;
            non crea correlazioni inferite.
          </p>
          <div className="flex gap-2">
            <select value={assetId} onChange={(e) => setAssetId(e.target.value)}
              className="flex-1 rounded-lg border border-[var(--color-border-strong)] bg-[var(--color-surface)] px-3 py-2 text-sm">
              <option value="">Seleziona asset…</option>
              {(assets.data?.items ?? []).map((a) => (
                <option key={String(a.id)} value={String(a.id)}>{String(a.name)}</option>
              ))}
            </select>
            <button disabled={!assetId}
              onClick={() => dl(api.exportAssetUrl(assetId), "asset-evidence.json")}
              className="rounded-lg bg-[var(--color-brand)] px-4 py-2 text-sm font-semibold text-white disabled:opacity-40 hover:bg-[var(--color-brand-2)]">
              Scarica
            </button>
          </div>
        </Card>
      </div>

      <Card title="Manifest corrente">
        <pre className="text-xs font-mono overflow-x-auto text-[var(--color-ink-2)]">
{JSON.stringify(m, null, 2)}
        </pre>
      </Card>
    </div>
  );
}
