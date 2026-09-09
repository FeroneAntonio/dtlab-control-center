# Catalogo funzioni v2 — checklist di porting (parità + miglioramento)

Fonte: sorgente v2 in `src/dtlab/` (release `79c5e59bd19f80b2`, identica a modbus.sitoclone.it).
Obiettivo: portare **tutte** queste funzioni nel nuovo stack (FastAPI + Next.js), migliorarle,
e aggiungere i domini v3. Legenda stato nel nuovo cockpit: ✅ fatto · 🟡 parziale · ⬜ da portare.

## Disciplina trasversale (da preservare ovunque)
- **Truth-labeling** su ogni dato: real/observed/expected/unavailable/stale (demo solo sandbox). ✅ (contratto)
- **Separazione metriche**: riskScore Cisco (0–100) · CVSS (0–10) · CSRS · quality DTLab — MAI combinati. ✅ (contratto) · 🟡 (UI)
- **Capability-awareness**: assenza di dati ≠ zero. Se una capability Cisco non è stata acquisita, si mostra "N/D", non "0". ⬜
- **Catalogo separato dalle associazioni**: catalogo CVE globale ≠ associazioni per-device. ⬜
- **Nessuna azione automatica** su PLC/VM/rete/Cisco: tutto manual-first. ✅ (principio)
- **Fail-closed**: nessuno snapshot verificato → nessun dato demo, errore esplicito. ✅ (API provider)

## Sistema di punteggio (i punteggi vengono da Cisco Cyber Vision)
- **Risk score Cisco per-device** 0–100, bande basso 0–39 / medio 40–69 / alto 70–100, con timestamp di calcolo, fattori, completezza evidenza. Letto da Cisco, nessuna formula sostitutiva. 🟡 (mostrato in war-room; manca vista dedicata + distribuzione aggregata Cisco cached)
- **CVSS** 0–10 per vulnerabilità (temporal, vector, version) — separato dal risk score. ⬜
- **CSRS** New UI mostrato solo se restituito. ⬜
- **Quality score DTLab** 0–100 (copertura/affidabilità snapshot) + checks pass/warn/fail/not_available + coverage per sorgente. 🟡

## 1. Centro operativo

### 1.1 Command Center (cockpit) 🟡→⬜
- Live strip: stato (Live/Parziale/Obsoleto/Offline/Errore), freschezza, finestra Cisco, publication_mode. ⬜
- KPI cockpit: Score Cisco massimo · Asset Cyber Vision · Eventi recenti · Segnali da valutare · Ticket attivi (con P1/P2) · Qualità dati. 🟡 (ho una war-room diversa)
- Segnali prioritari: card ordinate per severità+recenza, con "passo operativo", sommario per tipo. ⬜
- Grafici: distribuzione rischio per-device (bar), eventi per severità (donut). 🟡
- Riepilogo infrastruttura: VM powered-on, target operativo, sensori operativi, attività+flow. ⬜
- Tabella sorgenti con stato/versione/ultimo successo/record/verità. ⬜

### 1.2 Segnalazioni (inbox operativa) ⬜ — GAP GRANDE
- Inbox deduplicata di eventi/finding/differenze-baseline/vulnerabilità/alert New UI.
- Logica actionable (esclude storici/accettati) e needs-review/riemersione (fatto riosservato dopo decisione).
- KPI: Segnali · Da valutare · Critici/alti · Riosservati.
- Filtri: ricerca full-text, tipo, severità, "solo da valutare", "includi storici".
- Tabella + dettaglio segnale con 3 tab: Presa in carico (crea ticket+checklist, riapri), Evidenze (bundle ZIP/JSON source-owned, download), Record sorgente.
- Priorità iniziale derivata da severità (critical→P1 … info→P4).

### 1.3 Ticket & remediation (workflow persistente) ⬜ — GAP GRANDE
- Store SQLite persistente, ingest idempotente dallo snapshot verificato.
- Macchina a stati 10 stati (new→acknowledged→investigating→remediating/waiting_ot→resolved→closed + false_positive/accepted_risk/suppressed) con transizioni consentite.
- **SLA** per priorità (P1/P2/P3/P4 ore), stati on_time/due_soon/overdue/stopped, deadline ancorata alla creazione, ricalcolo su cambio priorità.
- KPI registro: attivi · P1/P2 · non assegnati · riemersi · SLA scaduti · SLA in scadenza · chiusi/terminali.
- Filtri: ricerca, stato, priorità, owner, stato SLA. Export **CSV registro**.
- Workspace ticket 5 tab: Governance (owner/priorità, cambio stato con nota obbligatoria per stati decisionali) · Checklist (task manual-first da playbook per tipo segnale, aggiungi/aggiorna) · Commenti · Evidenze (JSON ticket, bundle) · Audit (timeline append-only).
- Identità operatore auto-dichiarata per audit.

## 2. Monitoraggio

### 2.1 Topologia (3 livelli) ⬜
- VMware osservata (VM ↔ port group) · OT Cyber Vision (comunicazioni) · Vista integrata (correlazioni esplicite). Grafi Plotly → da rifare con grafo interattivo moderno.

### 2.2 Asset ⬜ / 🟡
- Tabella asset filtrabile con export. 🟡 (ho tabella base, manca filtri/export ricchi)

### 2.3 Inventario New UI ⬜
- Inventario Cisco Cyber Vision New UI (5 profili), separato dai Device Classic.

### 2.4 Attività & flow ⬜
- Attività e flussi Modbus con conteggi pacchetti/byte, direzione, porte.

## 3. Sicurezza

### 3.1 Risk score Cisco ⬜ (vista dedicata)
- Distribuzione aggregata Cisco cached (total/high/medium/low) + dettaglio per-device (bar orizzontale) + tabella filtrabile (fascia, completezza, fattori, verità).

### 3.2 Eventi & triage ⬜
- Contatori dashboard Cisco (categorie, centers per severità) + lista eventi filtrabile + dettaglio + checklist triage.

### 3.3 Vulnerabilità ⬜
- Catalogo CVE globale ricercabile (query, CVSS minimo slider, solo-CVE) con export JSON/CSV · associazioni device–vulnerabilità esplicite · dettaglio (soluzione Cisco, vector, temporal, ack).

### 3.4 Baseline & differenze ⬜
- Baseline Cisco (capability-gated, 402 feature_unlicensed) + differenze (nuovi/cambiati componenti e attività) filtrabili.

## 4. Piattaforma

### 4.1 Sensori & DPI ⬜
- Sensori Cyber Vision con stats (cpu/mem/disk/uptime/pps/pacchetti/drop/snort/discovery).

### 4.2 Ambiente VMware ⬜
- Inventario VM read-only (power, guest OS, NIC, IP, tools, snapshot count).

### 4.3 Sorgenti & qualità ⬜
- Stato connettori + quality score + checks + coverage.

### 4.4 Evidenze & report ⬜
- Documenti report + export evidenze.

## 5. Motori / servizi (backend)
- ✅ contract (v2) + contract_v3 · ✅ snapshot store content-addressed · ✅ history/retention.
- ⬜ ticket_store (SQLite: ticket/task/commenti/audit/SLA) → esporre via API.
- ⬜ signal_ingest (fingerprint, occorrenze, riemersione semantica) → API.
- ⬜ exports (evidence bundle ZIP, ticket CSV/JSON, CVE JSON/CSV) → API.
- ⬜ playbooks (task manual-first per tipo segnale) → API.
- ⬜ redaction (IP/MAC per export) · identity linking.

## 6. Domini v3 nuovi (oltre il v2) — già presenti
- ✅ Attacchi & detection (timeline, copertura, latenza, gap MITM) · ✅ Digital twin Modbus · ✅ Compliance Purdue/62443/NIS2/ATT&CK · ✅ Trend/retention.

---
**Priorità di porting suggerita**: (1) Ticket+Segnalazioni (il gap più grande e più usato), (2) Risk/Eventi/Vulnerabilità/Baseline dedicati, (3) Command Center completo, (4) Topologia interattiva, (5) Piattaforma, (6) Inventario New UI + Attività/flow. In parallelo: capability-awareness e export ovunque.
