# Analisi dettagliata del sito v2 live (modbus.sitoclone.it)

Crawl completo del 2026-08-07 sulle 15 pagine, con Chrome autenticato. Snapshot
mostrato: **Obsoleto**, generato 03/08/2026 22:57:57, `sha256 2bcbedb2ec88…`,
contract 2.0.0, `publication_mode real_only`, età ~90 h. Record: 5 VM · 3 asset ·
3 risk score · 2 flow · 10 eventi · 0 vulnerabilità associate.

## Elementi comuni a ogni pagina
- Header con titolo + sottotitolo + 4 chip stato sorgenti: **VMware ESXi: Connessa · Cisco Cyber Vision: Degradata · Cisco New UI: Connessa · Snapshot: Obsoleto**.
- Banner giallo "Ultimo snapshot valido vecchio di 90 h … I dati restano visibili ma sono marcati Obsoleti".
- Sidebar 4 gruppi (Centro operativo / Monitoraggio / Sicurezza / Piattaforma), pulsante "Aggiorna dati", "Auto-refresh 15s".
- Ogni tabella dati ha: **Show/hide columns · Download CSV · Search · Fullscreen**; molte hanno anche Scarica JSON/CSV dedicati.
- Disciplina: valori "N/D" mai trasformati in 0 (capability-aware); truth badge "Obsoleta"; metriche mai combinate.

## 1. Command Center (/)
- **Live strip**: stato Obsoleto · Freschezza 90h · Finestra Cisco 02/08 22:57 → 03/08 22:57 · Pubblicazione real_only.
- **KPI cockpit (6)**: Score Cisco massimo **50/100** (plcubuntu · Medio) · Asset Cyber Vision **3** · Eventi recenti **10** · Segnali da valutare **12** · Ticket attivi **0** (0 P1/P2) · Qualità dati **82%**.
- **Priorità operative — Segnali da verificare**: card per severità (Evento Cisco, Finding ambiente) con "Passo operativo". Es: "IPv4 guest duplicato osservato" (172.16.10.10 su più VM), "New component detected", "Failed login attempt".
- **Indicatori Cisco**: bar "Distribuzione rischio per-device" (Basso/Medio/Alto) + donut "Eventi per severità".
- **Riepilogo infrastruttura**: VM powered on 5/5 · Target operativo PLC-Desktop · Sensori operativi 1/1 · Telemetria 12 attività · 2 flow.
- **Tabella sorgenti**: DTLab Collector (2.0.0.dev0), VMware ESXi, Cisco Cyber Vision (5.5.1…, 3608 record), Cisco New UI — tutte Obsoleta.

## 2. Segnalazioni (/signals)
- Campo **Operatore** (etichetta per audit, non autenticazione). Caption "Inbox allineata allo snapshot 2bcbedb2ec88 · deduplicazione attiva".
- **KPI (4)**: Segnali · Da valutare · Critici/alti · Riosservati.
- **Coda operativa** — filtri: Cerca · Tipo (multiselect) · Severità (multiselect) · toggle "Solo da valutare" · toggle "Includi storici".
- **Tabella**: Severità · Tipo · Titolo · Ultima osservazione · Snapshot osservati · Asset espliciti · Ambito (Operativo/Storico) · Ticket (Da valutare/Aperto/Riemerso). Tipi visti: Evento Cisco, Finding DTLab. Es: Failed login, New component detected, "Baseline 'Traffico Normale OT' got 2 differences", "Modalità di cattura DPI non verificata".
- **Dettaglio segnale** (selectbox "Apri segnalazione") con 3 tab: **Presa in carico** (Priorità iniziale, Owner, "Crea ticket e checklist" — richiede operatore) · **Evidenze** (JSON + "Scarica evidence bundle") · **Record sorgente** (payload). Mostra Fonte (`src:cisco-cyber-vision:dtlab-01 dashboard-event:…`), snapshot osservati, asset correlati.

## 3. Ticket e remediation (/tickets)
- Campo Operatore. **KPI (7)**: Ticket attivi · P1/P2 · Non assegnati · Riemersi · SLA scaduti · SLA in scadenza · Chiusi/terminali.
- Stato attuale: **Nessun ticket creato** (0). Il registro completo compare quando esistono ticket, con: filtri (Cerca/Stato/Priorità/Owner/SLA), export **CSV registro**, tabella (Priorità, Stato, Titolo, Owner, SLA, Tempo SLA, Deadline, Aggiornato, Riemerso, Tipo segnale) e **workspace ticket a 5 tab**: Governance (owner/priorità + cambio stato con nota obbligatoria), Checklist (task manual-first da playbook), Commenti, Evidenze (JSON ticket + bundle), Audit (timeline append-only). Macchina a 10 stati, SLA per priorità.

## 4. Topologia (/topology)
- Segmented control **3 livelli**: VMware osservata · OT Cyber Vision · Vista integrata. Grafo (VM = cerchi, Port group = rombi, NIC = linee). Livello VMware: 5 VM (CyberVision-with-DPI, HMI-Ubuntu, Kali-Linux, PLC-Desktop, PLC-Ubuntu) ↔ port group (LB, PG-CV-DPI, PG-OT-LAB). Caption: le linee provano solo VM↔port group; VLAN/subnet non dedotte.

## 5. Asset (/assets)
- "Inventario Cyber Vision con score, vulnerabilità e protocolli osservati nei flow". Filtri: Cerca/Tipo/Vendor/Fascia.
- **Tabella**: Nome · Tipo · Vendor · IP · Protocolli osservati (finestra) · **Score Cisco** · Fascia · Vulnerabilità associate · Ultima attività. Righe: 172.16.10.30 (Device, score 10, Basso) · 172.16.10.20 (Web Server, 30, Basso) · plcubuntu (Controller, 50, Medio). Export JSON/CSV. Sotto: "Dettaglio asset".

## 6. Inventario New UI (/new-ui-inventory)
- "Profili asset, reti OT, gerarchia, alert e vulnerabilità dalla API New UI, separati dai Device Classic".
- **KPI (4)**: Profili asset **5** · Alert New UI **0** · Vulnerabilità New UI **0** (CSRS e CVSS separati) · Reti OT **11** (livelli gerarchia).
- Nota: profili con id diversi dai Classic; non altera topologia/flow/risk Classic.
- **3 tab**: Profili asset (tabella: Profilo, Tipo, Vendor, Interface, Gruppo funzionale, Alert attivi, Vulnerabilità, Sensori associati, PCAP associati) · Reti e gerarchia · Alert e vulnerabilità.

## 7. Attività e flow (/flows)
- Finestra 02/08 → 03/08 22:57:53. **Distribuzione protocolli Cisco** (cached): ICMP 9 · IPv6 8 · ARP 3 · Others 3 · Multicast DNS 2 · RARP 2. Export JSON/CSV. Sotto: "Attività osservate · Flow" (singoli flow con componenti/contatori/timestamp).

## 8. Risk score Cisco (/risk)
- "Punteggi per-device letti da Cisco Cyber Vision, senza formule DTLab sostitutive".
- **Distribuzione aggregata Cisco** (cached): Device 3 · Alto 0 · Medio 1 · Basso 2.
- **Dettaglio per-device**: Asset con score 3 · Alto 0 (70–100) · Medio 1 (40–69) · Basso 2 (0–39). Bar orizzontale (plcubuntu 50, .20 30, .30 10) + tabella filtrabile (Asset, Score, Fascia, Ultimo calcolo, Fattori, Completezza, Verità).

## 9. Eventi (/events)
- "Eventi recenti aggregati dal widget Cisco cached, senza associazioni ad asset inventate".
- **Contatori dashboard Cisco**: Anomaly Detection 1 · Extension-based alert 0 · Security Events 24 · Signature based 0 (con Cerca + download JSON/CSV).
- **Lista eventi** filtrabile: Cerca/Severità/Categoria/Center. Dettaglio evento + **checklist triage** (4 passi).

## 10. Vulnerabilità (/vulnerabilities)
- "Catalogo CVE Cisco ricercabile e associazioni device–vulnerabilità esplicite, CVSS sempre separato dal Cisco Security Risk Score".
- **Catalogo globale Cisco**: Catalogo **3576** · CVE indicizzate **3576** · CVSS massimo **10.0** · Associate agli asset **0**. Filtri: Cerca · CVSS minimo (slider) · Solo CVE. Tabella (CVE/ID, Titolo, CVSS, Versione CVSS, Pubblicata, ID Cisco, Vendor ID) + export JSON/CSV. Es: CVE-2002-20001 (Siemens SCALANCE, 7.5), CVE-2005-2946 (OpenSSL).
- Sotto: associazioni device–vulnerabilità (0) con dettaglio (soluzione, vector, temporal, ack).

## 11. Baseline (/baseline)
- **KPI**: Baseline 1 · Differenze 0 · Nuovi elementi 0. Filtri Cerca/Stato. Tabella: Nome "Traffico Normale OT" (active), Creata, Periodo da/a, Ultimo/Prossimo scan, Nuovi/cambiati componenti+attività. Export JSON/CSV. Differenze: "Nessuna differenza restituita". (Gestisce anche 402 feature_unlicensed.)

## 12. Sensori e DPI (/sensors)
- **KPI**: Sensori 1 · Operativi 1 · Stats disponibili N/D · Versioni note 0. Filtri Cerca/Tipo/Stato/Capture mode. Tabella: Nome CENTER-ETH2, Tipo CenterDPI, Stato RUNNING, IP/Capture/Versione/Ultimo contatto/CPU/RAM/Disk/Packet/Uptime/Snort/Discovery (N/D), Verità Obsoleta. Nota capability-aware: "i campi N/D non diventano zero".

## 13. Ambiente VMware (/vmware)
- **KPI**: VM 5 (5 on) · vCPU 16 · RAM 80 GB · Disco 365 GB · Snapshot 0. Filtri Cerca/Power/Lifecycle/Target ufficiale.
- **Tabella**: VM, Power, Ruolo, Lifecycle, KPI scope, Target ufficiale, vCPU, RAM, Disco, Tools, IP guest, Verità. Righe: CyberVision-with-DPI (8/64/250, IP management redatto) · HMI-Ubuntu (172.16.10.20) · Kali-Linux (tools not_installed, IP N/D) · **PLC-Desktop (Target ufficiale Sì, 172.16.10.10)** · PLC-Ubuntu (legacy, 172.16.10.10 = IP duplicato → origine del finding).

## 14. Sorgenti e qualità (/sources)
- **KPI**: Stato snapshot stale (90h) · Qualità dati **82%** · Schema 2.0.0 · Pointer current (2bcbedb2ec88). Filtri Cerca/Tipo/Stato.
- **Tabella sorgenti**: Sorgente, Tipo, Stato, Versione, Ultimo tentativo, Ultimo successo, Record, Errore, Verità. Conferme operative (8) · DTLab Collector (2.0.0.dev0, 3) · VMware ESXi (22) · Cisco Cyber Vision (Degradata, 3608, errore partial_capabilities) · Cisco New UI (17). Export JSON/CSV. Sotto: sezione **Capability** (dettaglio per-capability di ogni sorgente).

## 15. Evidenze e report (/evidence)
- Warning: "L'export tecnico contiene IP e MAC… Il token API non entra mai negli snapshot o negli export".
- **Report Cisco disponibili**: Nessun report configurato.
- **Bundle DTLab**: Bundle tecnico (indirizzi completi, CSV, snapshot, manifest) · Bundle pubblico redatto (IP/MAC pseudonimizzati coerenti).
- **Download JSON per integrazioni**: Snapshot canonico · JSON Schema · Manifest dello store.
- **Evidence bundle per asset** (selettore asset) · **Evidence bundle per evento/finding** (selettore) · **Manifest corrente** (JSON con sha256, object_name, record_counts…).

---
Vedi la checklist di porting in `V2-FEATURE-CATALOG.md`.
