# DTLab OT Security Control Center

[![CI](https://github.com/FeroneAntonio/dtlab-control-center/actions/workflows/ci.yml/badge.svg)](https://github.com/FeroneAntonio/dtlab-control-center/actions/workflows/ci.yml)

DTLab Control Center è un cockpit operativo per laboratori OT/ICS. Riunisce in un
solo prodotto inventario VMware, dati Cisco Cyber Vision, topologia, rischio,
vulnerabilità, baseline, evidenze, rilevazioni endpoint e gestione completa dei
ticket. L'obiettivo è trasformare telemetria tecnica proveniente da più sorgenti in
un flusso verificabile: **rileva → correla → assegna → investiga → documenta**.

Il repository contiene il prodotto completo: dashboard Streamlit operativa,
frontend Next.js, API FastAPI, collector, contratti JSON, motore di correlazione,
ticketing SQLite, integrazione endpoint PLC, export SIEM, strumenti di deploy e test.
Non contiene credenziali, token, database operativi, snapshot reali o backup.

## Perché esiste

Cisco Cyber Vision rimane la fonte autorevole per inventario e visibilità di rete,
ma un SOC deve anche correlare VMware, distinguere dati osservati da inferenze,
gestire l'assegnazione agli operatori, produrre evidenze esportabili e rilevare casi
che possono non attraversare il sensore di rete, come una scrittura PLC→PLC locale.
DTLab aggiunge questo livello operativo senza falsificare o sostituire i dati Cisco.

## Architettura

```text
VMware ESXi ───────────────┐
                           ├─> Collector read-only ─> Snapshot firmati da SHA-256
Cisco Cyber Vision ────────┘                              │
                                                        ├─> Dashboard Streamlit
PLC endpoint audit ─> HMAC ingress ─> Segnali ──────────┤
                                                        ├─> Ticket + audit trail
                                                        ├─> Export JSON/CSV/CEF
                                                        └─> API FastAPI + Next.js
```

La dashboard non interroga direttamente gli apparati durante il rendering. Legge
snapshot validati e content-addressed, con puntatori atomici `current`, `previous` e
`last_known_good`. In questo modo una sorgente lenta o indisponibile non corrompe lo
stato mostrato e ogni evidenza resta riconducibile ai byte originali.

## Funzioni principali

- **Command Center ticket-first**: stato sorgenti, KPI, priorità, SLA, coda operativa,
  riemersione e raccomandazioni.
- **Topologia OT**: correlazioni esplicite tra VM e asset Cisco, flussi, zone Purdue,
  provenienza del dato e distinzione delle workstation di security test.
- **Asset 360**: inventario, protocolli, attività, score Cisco, vulnerabilità,
  baseline, segnali, ticket ed evidenze per singolo asset.
- **Cyber Vision Classic e New UI**: adapter separati, capability dichiarate e
  degradazione per sorgente senza trasformare l'assenza del dato in uno zero.
- **Rilevazione Modbus**: regole per funzioni di scrittura note e generiche, più
  audit endpoint per i percorsi locali non osservabili dal sensore di rete.
- **Ticketing persistente**: owner, priorità P1–P4 DTLab, stati, checklist,
  commenti, audit append-only, deduplicazione, ricorrenze ed export.
- **Operatori e orari aziendali**: anagrafica persistente, ruoli operativi e SLA
  calcolati su calendario configurabile.
- **Syslog/SIEM**: configurazione di receiver, protocollo e formato; export CEF e
  NDJSON. L'invio continuo resta disabilitato finché non viene configurato un
  receiver reale.
- **Evidence management**: snapshot JSON, manifest, hash, dossier asset/segnale e
  bundle ZIP riproducibili.
- **Scenario BeerFactory**: simulatore e script di collaudo forniti dall'azienda,
  dataset deterministico, Digital Twin Modbus, mapping MITRE ATT&CK for ICS,
  IEC 62443, NIS2 e dimostrazioni isolate dal dato reale.
- **Retention bounded**: gli snapshot raw vengono ricondotti a 100 dopo ogni ciclo
  di raccolta e da un timer di sicurezza indipendente.

## Modello di verità

Ogni informazione visualizzata conserva la provenienza:

- `observed`: restituita direttamente da Cisco, VMware o dal sensore endpoint;
- `derived`: calcolata deterministicamente da dati osservati;
- `operator_confirmed`: associazione dichiarata da un operatore;
- `unavailable`: dato non fornito dalla sorgente.

Lo score mostrato come Cisco Device Risk Score è esclusivamente quello ricevuto da
Cisco. Dati mancanti, cache parziali e sorgenti degradate restano visibili come tali.

## Rilevazione di rete ed endpoint

Il sensore Cisco osserva il traffico che attraversa il punto di cattura. Un processo
che scrive sul server Modbus ospitato sulla stessa macchina può invece usare il loop
locale e non raggiungere lo switch o la porta SPAN. L'integrazione
`integrations/plc_endpoint_audit/` copre questo punto cieco:

1. osserva le operazioni Modbus senza modificarle;
2. aggrega scritture uguali in episodi, evitando una crescita incontrollata;
3. firma gli eventi con HMAC e una catena hash;
4. usa uno spool locale limitato a 50 MiB;
5. invia gli eventi al receiver autenticato;
6. crea o aggiorna segnali e ticket senza duplicare lo stesso episodio.

L'endpoint audit integra Cyber Vision: non sostituisce DPI, SPAN o TAP.

## Struttura del repository

| Percorso | Contenuto |
|---|---|
| `src/dtlab/collector/` | Client read-only, raccolta e pubblicazione atomica |
| `src/dtlab/services/` | Snapshot, correlazione, segnali, ticket, export e policy |
| `src/dtlab/ui/` | Dashboard Streamlit usata nel deploy operativo |
| `apps/api/` | API FastAPI con bearer token e RBAC |
| `apps/web/` | Frontend Next.js alternativo |
| `integrations/plc_endpoint_audit/` | Sensore endpoint PLC compatibile Python 2.7 |
| `lab/beerfactory-company/` | Simulatore e otto script di collaudo aziendali, conservati integralmente |
| `schemas/` | Contratti JSON v2/v3 ed eventi Host OT |
| `config/` | Configurazioni di esempio e regole di detection |
| `deploy/` | Systemd, bootstrap, staging, produzione e rollback |
| `tools/` | Collector CLI, audit, release, retention e verifica |
| `tests/` | Test unitari, di contratto, sicurezza, UI e deployment |
| `docs/` | Architettura, runbook, Cisco, SIEM e procedure operative |
| `legacy/` | Versione precedente conservata solo per confronto |

## Avvio rapido della demo API + Next.js

Requisiti: Python 3.12+, Node.js 22+ e Git.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
pip install -r requirements.txt -r apps/api/requirements-api.txt
cp .env.example .env
```

Generare tre token casuali e sostituire esclusivamente i placeholder nel file
locale `.env`. Il file è ignorato da Git. Caricare quindi le variabili nel proprio
ambiente e avviare l'API:

```bash
uvicorn dtlab_api.main:app --app-dir apps/api --host 127.0.0.1 --port 8531
```

In un secondo terminale:

```bash
cd apps/web
cp .env.example .env.local
npm ci
npm run dev
```

Aprire `http://127.0.0.1:3000` e usare uno dei token creati localmente. Il provider
API usa per default il dataset BeerFactory sandbox; non contatta VMware o Cisco.

## Dashboard Streamlit

La dashboard operativa usa lo snapshot store validato:

```bash
pip install -e .
pip install -r requirements.txt
streamlit run app.py --server.address=127.0.0.1 --server.port=8517
```

Percorsi configurabili:

- `DTLAB_SNAPSHOT_STORE`: store content-addressed;
- `DTLAB_TICKET_STORE`: database SQLite dei ticket;
- `DTLAB_DEFAULT_OPERATOR`: operatore proposto dalla UI.

### Retention del ticket store

`scripts/prune_ticket_store.py` mostra soltanto il piano per default. Conserva 50 ticket
secondo lo stesso ordine della UI (`updated_at DESC, id`); l'ultimo ticket
`host_modbus_write` classificato `security_test` sostituisce, se necessario, il più vecchio
dei 50. Con `--retain 0` la protezione prevale e conserva quel solo ticket, se presente.

```bash
python3 scripts/prune_ticket_store.py --database /percorso/tickets.sqlite3
python3 scripts/prune_ticket_store.py --database /percorso/tickets.sqlite3 --apply
```

`--apply` crea prima un backup coerente tramite l'API SQLite e un manifest JSON con
SHA-256, poi elimina in una sola transazione ticket e dipendenze non conservati e i segnali
orfani. Il ledger `snapshot_ingests` resta intatto per impedire il reingest. Su un database
attivo è consigliabile fermare e riavviare esternamente dashboard, receiver Host OT e worker
di ingest; lo script non gestisce servizi né credenziali.

Per la raccolta reale copiare `config/dtlab.example.toml` in un file locale ignorato
da Git, impostare host e fingerprint TLS e registrare credenziali read-only nel
credential store del sistema operativo. Nessuna password viene accettata nel file di
configurazione versionato.

## Deploy su VM Ubuntu

Il deploy raccomandato usa una VM dedicata nella rete OT:

- Nginx come reverse proxy;
- dashboard e receiver Host OT come servizi systemd;
- collector schedulato ogni 30 secondi;
- retention dopo ogni raccolta e timer di sicurezza;
- release versionate sotto `/opt/dtlab-control-center/releases/`;
- symlink atomici `current` e `previous` per il rollback;
- database, chiavi e credenziali fuori dalla directory applicativa.

`deploy/vm_local_install.sh` documenta e automatizza la struttura. Prima di un
ambiente reale leggere [Deployment](docs/DEPLOYMENT.md),
[Runbook](docs/RUNBOOK.md) e [PLC Host Audit](docs/PLC-HOST-AUDIT.md).

## Scenari di collaudo BeerFactory

Il materiale fornito dall'azienda e già presente sulle VM è versionato integralmente
in [`lab/beerfactory-company/`](lab/beerfactory-company/). Comprende il simulatore,
lo sfondo grafico, il setup PLC, il launcher noVNC e gli otto script Modbus coperti
dalle regole Cyber Vision.

Gli script originali con loop continuo vanno eseguiti attraverso il launcher DTLab,
che accetta soltanto indirizzi privati e applica un limite massimo di 60 secondi:

```bash
python tools/run_company_lab_scenario.py attack_shutdown \
  --target <PLC_PRIVATE_IP> \
  --duration 10 \
  --authorized-lab
```

Consultare la [guida del bundle BeerFactory](lab/README.md) per inventario,
provenienza, collaudo controllato e vincoli operativi.

## Sicurezza e segreti

- Il repository non contiene token, password, chiavi private o snapshot reali.
- L'API non possiede token predefiniti: senza `DTLAB_API_TOKENS` le route protette
  restano inaccessibili.
- I client Cisco ed ESXi verificano il fingerprint TLS configurato.
- Il receiver endpoint richiede firma HMAC, timestamp valido, sensor ID e key ID.
- Le operazioni amministrative sono interattive e non accettano password sulla
  command line.
- Export pubblico e tecnico sono separati; l'export pubblico redige IP, MAC e altri
  identificatori operativi.

Consultare [SECURITY.md](SECURITY.md) prima di aprire una segnalazione.

## Verifica

```bash
python -m pytest -q
python -m pytest apps/api/tests -q
python -m ruff check src tools tests apps/api

cd apps/web
npm ci
npm run lint
npm run build
```

La pipeline GitHub Actions esegue automaticamente gli stessi controlli a ogni push
e pull request.

## Documentazione

- [Architettura](docs/ARCHITECTURE.md)
- [Cisco Cyber Vision](docs/CISCO-CYBER-VISION.md)
- [SIEM e detection Modbus](docs/SIEM-AND-MODBUS-DETECTION.md)
- [Audit endpoint PLC](docs/PLC-HOST-AUDIT.md)
- [Contratto snapshot v3](docs/SCHEMA-V3.md)
- [Runbook operativo](docs/RUNBOOK.md)
- [Deployment e rollback](docs/DEPLOYMENT.md)
- [Demo commissione](docs/COMMISSION-DEMO.md)
- [Bundle e scenari BeerFactory](lab/README.md)
- [Changelog](CHANGELOG.md)
- [Contribuire](CONTRIBUTING.md)

## Stato del progetto

La piattaforma è utilizzabile end-to-end nel laboratorio: raccolta, dashboard,
rilevazione Host OT, deduplicazione, creazione ticket, operatori, SLA, evidenze,
retention e rollback sono implementati e testati. Restano evoluzioni intenzionali,
non prerequisiti per il funzionamento attuale: autenticazione centralizzata SSO,
forwarder Syslog continuo verso un SIEM scelto dal cliente, alta disponibilità e
osservabilità infrastrutturale esterna.

## Uso responsabile

Gli strumenti di detection e laboratorio sono destinati esclusivamente ad ambienti
propri o esplicitamente autorizzati. Le regole incluse generano alert e non modificano
né bloccano il traffico industriale.
