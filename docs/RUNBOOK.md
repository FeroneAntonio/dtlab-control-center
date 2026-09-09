# Runbook operativo

## Regole inderogabili

1. Non spegnere, sospendere o riconfigurare alcuna VM.
2. `PLC-Desktop` è il target ufficiale; `PLC-Ubuntu` legacy resta accesa.
3. Usare solo account VMware di lettura e token Cisco read-only.
4. Non copiare credenziali in TOML, snapshot, log, ticket, export o documentazione.
5. In caso di errore mantenere l'ultimo snapshot verificato; non attivare dati demo.

## Credenziali locali

```powershell
.\.venv\Scripts\pythonw.exe -m dtlab.collector.credential_prompt esxi --username <ESXI_READ_ONLY_USER>
.\.venv\Scripts\pythonw.exe -m dtlab.collector.credential_prompt cybervision
.\.venv\Scripts\pythonw.exe -m dtlab.collector.credential_prompt cybervision-new-ui
```

Le finestre mascherano il valore e lo salvano in Windows Credential Manager. Il token
Classic usa API Read; il token New UI usa il ruolo Auditor, verificato `readOnly`. I due
token sono distinti e non sono intercambiabili.

## Sincronizzazione locale

```powershell
.\.venv\Scripts\python.exe -m dtlab.collector.sync --config config\dtlab.local.toml --local-only
```

Finché il publish resta disabilitato, l'output deve contenere `remote_published=false`.
Un ciclo con ESXi non valido fallisce prima di cambiare `current`.
Anche con un target configurato e abilitato, il default è locale: una pubblicazione remota
richiede sempre `--publish-target staging` oppure `--publish-target production`.

Per la pipeline applicativa usare `tools/live_sync.py`: separa intenzionalmente raccolta e
publish. Il wrapper `tools/run_near_realtime.ps1` li esegue in sequenza, mantiene un lock
anti-overlap, conserva 240 snapshot e pubblica il backlog approvato dopo un outage.

```powershell
.\tools\run_near_realtime.ps1 -Target staging,production
```

Il task non connette la VPN: se la VPN è assente il ciclo fallisce in sicurezza e lascia
attivo l'ultimo snapshot verificato. Il task pianificato deve essere eseguito con il profilo
Windows dell'utente che possiede le credenziali nel vault. Per un portatile, le opzioni
`DisallowStartIfOnBatteries` e `StopIfGoingOnBatteries` devono restare disattivate:
il fail-safe VPN protegge già la raccolta, mentre quei vincoli possono fermare silenziosamente
il near-real-time per giorni.

## Riferimento live corrente

Il ciclo del 3 agosto 2026 ha prodotto:

- stato `partial` e qualità dati 82/100;
- VMware: 5 VM, 9 NIC e 3 port group; host-network scope non disponibile;
- Classic: 3 Device, 3 risk score, 12 attività, 2 flow, 10 eventi, 1 baseline e 1 sensore;
- New UI: 5 profili asset, zero alert, zero vulnerabilità, 11 reti e 1 gerarchia;
- `sensor_stats`: HTTP 500 classificato `server_error`, metriche mostrate `N/D`.

I conteggi sono un riferimento di verifica, non valori hardcoded: se il laboratorio cambia,
la differenza deve essere spiegata dalla sorgente e dallo snapshot.

## Controlli prima di ogni publish

- VPN connessa e Internet ancora disponibile.
- Fingerprint TLS uguale a quello approvato.
- ESXi mostra tutte e cinque le VM `powered_on`.
- Nessuna azione VMware compare nel log.
- Sorgenti Classic e New UI presenti separatamente con capability esplicite.
- New UI autenticata con Auditor e Classic con API Read.
- Score PLC letto dalla proprietà Classic Cisco, senza formule DTLab.
- CVSS, CSRS e `riskScore` non combinati.
- Mapping componenti/flow preserva lati, porte e direzione Cisco.
- Profili New UI non sommati ai Device Classic e associazioni sensore/PCAP non promosse a
  entità autonome.
- Finestra attività/flow coerente con `window.from` e `window.to`.
- Snapshot conforme allo schema, senza segreti e con hash verificato.
- Gate staging eseguito in modalità rigorosa; uno stato `partial` non è approvato
  implicitamente.
- L'eventuale eccezione `sensor_stats=server_error` è accettabile soltanto dopo decisione
  esplicita e usando il flag dedicato del gate.

```powershell
.\.venv\Scripts\python.exe tools\verify_staging_snapshot.py --store runtime\store
```

Solo dopo l'approvazione dell'eccezione nota, il comando diventa:

```powershell
.\.venv\Scripts\python.exe tools\verify_staging_snapshot.py --store runtime\store --allow-classic-sensor-stats-server-error
```

## Smoke test UI

Verificare le 16 route:

- `/`, `signals`, `tickets`;
- `topology`, `assets`, `new-ui-inventory`, `flows`;
- `risk`, `events`, `vulnerabilities`, `baseline`;
- `sensors`, `vmware`, `sources`, `evidence`.
- `scenario-lab` (banner permanente `SIMULAZIONE CONTROLLATA — NON DATI LIVE`).

Su ogni route controllare assenza di eccezioni, layout mobile, valori `N/D`, fonte del dato
e assenza di score o conteggi sintetici. Nel flusso operativo creare un ticket di collaudo,
assegnare owner/priorità, registrare una transizione, una checklist e un commento; dopo il
riavvio dell'app verificare la persistenza e l'audit.

Controllare inoltre:

- manifest corrente e oggetto con SHA-256 coerente;
- worker ticket oneshot terminato con successo e path unit attiva;
- conteggio osservazioni incrementato una sola volta per snapshot;
- catalogo CVE globale separato dalle associazioni per Device;
- eventi Classic marcati `cached`, non presentati come feed completo;
- export JSON/CSV/ZIP scaricabili dopo filtri e selezioni.
- Asset 360 correlato soltanto tramite ID espliciti e dossier CVE senza inferenze.
- Scenario Lab separato dallo store e dal ticketing operativo, senza azioni o publish.

## Incidenti

- Token Classic 401/403: correggere o rigenerare un token API Read, senza aumentare i
  privilegi.
- Token New UI 401/403: correggere il token Auditor; i dati Classic restano indipendenti.
- TLS mismatch: fermare il ciclo e verificare il certificato fuori banda.
- Baseline 402: registrare `feature_unlicensed`; il resto del ciclo può restare valido.
- CenterDPI stats 500: mantenere dettagli sensore e stato `RUNNING`, mostrare metriche `N/D`
  e registrare `server_error`; non provare endpoint o metodi non documentati.
- New UI `unsafe_pagination_link`: non seguire il link e non disabilitare il controllo TLS;
  verificare che il Center pubblichi stesso origin HTTPS/path. Il cursor non deve essere
  riportato nei log o nei ticket.
- Snapshot `partial`: pubblicare soltanto se conforme alla policy e con motivazione visibile.
- Store corrotto: il portale tenta `last_known_good`, poi `previous`; mai dati demo.
- SSH pubblico non disponibile: continuare la raccolta locale; il publisher recupera in
  ordine gli archivi approvati mancanti e committa `current` per ultimo.
- Worker ticket fallito: mantenere lo snapshot visibile, correggere il ticket store e
  rilanciare l'unità oneshot; l'ingest è idempotente.

## Produzione

Una promozione è valida soltanto se staging e produzione usano la stessa release e lo
stesso SHA snapshot approvato, health/readiness sono verdi e il rollback conserva sia
servizi sia ticket. Seguire sempre [DEPLOYMENT.md](DEPLOYMENT.md); Apache e le VM restano
fuori dal perimetro del deploy applicativo.
