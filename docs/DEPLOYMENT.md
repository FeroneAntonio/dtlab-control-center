# Staging, produzione e rollback

## Principi

- Staging e produzione usano la stessa release immutabile e lo stesso SHA snapshot.
- Ogni operazione è dry-run per default e produce un token legato al piano; `--apply`
  accetta soltanto quel token esatto.
- Apache, porte pubbliche e VM non fanno parte del deploy applicativo.
- Lo store snapshot è read-only per l'app; il ticket store è separato e scrivibile solo
  dall'utente dashboard.
- Ogni attivazione conserva release precedente, stato systemd e backup SQLite coerente.

## Percorsi remoti

- release: `/var/www/clients/client1/web75/private/modbus-dashboard-releases/<id>`
- venv: `/var/www/clients/client1/web75/private/modbus-dashboard-venvs/<id>`
- symlink staging: `modbus-dashboard-staging-current` e
  `modbus-dashboard-staging-venv-current`
- symlink produzione: `modbus-dashboard-current` e `modbus-dashboard-venv-current`
- snapshot staging: `modbus-dashboard-data-staging`
- snapshot produzione: `modbus-dashboard-data`
- ticket staging: `modbus-dashboard-ticket-data-staging`
- ticket produzione: `modbus-dashboard-ticket-data`
- backup produzione: `/var/backups/dtlab-control-center-production`

Gli snapshot appartengono a `dtlab-publish:dtlab-dashboard`; `web75` legge tramite il
gruppo. I ticket store sono `web75:dtlab-dashboard`, directory `0700`, database/WAL/SHM
`0600`. Symlink e file speciali vengono rifiutati.

## Build verificabile

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check src tests tools deploy app.py
.\.venv\Scripts\python.exe tools\build_release.py --output-dir runtime\release-candidate
```

La release non contiene `runtime`, `legacy`, `.venv`, configurazione locale o segreti.
`requirements-server.lock` contiene solo il runtime server e viene installato con hash.

## Bootstrap staging

Eseguire come root sul server:

```bash
python3 staging_tool.py bootstrap
python3 staging_tool.py bootstrap --apply --confirm-plan <token-dry-run>
```

Il bootstrap crea/verifica gruppo, account publisher key-only, ACL minime, radici
immutabili, store staging con `objects/` e `manifests/`, e ticket store. È idempotente,
non installa chiavi e non tocca produzione o sito legacy.

## Dati staging

La raccolta resta locale. Dopo un ciclo fresco, pubblicare esplicitamente:

```powershell
.\.venv\Scripts\python.exe tools\live_sync.py --once `
  --allow-classic-sensor-stats-server-error
.\.venv\Scripts\python.exe tools\live_sync.py --once --publish-current `
  --target staging --allow-classic-sensor-stats-server-error
```

Il gate v1.1 richiede tutte le capability core, qualità minima, freschezza wall-clock,
assenza di demo e schema valido. L'unica eccezione ammessa è esattamente
`cisco_cyber_vision/sensor_stats/error/server_error`.

## Installazione staging

```bash
python3 staging_tool.py install --archive <release.tar.gz> --checksum <release.sha256>
python3 staging_tool.py install --archive <release.tar.gz> --checksum <release.sha256> \
  --apply --confirm-plan <token-dry-run>
```

Il tool verifica archivio e manifest, estrae senza sovrascrivere, crea il venv, installa
atomicamente le unità e cambia soltanto i symlink staging. Avvia l'app su loopback 8518,
esegue una prima ingestione ticket, verifica snapshot/ticket/health e solo dopo abilita:

- `modbus-dashboard-v2-staging.service`
- `modbus-dashboard-ticket-ingest-staging.service`
- `modbus-dashboard-ticket-ingest-staging.path`

Lo staging si prova tramite tunnel SSH locale; non richiede un vhost pubblico.

## Checklist staging

1. Tutte le 16 route senza eccezioni su desktop e 390 px; `scenario-lab` deve mostrare
   sempre il banner di simulazione e non deve leggere/scrivere ticket operativi.
2. Conteggi, topologia, PLC-Desktop e score uguali allo snapshot approvato.
3. Catalogo CVE separato dalle associazioni per Device.
4. Ticket da segnale, owner/priorità/SLA, transizione, task, commento e audit.
5. Persistenza ticket dopo restart e rollback/forward della sola app.
6. Export JSON/CSV/ZIP filtrati e hash evidenze verificabile.
7. Worker oneshot riuscito e path unit attiva.
8. Nessun comando o modifica verso PLC, VMware, Cisco o rete.

## Promozione produzione

1. Pubblicare in produzione lo stesso snapshot `current` già approvato in staging.
2. Eseguire il dry-run come root:

   ```bash
   python3 production_tool.py promote --release-id <release-id> \
     --allow-classic-sensor-stats-server-error
   ```

3. Applicare lo stesso piano con il token restituito.
4. Il tool richiede release/venv/unità identiche allo staging sano e SHA/manifest dati
   identici fra staging e produzione.
5. Il tool crea il ticket store, ferma in modo coerente l'ingest, salva stato e SQLite,
   cambia i symlink, installa le unità, riavvia solo il servizio web su 8517, esegue
   l'ingest iniziale e abilita il path solo a readiness completata.
6. Verificare loopback 8517, HTTPS autenticato, WebSocket ed export pubblici.

Unità produzione:

- `modbus-dashboard-v2.service`
- `modbus-dashboard-ticket-ingest.service`
- `modbus-dashboard-ticket-ingest.path`

## Rollback

Usare sempre il dry-run/token del comando `rollback`. Il rollback ripristina symlink,
unità, stato active/enabled e ticket database dal backup coerente. Attende anche un
eventuale oneshot riattivato dal path prima della verifica finale. Oggetti snapshot e
release immutabili non vengono cancellati.

Un file recovery marker root-only resta disponibile se un `BaseException` interrompe la
procedura fuori dal normale blocco di rollback.

## Attivazione near-real-time sul PC

Dopo il cutover, pianificare `tools/run_near_realtime.ps1` ogni minuto con:

- profilo Windows dell'utente che possiede il vault;
- esecuzione solo in sessione interattiva, senza password salvata nel task;
- istanze sovrapposte disabilitate;
- avvio consentito anche su batteria, senza arresto al passaggio da rete elettrica;
- nessuna connessione/disconnessione automatica della VPN.

Il ciclo pubblica staging e produzione, recupera il backlog dopo outage SSH e lascia
l'ultimo snapshot valido quando VPN o sorgenti non sono raggiungibili.
Le esecuzioni sovrapposte sono ignorate: il trigger resta a un minuto, mentre la cadenza
effettiva può essere 60–90 secondi in base a raccolta, backlog e latenza SSH.

## Rischi residui espliciti

- L'etichetta operatore del ticketing non è ancora SSO/RBAC: per uso multiutente continuo
  servono identità autenticata e ruoli.
- I dieci eventi Classic sono cache dashboard; il feed completo richiede Syslog/CEF.
- Le statistiche CenterDPI restano `N/D` finché l'endpoint Cisco HTTP 500 non viene
  risolto.
- Il PC e la VPN sono il punto di raccolta: task heartbeat e monitoraggio devono rendere
  visibile un'interruzione.
