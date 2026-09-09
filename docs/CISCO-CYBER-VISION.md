# Cisco Cyber Vision: copertura del portale

## Contratti e autenticazione verificati

Il Center installato dichiara la versione `5.5.1`. Le due famiglie API sono raccolte in
sola lettura con credenziali separate:

- Classic Swagger `3.0.0-5.5.1`, base `/api/3.0`, token con permesso API Read.
- New UI Swagger `1.0.0-5.5.1`, base `/cvapi/v1`, token con ruolo predefinito Auditor.

Entrambe usano l'header `x-token-id`. Il ruolo Auditor è stato verificato `readOnly` sulle
aree pubbliche esposte dal Center. I token risiedono in due voci distinte di Windows
Credential Manager e non entrano in file, log, snapshot o release.

## Copertura Classic effettiva

Nel ciclo live del 3 agosto 2026 risultano disponibili:

- versione Center e stato per-capability;
- 3 Device, 25 componenti e 3 risk score per-device con fattori Cisco;
- 12 attività aggregate e 2 flow con lati, porte e direzione Cisco preservati;
- 4 categorie e 10 record evento cached del widget dashboard;
- distribuzione rischio e 6 record di distribuzione protocolli;
- catalogo generale di 3.576 vulnerabilità, ma zero associazioni device–vulnerabilità;
- 1 baseline e zero differenze;
- 1 CenterDPI e relativo dettaglio;
- zero report metadata.

Il contratto canonico espone zero vulnerabilità per-asset: i 3.576 elementi del catalogo
generale non vengono attribuiti arbitrariamente ai Device senza l'associazione restituita
dall'endpoint dedicato.

## Copertura New UI effettiva

Lo Swagger installato documenta dieci operazioni GET. Il collector corrente usa i cinque
endpoint aggregati verificati:

- `/assets`: 5 profili asset;
- `/assets/alerts`: tre query distinte `Active`, `Cleared` e `Muted`, tutte disponibili
  e con zero alert;
- `/assets/vulnerabilities`: capability disponibile, zero vulnerabilità;
- `/networks`: 11 reti OT;
- `/oh`: 1 livello di gerarchia operativa.

I profili includono, quando presenti, identità, vendor, attività temporale, gruppo
funzionale, interfacce, conteggi e associazioni sensore/PCAP. Le custom property inline
vengono conteggiate ma i valori arbitrari non sono pubblicati. Gli endpoint dedicati alle
custom property e il dettaglio `/assets/vulnerabilities/{cveId}` non sono ancora
normalizzati; con zero CVE aggregate non viene eseguita alcuna chiamata di dettaglio.

I profili New UI hanno identificativi propri e restano separati dai Device Classic. Zero
record da una capability disponibile significa realmente zero; `N/D` viene usato soltanto
quando la capability non è disponibile.

Alert e vulnerabilità New UI vengono trasformati in segnali operativi con fingerprint
stabile. Gli stati `Cleared` e `Muted` restano consultabili come storico; uno stato
sconosciuto viene mostrato in modo fail-safe e non scambiato per chiuso. Non viene
inferito alcun mapping verso un Device Classic.

## Eventi: cache API e feed completo

La Classic API documenta conteggi per severità e gli eventi cached del widget dashboard,
ma non espone una risorsa pubblica equivalente a uno storico eventi completo. I dieci
record raccolti vengono quindi etichettati esplicitamente come cache, con riferimento
al record sorgente.

Per eventi e alert continui Cisco prevede l'invio Syslog in formato CEF verso un receiver
o SIEM. Questa integrazione richiede configurazione amministrativa sul Center e un
receiver raggiungibile: è il canale corretto per la fase SIEM, non un endpoint Classic
inventato o uno scraping della UI.

La configurazione e il collaudo sono descritti in
[SIEM e rilevazione delle scritture Modbus](SIEM-AND-MODBUS-DETECTION.md). In sintesi:

- gli export JSON/CSV/ZIP e il nuovo bundle SIEM NDJSON/CEF di DTLab sono download
  manuali verificabili, non un feed continuo;
- il flusso continuo nativo è Syslog CEF, eventualmente integrato con Splunk;
- Variable Storage e Variable Processing devono essere abilitati e verificati sul
  sensore/template effettivo prima di dichiarare visibili gli accessi Modbus;
- Cisco documenta tipo `READ`/`WRITE`, componente e tempi, ma non il valore scritto;
- Monitor Mode confronta preset e baseline; una regola Snort custom per funzione o
  registro specifico resta `DA VALIDARE` sul motore installato;
- nessuna detection autorizza remediation automatica o scritture verso il PLC.

## Regole che evitano dati falsi

- Campi numerici assenti restano `null`, mai zero.
- Il `riskScore` Classic 0–100 non viene sostituito da formule DTLab.
- CVSS, CSRS e `riskScore` restano metriche diverse e non vengono confrontate o sommate.
- Il CSRS viene mostrato soltanto se presente nel payload New UI di una vulnerabilità.
- Un'associazione sensore o PCAP New UI non prova l'esistenza di un'entità API autonoma.
- I protocolli degli asset Classic derivano dai flow della finestra dichiarata.
- Le nuove raccolte conservano separatamente `left_asset_id` e `right_asset_id` anche
  nelle attività aggregate. Gli snapshot storici senza questi campi non vengono
  attribuiti per posizione: una direzione non basta a inventare l'origine.
- Un `targetId` baseline non viene scambiato per un flow.
- HTTP 402 sulla baseline significa funzione non licenziata, non errore di rete.
- La New UI viene richiesta con pagine da 500 record. Il collector segue il `Link`
  `rel=next`, conserva i metadati della prima risposta, rileva cursor ripetuti e impone il
  limite configurato di 500 pagine; il cursor non entra in errori, log o snapshot.
- Un link di pagina è accettato soltanto sullo stesso origin HTTPS e sullo stesso path
  `/cvapi/v1`. Il Center corrente, quando si forza `max=1`, pubblica un link assoluto con
  schema `http`: il guard lo rifiuta come `unsafe_pagination_link`. Con i conteggi correnti
  e `max=500` ogni endpoint usa una sola pagina, quindi il ciclo live non è impattato.

## CenterDPI: statistiche non disponibili

Lo Swagger Classic conferma
`GET /api/3.0/sensors/{id}/stats?p={periodo}`, con UUID e periodo obbligatorio fra `2h`,
`24h`, `7d`, `30d`, `180d` e `360d`.

Lista e dettaglio del CenterDPI rispondono HTTP 200 e lo stato operativo è `RUNNING`.
Le statistiche provate con `2h`, `24h` e `7d` restituiscono invece HTTP 500 con risposta
server-side `internal error`. Il collector classifica il risultato come `server_error`, la
sorgente Classic diventa `degraded` e CPU, RAM, disco, packet rate e uptime restano `N/D`.
Non è corretto descriverlo come feature assente: l'endpoint è documentato. Per ottenere le
metriche serve verificare la telemetria CenterDPI o aprire un approfondimento Cisco TAC.

## Stato complessivo

La sorgente New UI è `connected`; la sorgente Classic è `degraded` esclusivamente per
`sensor_stats`. Lo snapshot operativo resta quindi `partial`, approvabile soltanto dal
gate v1.1 con l'eccezione esatta e documentata
`sensor_stats/error/server_error`. Nessun'altra degradazione ha un bypass generico.
