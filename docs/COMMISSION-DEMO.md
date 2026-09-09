# Demo commissione · 8 minuti

La demo deve raccontare un solo flusso: **rileva → contestualizza → assegna → verifica →
dimostra**. I dati operativi e lo Scenario Lab non vanno mai mescolati.

## Preflight (30 minuti prima)

1. Collegare manualmente `DTLAB CISCO` e attendere una raccolta riuscita; il task non
   connette né disconnette la VPN.
2. Verificare in Command Center `Snapshot: Live` o `Parziale`, età sotto 15 minuti,
   VMware/Cisco e qualità. `Parziale` è accettabile solo per l'eccezione nota
   `classic_sensor_stats_server_error`.
3. Verificare una volta le 16 route, il ticket di demo, i download JSON/CSV/ZIP e il
   banner permanente dello Scenario Lab.
4. Tenere pronto il manifest corrente con SHA-256 e il rollback della release precedente.
5. Non riavviare, spegnere o riconfigurare VM, PLC, Cisco Cyber Vision o rete.

## Sequenza parlata

### 0:00–0:45 · Command Center

> Questa è una console operativa, non un clone grafico: espone prima freschezza e verità
> del dato, poi il lavoro ancora da fare.

Mostrare stato snapshot, KPI ticket-first, SLA, score Cisco massimo e qualità DTLab.
Evidenziare che CVSS, risk score Cisco e qualità dati sono metriche diverse.

### 0:45–1:30 · Percorso end-to-end

Usare la barra `Rileva → Contestualizza → Valuta → Agisci → Dimostra`. Spiegare che ogni
passo apre una vista tecnica completa, ma il percorso resta comprensibile a colpo d'occhio.

### 1:30–2:30 · Topologia verificabile

Aprire `/topology` e mostrare in sequenza VMware osservata, OT Cyber Vision e vista
integrata. Sottolineare che i link tratteggiati/proposti non diventano fatti e che
`PLC-Desktop` è il target operativo confermato; `PLC-Ubuntu` resta legacy.

### 2:30–3:40 · Asset 360

Aprire `/assets`, scegliere il PLC e mostrare:

- score e provenienza Cisco;
- relazione Cisco↔VMware con metodo, confidenza e stato;
- flow, eventi e baseline esplicitamente correlati;
- segnali/ticket persistenti;
- profilo JSON stretto e dossier ZIP con manifest SHA-256.

Dire esplicitamente che il portale non correla entità soltanto perché nome o IP si
somigliano.

### 3:40–4:35 · Dossier CVE

Aprire `/vulnerabilities`, cercare una CVE e aprire il dossier. Mostrare la frase:

> Presente nel catalogo globale Cisco; nessuna associazione device–vulnerabilità
> restituita.

È una dimostrazione importante: catalogo globale non significa vulnerabilità presente sul
PLC. Mostrare CVSS e risk score device in campi separati e scaricare il dossier JSON.

### 4:35–6:15 · Segnalazione → ticket → remediation

Aprire una segnalazione, poi il ticket collegato. Mostrare owner, priorità, deadline SLA,
checklist manual-first, commento, transizione e audit append-only. Non eseguire azioni sul
PLC: il sistema governa il lavoro e conserva la prova, non automatizza modifiche OT.

### 6:15–7:05 · Evidenze

Aprire `/evidence`: snapshot canonico, JSON Schema, manifest, ZIP tecnico, ZIP pubblico
redatto e bundle per asset/segnale. Mostrare che il manifest contiene hash e identità dello
snapshot, quindi l'evidenza è verificabile e riusabile per clienti futuri.

### 7:05–8:00 · Scenario Lab

Aprire `/scenario-lab` e leggere il banner `SIMULAZIONE CONTROLLATA — NON DATI LIVE`.
Mostrare rapidamente il gap MITM, la telemetria Modbus fuori range, Purdue/IEC 62443 e il
trend. Presentarlo come banco prova deterministico per nuovi use case, mai come stato live.

## Fallback onesto

Se la VPN o il laboratorio non sono disponibili, non nascondere lo stato obsoleto. Dire:

> Il portale conserva l'ultimo snapshot immutabile verificato e ne mostra chiaramente
> l'età. Il dato operativo non viene inventato; per le capacità future uso il replay
> separato dello Scenario Lab.

La demo può continuare su ticket, audit, export e Scenario Lab. Non modificare timestamp,
stato o dati per farli apparire live.
