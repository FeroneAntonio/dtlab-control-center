# SIEM e rilevazione delle scritture Modbus

## Scopo e stato

Questo documento definisce il percorso verificabile da traffico OT a segnalazione:

```text
PLC/HMI/Kali -> Sensor o CenterDPI -> Cyber Vision -> evento/alert CEF
             -> receiver SIEM -> segnale DTLab -> ticket -> evidenza
```

Non documenta una funzione già attiva. Al momento non è stata verificata una
connessione SIEM continua e non è stato eseguito il collaudo delle scritture Modbus qui
descritto. Ogni esito resta `NON VERIFICATO` finché non esiste evidenza datata e
riconducibile al test autorizzato.

## Evidenza live osservata il 1 settembre 2026

Una raccolta read-only fresca da ESXi e Cisco Cyber Vision ha verificato questi fatti:

- la baseline `Traffico Normale OT` è attiva;
- una differenza `new_component` è associata esplicitamente, tramite `asset_ids`,
  all'asset Kali confermato (`172.16.10.30`);
- una seconda differenza `new_activity`, rilevata nello stesso ciclo baseline, non
  contiene un'associazione esplicita ad asset e resta quindi globale e non attribuita;
- l'evento Cisco cached riporta due differenze baseline, ma non contiene `asset_ids`;
- la finestra corrente non restituisce flow né attività `Write Var`/Modbus collegabili;
- PLC-Desktop, HMI, Kali e Cyber Vision risultavano accese; la VM PLC-Ubuntu legacy era
  già spenta. Nessuna power action è stata eseguita.

Il portale mostra la prima evidenza come `Kali · nuovo componente rilevato` in Command
Center, Eventi e Topologia. Mostra separatamente il record globale non attribuito. Questa
è una deviazione baseline reale da classificare, non la prova di un attacco, di una
scrittura Modbus, della tecnica usata o dell'origine della seconda attività. La matrice
usa soltanto identity link confermati e `asset_ids` espliciti; non correla per titolo,
timestamp, IP testuale o semplice co-occorrenza.

La VM Kali non espone SSH e non ha VMware Tools disponibili. Il percorso e il contenuto
dello script citato dal collega non sono quindi stati verificati dalla console guest:
servono accesso console VMware oppure il percorso consegnato dal proprietario dello
script prima di qualunque test controllato.

## Requisiti ricavati dalle call e dalle trascrizioni disponibili

Le call richiedono di:

- collegare PLC, HMI, Kali e Cisco Cyber Vision usando dati reali, eliminando dal
  percorso operativo il database dimostrativo;
- usare PLC-Desktop come target operativo e l'HMI per produrre traffico Modbus normale;
- verificare in Cyber Vision che il traffico normale e le successive prove controllate
  siano effettivamente osservati;
- costruire prima una baseline del comportamento lecito e soltanto dopo avviare la fase
  di test da Kali;
- distinguere una scrittura HMI autorizzata da una scrittura Kali di verifica;
- conservare per ogni prova timestamp, sorgente, destinazione, funzione, registro,
  valore richiesto, risultato applicativo e prova Cyber Vision;
- mostrare nel portale topologia, evento, segnalazione, ticket ed evidenza senza
  attribuire a Cisco dati non restituiti;
- prevedere un flusso futuro verso SIEM, senza dichiararlo connesso prima del collaudo;
- lavorare anche in condizioni di connettività limitata, preparando dipendenze e
  materiali offline senza cambiare autonomamente rete, port group o route.

Le trascrizioni e il materiale storico citano Run/Stop `0x10` e Reset `0x09`. Sono
riferimenti da confermare con il proprietario OT e con il mapping effettivo del PLC:
non autorizzano una scrittura e restano esclusi dalla prima campagna perché possono
modificare lo stato operativo. Qualunque prova usa un registro innocuo dedicato, un
valore reversibile e una finestra approvati prima dell'esecuzione.

## Due canali diversi: export DTLab e feed continuo Cisco

### Export manuale DTLab

La pagina `/evidence` produce su richiesta snapshot JSON, CSV e bundle ZIP tecnici o
pseudonimizzati. Produce inoltre un export SIEM tecnico dei segnali in NDJSON e CEF con
vendor `DTLab`, disponibile anche come ZIP con JSON Schema, manifest e SHA-256. Questo canale è
adatto a collaudi di ingest, dossier, allegati ticket, audit e consegne puntuali. Non è
il CEF nativo Cisco e non deve essere presentato come integrazione SIEM continua.

### Syslog CEF e Splunk

Cisco Cyber Vision inoltra eventi e alert a un receiver Syslog/SIEM. In 5.5.x la
configurazione è in **Admin > System > Syslog configuration** e supporta UDP, TCP e
TCP+TLS; con TLS occorre il certificato P12 fornito dall'amministratore SIEM. Da 5.3 i
formati operativi sono CEF e CEF Extended Time Precision.

L'export si abilita inoltre per gli eventi Classic in **Admin > Events** e per gli alert
New UI in **Configuration > Alerts > tipo di alert > Syslog Notification**. Il CEF può
contenere identificativi di evento, severità, categoria, messaggio, componenti e
metadati di flow. Le proprietà di flow sono dipendenti dal protocollo e Cisco non le
enumera in modo esaustivo: indirizzo registro e valore Modbus non vanno promessi finché
non compaiono nel payload reale.

L'integrazione Cisco con Splunk usa due canali distinti:

- HTTPS/API dal receiver verso il Center per dati inventariali e di contesto;
- Syslog dal Center verso Splunk per eventi e alert.

Cisco sconsiglia di abilitare contemporaneamente l'input Events e la sorgente Syslog per
lo stesso Center perché raccolgono la stessa informazione. La scelta deve quindi essere
esplicita e accompagnata da una strategia di deduplicazione.

Fonti ufficiali:

- [Administration Guide 5.5.x: monitoraggio, Syslog e Snort](https://www.cisco.com/c/en/us/td/docs/security/cyber_vision/Release-5-5-x/Admin-guide/b-cisco-cyber-vision-administration-guide-release-5-5-x/m-maintain-and-monitor-cisco-cyber-vision.html)
- [Formato delle notifiche Syslog CEF](https://www.cisco.com/c/en/us/td/docs/security/cyber_vision/publications/syslog/b_Cisco_Cyber_Vision_Syslog_notification_format_Configuration_Guide/m_log-format.html)
- [Integrazione ufficiale Cisco Cyber Vision con Splunk](https://www.cisco.com/c/en/us/td/docs/security/cyber_vision/integrate-cisco-cyber-vision-with-splunk.html)

## Procedura truth-first

### 1. Abilitare la visibilità delle variabili

Queste operazioni richiedono approvazione e un ruolo Cisco adeguato.

1. Verificare che CenterDPI o il sensore previsto osservi davvero il traffico
   PLC-HMI; la sola presenza della NIC VMware non dimostra la cattura.
2. In **Admin > Data Management > Ingestion Configuration**, abilitare **Variable
   Storage** e salvare. Cisco lo lascia disabilitato per impostazione predefinita.
3. In **Admin > Sensors > Templates**, modificare il template assegnato al sensore.
4. Per il protocollo che offre variable inspection, selezionare **Variable Processing**
   e salvare.
5. Generare una sola lettura HMI autorizzata e cercarla in **Explore > All Data >
   Device list > dispositivo > Variable > Automation**.
6. Registrare nome variabile, tipo `READ` o `WRITE`, componente, primo e ultimo accesso.

Cisco documenta questi campi, ma specifica che la tabella non mostra il valore della
variabile. Il valore richiesto può essere conservato nel log del generatore HMI/Kali,
marcato come evidenza della sorgente di test e non come valore restituito da Cisco.

Fonte ufficiale:
[Administration Guide 5.5.x: Variable accesses](https://www.cisco.com/c/en/us/td/docs/security/cyber_vision/Release-5-5-x/Admin-guide/b-cisco-cyber-vision-administration-guide-release-5-5-x/m-introduction-to-cyber-vision.html).

### 2. Costruire e monitorare la baseline

1. Creare un preset ristretto a PLC-Desktop, HMI, rete OT, sensore e activity tag
   realmente disponibili.
2. Acquisire la baseline durante una finestra di traffico normale approvata.
3. Da **Monitor > Monitored preset settings**, impostare intervallo, baseline attiva,
   severità e differenze di componenti, proprietà e attività da osservare.
4. Ripetere le operazioni HMI lecite e includerle nella baseline solo dopo verifica.
5. Per una differenza, usare **Investigate with flows**. `Acknowledge` la classifica come
   normale; `Report` crea un evento. Conservare commento, operatore e orario.

Monitor Mode rileva deviazioni rispetto alla baseline; la documentazione pubblica non
dimostra un filtro nativo per il singolo indirizzo di registro.

### 3. Valutare una regola Snort custom

Usare questa strada soltanto se Variable Processing e Monitor Mode non soddisfano il
caso d'uso e dopo un test offline della sintassi supportata dal motore installato.

1. Verificare licenza, piattaforma del sensore e stato IDS. Sul Center DPI Snort è
   abilitato per impostazione predefinita; sui sensori compatibili va abilitato.
2. Esportare o consultare le regole disponibili e verificare se esiste già una firma
   pertinente, senza assumere che la categoria Experimental-Scada copra ogni write.
3. Preparare una regola custom `alert` limitata a sorgente, destinazione, porta, Unit ID,
   funzione e registro concordati. Nessuna azione `drop`.
4. Validare la regola su PCAP controllato e sullo stesso motore/versione installato.
5. Importare da **Admin > Snort > Import custom rules file**, sincronizzare soltanto il
   sensore approvato e verificare l'alert.
6. Misurare falsi positivi con traffico HMI normale prima di estendere lo scope.

Cisco documenta l'import di regole custom, ma la guida pubblica Cyber Vision 5.5.x non
fornisce una regola di esempio per estrarre indirizzo e valore di uno specifico registro
Modbus. Finché la compatibilità non è provata in laboratorio, lo stato resta
`DA VALIDARE`, non `SUPPORTATO`.

## Matrice di test controllata

Tutte le righe partono da `NON ESEGUITO`. Compilare gli esiti solo con evidenza.

| ID | Origine | Azione proposta | Risultato PLC atteso | Evidenza Cisco attesa | Esito |
|---|---|---|---|---|---|
| T0 | HMI | Lettura ciclica dei registri approvati | Nessuna modifica di processo | Activity/flow Modbus e accesso `READ` | NON ESEGUITO |
| T1 | HMI | Ripetizione di una scrittura lecita già prevista dallo scenario | Nessun comportamento inatteso | Accesso `WRITE`, componente HMI e timestamp | NON ESEGUITO |
| T2 | HMI o PLC | Una scrittura su registro innocuo dedicato e concordato | Valore di test reversibile | Accesso `WRITE`, origine interna e policy prevista | NON ESEGUITO |
| T3 | Kali | Discovery passiva o connessione TCP/502 autorizzata | Nessuna modifica | Nuovo flow/attività o differenza baseline | NON ESEGUITO |
| T4 | Kali | FC06 verso registro innocuo concordato | Valore di test reversibile | Accesso `WRITE` e differenza/evento secondo policy | NON ESEGUITO |
| T5 | Kali | Ripetizione di T4 con la policy IDS candidata attiva | Valore di test reversibile | Alert Snort o evento baseline, se configurato | NON ESEGUITO |
| T6 | HMI | Ripetizione operazione lecita dopo T4/T5 | Funzionamento normale | Nessun falso positivo critico non gestito | NON ESEGUITO |
| T7 | SIEM | Ricezione dell'evento/alert di test | Nessun impatto OT | CEF con ID, tempo, severità e riferimenti osservati | NON ESEGUITO |
| T8 | DTLab | Ingest, deduplica, ticket ed evidence | Nessun comando verso PLC | Ticket correlato a snapshot/payload e manifest | NON ESEGUITO |

Per ogni riga conservare: autorizzazione, inizio/fine finestra, operatori, IP/MAC reali,
funzione, Unit ID, registro, valore richiesto, stato iniziale/finale PLC, PCAP se
autorizzato, ID evento/alert, CEF originale, ticket DTLab e hash delle evidenze.

## Decisioni ancora mancanti

| Decisione | Owner richiesto | Stato iniziale |
|---|---|---|
| Receiver scelto: Splunk, altro SIEM o receiver CEF temporaneo | Responsabile SIEM | DA DECIDERE |
| Host, porta, protocollo e certificato TCP+TLS | Rete/SIEM | DA DECIDERE |
| Canale Splunk: Events input oppure Syslog, non entrambi senza deduplica | SIEM | DA DECIDERE |
| Retention, indice, sourcetype, timezone e sincronizzazione NTP | SIEM | DA DECIDERE |
| Sensore/template che osserva PLC-HMI-Kali | Cyber Vision/OT | DA VERIFICARE |
| Supporto Variable Processing per il Modbus realmente osservato | Cyber Vision | DA VERIFICARE |
| Registro innocuo, Unit ID, valori e rollback applicativo | Proprietario PLC | DA APPROVARE |
| Finestra e Rules of Engagement Kali | OT/Security | DA APPROVARE |
| Necessità e sintassi della regola Snort custom | Cyber Vision/Security | DA VALIDARE |
| Mapping CEF -> fingerprint/severità/asset/ticket DTLab | DTLab/SOC | DA DEFINIRE |
| Dati tecnici da pseudonimizzare negli export e nel SIEM | Privacy/Security | DA DEFINIRE |

## Criteri di accettazione

La funzione può essere dichiarata completata soltanto quando:

1. PLC-Desktop, HMI e Kali sono identificati senza inferenze e la sorgente di ogni test
   è distinguibile.
2. Il sensore o CenterDPI vede il flow autorizzato e Variable Processing restituisce
   almeno tipo, componente e tempi, oppure il limite è documentato come indisponibile.
3. Le operazioni HMI lecite non generano un volume di falsi positivi incompatibile con
   l'uso operativo.
4. Il test Kali concordato produce la detection prevista oppure un gap documentato; un
   mancato evento non viene trasformato in successo.
5. Il receiver conserva il CEF originale con tempo coerente e riferimenti sufficienti a
   correlare asset e prova.
6. DTLab crea o aggiorna un solo segnale/ticket secondo la policy di deduplicazione e
   conserva evidenza verificabile.
7. La UI distingue fatto Cisco, dato del generatore di test e inferenza DTLab.
8. Il PLC torna allo stato iniziale verificato; nessuna VM, rete o configurazione Cisco
   viene modificata fuori dal change approvato.
9. Un test negativo prova che traffico fuori scope non crea ticket ingannevoli.
10. Runbook, owner e procedura di disabilitazione sono approvati.

## Sicurezza OT, stop e rollback

- Nessun test senza change, Rules of Engagement, registro/valore consentiti, operatore
  OT presente e criterio di stop.
- Acquisire e verbalizzare lo stato iniziale del PLC. Predisporre il comando applicativo
  di ripristino, ma non eseguirlo automaticamente dal portale.
- Procedere una richiesta alla volta; vietati scan aggressivi, flood, scritture multiple
  e test su registri non mappati.
- Al primo comportamento inatteso: interrompere Kali/HMI di test, non spegnere VM o PLC,
  informare l'owner OT e applicare soltanto il rollback approvato.
- Cyber Vision, DTLab e SIEM restano strumenti di osservazione e governance. Nessuna
  remediation automatica, regola firewall, isolamento, power action o scrittura PLC.
- Una regola Snort nuova parte in `alert`, con scope minimo. `drop` e automazioni SOAR
  sono fuori perimetro finché non esiste una valutazione safety separata.
- Token API dedicati: Classic API Read e New UI Read/Auditor. La piattaforma Cisco
  supporta anche permessi write, quindi il carattere read-only dipende dal ruolo e dal
  client, non dal token in sé.
- CEF, PCAP e bundle tecnici possono contenere IP, MAC, nomi asset e dettagli di
  processo: accesso minimo, retention definita e condivisione autorizzata.

## Limiti da dichiarare

- Variable accesses mostra `READ`/`WRITE`, ma non il valore della variabile.
- La documentazione pubblica non garantisce un evento per ogni write né un filtro per
  singolo registro.
- Le proprietà Modbus nel CEF non sono garantite finché non vengono osservate nel
  payload reale.
- L'import Snort custom è nativo; una firma exact-register è solo una possibilità da
  validare sul motore installato.
- Syslog CEF è il feed continuo; un download DTLab resta un export manuale.
- “Near-real-time” non significa latenza zero e va misurato end-to-end nel collaudo.
