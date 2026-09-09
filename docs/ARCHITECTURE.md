# Architettura

## Obiettivo

DTLab Control Center chiude il ciclo OT `dato → detection → decisione → ticket →
evidenza → reporting`. Non sostituisce Cisco Cyber Vision come sensore: ne rende più
semplice l'uso operativo, lo correla con VMware e aggiunge governance persistente.

## Flusso near-real-time

```text
VPN DTLAB CISCO sul PC autorizzato
  ├─ VMware ESXi ─────────────── inventario read-only ─────────┐
  ├─ Cyber Vision Classic ───── API Read /api/3.0 ─────────────┤
  └─ Cyber Vision New UI ────── Auditor /cvapi/v1 ─────────────┤
                                                               v
                                               collector locale Windows
                                      raw privato + adapter per sorgente
                                                               |
                                              snapshot canonico DTLab v2
                                  oggetto immutabile + manifest SHA-256
                                                               |
                              gate fail-closed + backlog store-and-forward
                                                               |
                                      publish SSH atomico verso il server
                                                               |
                       manifest archive ──> worker ticket idempotente SQLite
                                                               |
                                  Streamlit refresh leggero ogni 15 secondi
```

Il server web non raggiunge ESXi o Cyber Vision e non conserva token Cisco o password
VMware. La latenza prevista è circa 60–90 secondi: un trigger al minuto, publish atomico
e aggiornamento UI entro 15 secondi. `IgnoreNew` impedisce sovrapposizioni: se un ciclo
dura oltre un minuto, il trigger intermedio viene scartato e la cadenza effettiva segue
la durata del ciclo. Il publisher verifica oggetti e manifest remoti in blocchi limitati
anziché aprire una sessione per archivio. Se VPN o SSH non sono disponibili, l'ultimo
snapshot verificato resta attivo; gli archivi locali approvati vengono recuperati in
ordine alla connessione successiva.

## Sorgenti e confini di verità

`cisco_cyber_vision` e `cisco_cyber_vision_new_ui` restano sorgenti separate. I 5
profili New UI non vengono sommati ai 3 Device Classic e non modificano topologia,
flow o risk score Classic. `sensorAssociations` e `pcapAssociations` rimangono
associazioni inline finché Cisco non espone entità autonome.

- `real`: valore restituito dalla sorgente corretta o correlazione confermata.
- `observed`: configurazione vista senza prova della funzione operativa.
- `expected`: ruolo previsto ma non ancora verificato.
- `unavailable`: endpoint, licenza o permesso non disponibile.
- `stale`: ultimo fatto valido oltre la soglia di freschezza.
- `demo`: vietato nello store operativo.

VMware prova VM, NIC, IP guest e port group visibili all'account. L'account non espone
host, vSwitch, VLAN o policy di port group, quindi `host_network_scope` resta `N/D`.
La presenza di una NIC DPI non dimostra da sola la cattura del traffico.

Le correlazioni VM↔Device sono bipartite e uno-a-uno. HMI, Kali e PLC-Desktop sono
`confirmed` perché la conferma operativa coincide con IP/MAC live univoci.
PLC-Desktop è il target ufficiale; PLC-Ubuntu resta acceso e legacy.

## Semantica delle metriche

- Classic `riskScore`: rischio Cisco del Device, scala 0–100.
- CVSS: severità tecnica della vulnerabilità, scala 0–10.
- CSRS: valore New UI mostrato soltanto quando restituito dall'API.
- Qualità DTLab: copertura e affidabilità dello snapshot, non rischio cyber.

Queste metriche non vengono convertite, combinate o sostituite da formule locali.

## Snapshot e pubblicazione

Ogni snapshot conforme allo schema viene serializzato in modo canonico. L'oggetto prende
il nome dal proprio SHA-256; i manifest `current`, `previous`, `last_known_good` e
`manifests/<sha>.json` puntano a oggetti immutabili. `current` è sempre l'ultimo commit
remoto. Il publisher:

1. verifica schema, qualità, capability e freschezza;
2. rifiuta dati demo, snapshot scaduti e stati non approvati;
3. pubblica prima gli archivi approvati mancanti, in ordine cronologico;
4. verifica gli hash già presenti e fallisce in modo chiuso sui risultati ambigui;
5. aggiorna `current` solo alla fine, sotto lock remoto.

## Ticketing

Il worker server-side scandisce tutti i manifest immutabili, quindi il coalescing degli
eventi filesystem non perde snapshot intermedi. `snapshot_ingests` rende l'ingest
idempotente. Ogni segnale ha:

- fingerprint stabile e record sorgente;
- conteggio delle osservazioni per snapshot;
- versioni di evidenza soltanto quando il contenuto semantico cambia;
- stato di triage, eventuale ticket e regole di riemersione per tipo.

Eventi puntuali e differenze baseline non riaprono automaticamente un ticket chiuso.
Finding persistenti, vulnerabilità e alert New UI possono riemergere soltanto dopo un
aggiornamento semantico. Nessuna remediation modifica automaticamente PLC, VM o rete.

SQLite, WAL e SHM sono conservati in una directory `0700` e file `0600`, separata dallo
store snapshot read-only. Ticket, task, commenti e audit sono persistenti e vengono
salvati atomicamente durante promozione e rollback.

## Moduli

- `collector/`: client GET-only, vault, raw retention e raccolta.
- `adapters/`: normalizzazione ESXi, Classic e New UI senza merge impliciti.
- `services/`: assembly, identità, snapshot, publisher, segnali e ticket.
- `ui/`: 16 route Material 3, cockpit ticket-first, Asset 360, viste tecniche,
  export e Scenario Lab isolato.
- `schemas/`: contratto JSON canonico e controlli semantici.
- `deploy/`: bootstrap, staging, promozione, rollback, unità app e worker.
