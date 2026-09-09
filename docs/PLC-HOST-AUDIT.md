# DTLab PLC Host Audit

## Obiettivo

Rilevare le scritture Modbus/TCP anche quando origine e destinazione coincidono
con il PLC (`172.16.10.10 → 172.16.10.10`). In questo caso Linux instrada la
connessione localmente e il traffico può non attraversare il vSwitch e il DPI di
Cisco Cyber Vision.

La sorgente viene quindi mostrata come **DTLab PLC Host Audit**, mai come evento
Cisco. Il primo episodio di scrittura apre automaticamente un ticket P2; la
sequenza FC06 sui registri `3=0`, `4=0`, `16=0` eleva lo stesso ticket a P1.
Nessuna remediation o scrittura PLC viene eseguita dal portale.

## Catena verificabile

```text
Pymodbus _execute
  → episodio aggregato sul PLC
  → spool locale append-only e firmato
  → sender HTTPS asincrono
  → HMAC verificato dal receiver write-only
  → oggetto JSON content-addressed SHA-256
  → segnale host_modbus_write
  → ticket e checklist idempotenti
```

Il sensore registra soltanto richieste Modbus di rete con Function Code di
scrittura `5`, `6`, `15`, `16`, `22` o `23`. Gli aggiornamenti interni del
simulatore BeerFactory non attraversano l'hook e non vengono scambiati per un
attacco di rete.

## Semantica dell'evidenza

- `endpoint_request_observed`: richiesta vista, esito applicativo non attestato;
- `endpoint_server_processed`: richiesta elaborata dal server Modbus;
- `endpoint_server_rejected`: richiesta ricevuta ma respinta;
- `plc_self`: IP sorgente uguale alla destinazione o indirizzo locale configurato;
- `security_test`, `authorized_hmi`, `unknown`: classificazioni di contesto, non
  identità crittografiche.

La UI conserva separatamente fatto, decisione di policy e classificazione. La
frase “compatibile con sequenza di arresto” non attribuisce automaticamente
l'azione a un utente o processo; tale attribuzione rimane `N/D` finché non viene
aggiunta telemetria di processo verificabile.

## Receiver del sito

Il servizio systemd è
`deploy/modbus-dashboard-host-ot-ingress.service` e ascolta soltanto su
`127.0.0.1:8520`. Apache pubblica esclusivamente
`POST /api/host-ot/v1/events` tramite il blocco
`deploy/apache-host-ot-ingress-vhost.inc`.

Il keyring server è un JSON root-owned e deve contenere almeno 256 bit casuali
per sensore:

```json
{
  "keys": [
    {
      "key_id": "plc-desktop-v1",
      "sensor_id": "plc-endpoint-sensor",
      "secret_base64": "<generata fuori dal repository>"
    }
  ]
}
```

La chiave reale non deve mai essere salvata nel repository, nei ticket, negli
snapshot o nei log. La firma HTTP è:

```text
hex(HMAC-SHA256(secret, unix_timestamp + "\n" + canonical_event_body))
```

Header richiesti: `X-DTLab-Key-Id`, `X-DTLab-Timestamp` e
`X-DTLab-Signature`. Il body deve essere il JSON canonico DTLab UTF-8 con newline
finale. Il receiver rifiuta firma errata, key/sensor mismatch, timestamp oltre 5
minuti, JSON non canonico, schema non valido e sorgenti che tentano di dichiararsi
Cisco.

## Attivazione sul PLC

Il pacchetto è in `integrations/plc_endpoint_audit`. L'installazione dei file può
essere preparata senza spegnere la VM. L'attivazione dell'hook richiede però una
change window e il riavvio del solo processo BeerFactory, non della VM.

Prima del riavvio:

1. verificare il percorso reale di `world.py` e creare una copia di rollback;
2. installare pacchetto, configurazione e chiave con permessi minimi;
3. eseguire i test offline e validare lo spool;
4. aggiungere l'import `StartAuditedTcpServer` e sostituire esclusivamente la
   chiamata `StartTcpServer`;
5. annotare PID/stato e registri operativi prima del cambio.

Dopo il riavvio controllato:

1. confermare che TCP/502 risponda e che HMI continui a funzionare;
2. verificare heartbeat e health locale;
3. inviare un evento sintetico marcato `TEST` senza scrivere il PLC;
4. soltanto con approvazione OT, ripetere il test reale e verificare un singolo
   ticket per episodio;
5. in caso di errore, ripristinare `world.py` e riavviare il solo servizio
   BeerFactory.

## Criteri di accettazione

- prima FC06 PLC→PLC: ticket P2 entro la latenza del sender;
- sequenza `3/4/16=0`: stesso ticket elevato a P1;
- loop infinito: storage e numero ticket restano limitati;
- nuovo burst dopo quiete: nuovo episodio e nuovo ticket;
- Kali→PLC: ticket host-side, con eventuale record Cisco mostrato solo come
  corroborazione separata;
- letture Modbus: nessun ticket di write;
- retry/restart/backlog: nessun duplicato;
- firma falsa o sensor spoof: nessuna pubblicazione come fatto.
