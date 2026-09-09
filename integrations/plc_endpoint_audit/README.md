# DTLab PLC Endpoint Audit

Pacchetto isolato per rilevare richieste di scrittura Modbus/TCP ricevute dal server
BeerFactory anche quando sorgente e destinazione coincidono con `PLC-Desktop`. Il
sensore non sostituisce Cisco Cyber Vision e non attribuisce a Cisco l'evidenza prodotta
localmente.

Il codice non è installato sul PLC automaticamente. `install.sh` copia il pacchetto e
genera una chiave locale, ma non modifica `world.py`, non riavvia il simulatore e non
avvia servizi.

L'installer verifica inoltre la compilazione con `/usr/bin/python2`, rifiuta una
versione Pymodbus diversa dalla `2.5.3` e registra `/opt/dtlab-plc-endpoint-audit`
mediante un file `.pth` nel `site-packages` di Python 2.7. In questo modo `world.py`
può importare il hook indipendentemente dalla propria directory di lavoro. Il sender
continua a usare un `PYTHONPATH` esplicito nella propria unità systemd.

## Perché serve

Linux instrada una connessione verso un proprio indirizzo IP attraverso lo stack locale.
Il traffico `172.16.10.10 → 172.16.10.10` può quindi non attraversare vSwitch, port
group DPI o Cisco Cyber Vision. Il server hook osserva invece la request decodificata
nel punto in cui Pymodbus la processa.

Lo script pubblico `attack_shutdown.py` usa `write_register` in un ciclo senza pausa e
produce FC06 sui registri `3`, `4` e `16` con valore `0`. Il sensore:

- emette subito una detection `high/P2` alla prima write;
- mantiene lo stesso `event_id` e aumenta `revision` per lo stesso episodio;
- correla `3=0`, `4=0`, `16=0` entro due secondi come
  `process_shutdown_sequence`, `critical/P1`;
- aggrega la ripetizione infinita, invece di creare un ticket per pacchetto;
- marca sempre la fonte come `src:dtlab-host-ot:plc-desktop` e non Cisco.

Il mapping dei registri è specifico del laboratorio BeerFactory. Non deve essere
riutilizzato su un PLC diverso senza un mapping approvato dal proprietario OT.

## Struttura

- `dtlab_plc_audit/audit_hook.py`: protocollo Pymodbus 2.5.3 compatibile Python 2.7.
- `dtlab_plc_audit/core.py`: estrazione write, classificazione e correlazione episodio.
- `dtlab_plc_audit/spool.py`: JSONL append-only, catena SHA-256 e HMAC per record.
- `dtlab_plc_audit/sender.py`: processo separato che verifica lo spool e invia l'evento.
- `schemas/`: contratto evento e contratto envelope locale.
- `systemd/`: unità hardenizzata del sender, non abilitata dall'installer.
- `tests/`: test della logica condivisa eseguibili con Python 3.

## Confini di verità

L'hook dichiara soltanto:

- `endpoint_server_processed`: la request è stata processata senza risposta Modbus di
  errore;
- `endpoint_server_rejected`: il server ha prodotto un errore;
- `endpoint_request_observed`: request osservata ma risultato non determinabile;
- `endpoint_heartbeat`: heartbeat del sensore.

Il peer TCP prova l'indirizzo visto dal server, non il processo o l'intento umano. Per
questo `process` rimane `null`. L'identità del processo richiede una futura sorgente
eBPF/auditd. Un aggressore con privilegi root sul PLC può alterare hook, chiave o kernel:
HMAC e hardening proteggono trasporto, replay accidentali e spoofing esterno, non una
compromissione completa dell'host.

Il monitoraggio è passivo: un errore del sensore viene scritto in `health.json`, ma non
blocca né modifica la risposta Modbus.

Il sender usa `sender-health.json` separatamente e trasmette un heartbeat soltanto se
`health.json` è `ready` e recente. Un sender funzionante non può quindi mascherare un
hook fermo o in errore.

## Formato e autenticazione

Lo spool conserva envelope locali firmati e concatenati. Il receiver web riceve
esclusivamente l'oggetto `event` canonico, non l'envelope:

```text
POST /api/host-ot/v1/events
Content-Type: application/json
X-DTLab-Key-Id: <key-id registrato>
X-DTLab-Timestamp: <epoch UTC intero>
X-DTLab-Signature: <hex HMAC-SHA256>
```

Il body è UTF-8:

```python
json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
```

La firma è `HMAC-SHA256(timestamp + "\n" + body)`. Il receiver deve associare
`sensor.id` alla chiave, applicare finestra temporale, replay protection e idempotenza
su `event_id + revision`.

## Test offline

Dalla directory del pacchetto:

```bash
python3 -m pip install -r requirements-test.txt
PYTHONPATH=. python3 -m unittest discover -s tests -v
python3 -m compileall -q dtlab_plc_audit
```

Sul PLC, prima del rilascio, verificare inoltre la sintassi Python 2.7 senza avviare il
server:

```bash
PYTHONPATH=. python2 -m py_compile \
  dtlab_plc_audit/__init__.py \
  dtlab_plc_audit/core.py \
  dtlab_plc_audit/spool.py \
  dtlab_plc_audit/runtime.py \
  dtlab_plc_audit/audit_hook.py \
  dtlab_plc_audit/sender.py
```

## Installazione preparatoria

Solo in una change window autorizzata:

```bash
sudo ./install.sh
sudo editor /etc/dtlab/plc-endpoint-audit.json
/usr/bin/python2 -c 'from dtlab_plc_audit.audit_hook import StartAuditedTcpServer'
```

Verificare prima dell'avvio:

- asset ID canonico reale di PLC-Desktop già preconfigurato per DTLab;
- `destination_ip=172.16.10.10`;
- endpoint HTTPS reale `/api/host-ot/v1/events` già preconfigurato, oppure un
  `outbox_directory` locale esplicitamente scelto;
- key ID registrato nel receiver;
- IP HMI e Kali effettivamente approvati.

La chiave viene generata direttamente sul PLC in `/etc/dtlab` con permessi `0600`; non
deve essere copiata in repository, ticket, screenshot o snapshot. Registrarla sul
receiver tramite il suo secret store.

## Integrazione controllata con Pymodbus

Il progetto BeerFactory usa Pymodbus 2.5.3 e
`pymodbus.server.asynchronous.StartTcpServer`. Durante una change window, dopo backup e
test offline, sostituire soltanto l'import e la chiamata di avvio:

```python
from dtlab_plc_audit.audit_hook import StartAuditedTcpServer

def startModbusServer():
    StartAuditedTcpServer(
        context,
        audit_config="/etc/dtlab/plc-endpoint-audit.json",
        identity=identity,
        address=("0.0.0.0", MODBUS_SERVER_PORT),
    )
```

Il pacchetto non monkey-patcha Pymodbus. L'override replica il percorso `_execute` della
versione 2.5.3 e aggiunge l'audit dopo l'esecuzione; le chiamate interne di `world.py` a
`context.setValues` non diventano falsi eventi di rete.

Come il server originale Pymodbus 2.5.3, il hook abilita i signal handler di Twisted
soltanto quando il reactor parte dal thread principale. Questo conserva anche gli
avvii di BeerFactory che delegano il server a un thread.

Prima del riavvio:

1. salvare copia e hash di `world.py`;
2. confermare che Pymodbus sia esattamente `2.5.3`;
3. eseguire i test Python 2 e Python 3;
4. verificare endpoint, CA, key ID e orologio NTP;
5. predisporre rollback alla copia precedente;
6. non eseguire scritture di prova finché il proprietario OT non approva registro,
   valore, stato iniziale/finale e procedura di ripristino.

Dopo la verifica del hook:

```bash
sudo systemctl enable --now dtlab-plc-audit-sender.service
sudo systemctl status dtlab-plc-audit-sender.service
sudo journalctl -u dtlab-plc-audit-sender.service -n 100 --no-pager
```

## Criteri di collaudo

- Una singola FC06 produce una sola revisione `high/P2`.
- La sequenza `3/4/16=0` aggiorna lo stesso episodio a `critical/P1`.
- Il ciclo infinito non crea un ticket per write: incrementa `request_count`.
- Dopo l'emissione immediata e l'eventuale escalation, un episodio continuo pubblica
  al massimo una revisione aggregata ogni 30 secondi con la configurazione proposta.
- Un nuovo episodio dopo la finestra di quiete ottiene un nuovo `event_id`.
- Firma errata, catena interrotta o record parziale non avanzano il cursor.
- Il sender ritenta senza perdere record e usa HTTPS con verifica certificato.
- Il sito mostra “sensore endpoint PLC” e lo stato di corroborazione Cisco separato.
- L'assenza del heartbeat diventa perdita di copertura, non “nessun attacco”.

## Rollback

Arrestare il sender, ripristinare l'import/chiamata originale di Pymodbus e riavviare il
solo processo BeerFactory nella change window. Se il pacchetto viene disinstallato,
rimuovere anche `dtlab_plc_endpoint_audit.pth` dal percorso restituito da
`python2 -c 'from distutils.sysconfig import get_python_lib; print(get_python_lib())'`.
Lo spool non va cancellato: conservarlo con chiave, cursor e hash per audit. Nessuna VM
deve essere spenta.
