# BeerFactory company laboratory bundle

Questa directory contiene una copia integrale del materiale BeerFactory fornito
all'interno del progetto aziendale e già installato sulle VM autorizzate del
laboratorio. La copia è stata importata dal repository di manutenzione del team:

- origine: `https://github.com/silvatos/ot-security-lab`;
- commit acquisito: `d1518c3a5ef0e1a7a32b82bb9681cfed8a1b6bf7`;
- directory immutata: `beerfactory-company/`.

Il nome dell'account che ospita il repository di manutenzione non costituisce una
dichiarazione di paternità individuale. Il materiale è stato fornito dall'azienda
per il laboratorio DTLab ed è qui conservato per riproducibilità, tracciabilità e
allineamento con le regole di detection.

## Contenuto

| Percorso | Funzione |
|---|---|
| `beerfactory-company/world.py` | Simulatore PLC/BeerFactory e server Modbus/TCP |
| `beerfactory-company/Factory_bkg.png` | Sfondo grafico del simulatore |
| `beerfactory-company/setup-plc.sh` | Setup originale della VM PLC |
| `beerfactory-company/avvia-plc.sh` | Avvio originale Xvfb, VNC, noVNC e simulatore |
| `beerfactory-company/requirements-plc.txt` | Dipendenze Python 2.7 originali |
| `beerfactory-company/scripts/` | Otto scenari Modbus forniti per il collaudo |

## Esecuzione controllata

Gli script originali di scrittura contengono intenzionalmente cicli continui. Non
eseguirli direttamente durante una dimostrazione: un processo dimenticato può
generare traffico e ticket ripetuti. Usare il launcher DTLab, che accetta soltanto
indirizzi privati e termina automaticamente lo scenario:

```bash
python tools/run_company_lab_scenario.py attack_shutdown \
  --target <PLC_PRIVATE_IP> \
  --duration 10 \
  --authorized-lab
```

Per una singola scrittura controllata:

```bash
python tools/run_company_lab_scenario.py set_registry \
  --target <PLC_PRIVATE_IP> \
  --register 3 \
  --value 0 \
  --authorized-lab
```

Il launcher usa `python2` per default, coerentemente con la VM fornita. È possibile
specificare un interprete diverso con `--interpreter` solo dopo aver verificato la
compatibilità di `pymodbus`.

## Relazione con la detection

`config/cybervision-dtlab-modbus.rules` copre tutti gli otto nomi originali e le
relative sequenze FC03/FC06. Sono presenti anche regole generiche per le funzioni di
scrittura Modbus, così un nuovo script non diventa invisibile solo perché il nome è
diverso. L'endpoint audit completa Cyber Vision nei percorsi locali che non
attraversano SPAN/TAP.

## Vincoli operativi

- usare esclusivamente VM e reti per cui esiste autorizzazione esplicita;
- verificare prima che dashboard, receiver e ticket ingest siano attivi;
- terminare lo scenario e controllare lo stato BeerFactory al termine;
- non esporre noVNC senza autenticazione fuori dalla rete di laboratorio;
- non pubblicare evidenze reali, indirizzi o credenziali insieme ai sorgenti.
