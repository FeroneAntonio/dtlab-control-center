# Contributing to DTLab

## Regole essenziali

1. Non inserire credenziali, token, chiavi private, indirizzi operativi, database,
   snapshot reali, PCAP o evidenze del cliente.
2. Conservare la provenienza `observed`, `derived`, `operator_confirmed` o
   `unavailable`: un dato mancante non deve diventare uno zero inventato.
3. Le integrazioni Cisco e VMware devono restare read-only salvo strumenti
   amministrativi separati, espliciti e verificabili.
4. Gli scenari di laboratorio devono essere limitati nel tempo e utilizzati solo
   su reti autorizzate. Non aggiungere esecuzione automatica di attacchi alla CI.
5. Ogni nuova funzione deve includere test e documentazione operativa.

## Verifica prima di una pull request

```bash
python -m ruff check src tools tests apps/api
python -m pytest -q
python -m pytest apps/api/tests -q

cd apps/web
npm ci
npm run lint
npm run build
```

Controllare inoltre che `.env`, runtime, snapshot, log ed export non siano presenti
nel diff. La CI esegue automaticamente i controlli Python e web supportati.

## Aggiornamento del bundle BeerFactory

Il contenuto di `lab/beerfactory-company/` è uno snapshot verificabile e non va
modificato file per file. Per aggiornarlo, acquisire un commit identificato dal
repository di manutenzione, sostituire l'intero albero, aggiornare il commit in
`lab/README.md` e verificare che gli otto nomi siano coperti dalle regole Cyber
Vision e dal launcher limitato nel tempo.
