# Schema v3 — estensione additiva

Lo schema v3 è un **superset additivo** del contratto v2. Non modifica né un byte
del v2: riusa ogni definizione di entità v2 via `$ref` JSON Schema e aggiunge sei
domini nuovi più la storia dei trend. Uno snapshot v2 continua a validare contro
il contratto v2 immutato; un file v2 con campi v3 viene **rifiutato** dal v2
(`additionalProperties: false`), a garanzia dell'isolamento.

- `schemas/dtlab-snapshot-v2.schema.json` — contratto storico, invariato.
- `schemas/dtlab-snapshot-v3.schema.json` — superset, `schema_version` `3.0.0`.
- `src/dtlab/contract_v3.py` — validatore che risolve i `$ref` al v2 con un
  `referencing.Registry`, riusa tutte le regole v2 (unicità, cross-reference,
  semantica, anti-leak) e aggiunge quelle v3.

## Nuovi domini (tutti opzionali → veramente additivi)

| Collezione | Cosa modella |
|---|---|
| `attack_scenarios` | Catalogo scenari offensivi (Kali) con tecniche MITRE ATT&CK for ICS, `execution_mode` e riferimento RoE. |
| `attack_runs` | Esecuzioni di uno scenario, con step, esito e stato. |
| `detection_correlations` | Correlazione run→detection Cisco con **latenza** e flag `detected`; il caso non rilevato è modellato esplicitamente. |
| `process_telemetry` | Digital twin: registri/coil Modbus, stato nastro, setpoint HMI nel tempo. |
| `security_zones` | Modello di Purdue + zone/conduit IEC 62443 con Security Level target. |
| `compliance_mappings` | Copertura IEC 62443 / NIS2 / MITRE ATT&CK ICS / Purdue con `evidence_refs`. |
| `history` | Punti-trend con `retention` (bucket + max punti + max età). |

## Regole semantiche v3 (oltre allo schema)

- **RoE obbligatoria**: `execution_mode: real` richiede `roe_reference` non nullo
  (scenari e run). In sandbox tutto è `simulated`.
- **Coerenza detection**: se `detected` è vero servono `detected_at`, latenza
  ≥ 0 coerente con l'intervallo, sorgente ≠ `none` (ed `event_id` per detection
  Cisco); se falso, latenza e `detected_at` nulli e sorgente `none`.
- **Bounds Modbus**: `in_bounds` deve essere coerente con `value` ed
  `expected_min/max`.
- **ATT&CK**: un `compliance_mapping` con framework `mitre_attack_ics` deve avere
  `reference_id` in forma `T####`.
- **Integrità referenziale**: run→scenario, correlation→run/event,
  telemetry→asset/run, zone conduit→zone, compliance→asset/zone/evidence.

## Disciplina anti-dati-falsi

La sandbox gira in `publication_mode: allow_demo` con evidenze `truth: demo` e un
nome ambiente marcato `SANDBOX`: non può mai spacciarsi per telemetria reale né
finire nello store operativo `real_only`. L'unica eccezione imposta dal contratto
v2 è il risk score Cisco (`truth` `real`/`stale`): lì la nota d'evidenza dichiara
esplicitamente che il valore è simulato.

## Generare la sandbox

```bash
python tools/generate_sandbox.py --output runtime/sandbox/beerfactory-v3.json
```

Il generatore (`src/dtlab/sandbox/generator.py`) è deterministico: produce la
BeerFactory con 4 scenari d'attacco (3 rilevati, 1 gap MITM voluto), 24 campioni
di digital twin con una finestra di manomissione, zone Purdue/62443, mappature
NIS2/ATT&CK e trend storici. L'output valida contro `contract_v3`.
