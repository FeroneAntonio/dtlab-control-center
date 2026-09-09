"""Versioned, manual-first OT triage playbooks used by ticket creation."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PlaybookTask:
    title: str
    description: str


_COMMON_CLOSE = PlaybookTask(
    "Documentare esito ed evidenze",
    "Registrare decisione, prove, approvazioni e verifica finale prima della chiusura.",
)

PLAYBOOKS: dict[str, tuple[PlaybookTask, ...]] = {
    "host_modbus_write": (
        PlaybookTask(
            "Confermare l'evidenza endpoint",
            "Verificare sensor ID, episodio, Function Code, Unit ID, registri, valori "
            "e stato request/processed. L'evidenza è host-side DTLab e non Cisco.",
        ),
        PlaybookTask(
            "Verificare autorizzazione e impatto OT",
            "Confrontare origine, change window e sequenza osservata con le operazioni "
            "autorizzate, senza dedurre l'esito del processo dal solo nome dello script.",
        ),
        PlaybookTask(
            "Confermare stato PLC e rollback",
            "Far verificare al referente OT lo stato reale del processo e applicare soltanto "
            "il rollback approvato; nessuna scrittura viene eseguita dal portale.",
        ),
        _COMMON_CLOSE,
    ),
    "event": (
        PlaybookTask(
            "Confermare il record sorgente",
            "Verificare timestamp, severità, Center e riferimento Cisco senza "
            "inferire asset mancanti.",
        ),
        PlaybookTask(
            "Correlare il contesto OT",
            "Controllare asset, flow, baseline e change window nello stesso intervallo temporale.",
        ),
        PlaybookTask(
            "Concordare l'azione con OT",
            "Qualsiasi intervento su PLC, VM o rete richiede validazione del referente operativo.",
        ),
        _COMMON_CLOSE,
    ),
    "finding": (
        PlaybookTask(
            "Validare il finding",
            "Confermare la condizione con la sorgente indicata e distinguere "
            "osservazione da fatto.",
        ),
        PlaybookTask(
            "Assegnare owner e impatto",
            "Identificare responsabile, criticità operativa e finestra sicura di intervento.",
        ),
        PlaybookTask(
            "Eseguire verifica manuale",
            "Applicare soltanto azioni approvate, con pre-check e possibilità di rollback.",
        ),
        _COMMON_CLOSE,
    ),
    "baseline_difference": (
        PlaybookTask(
            "Confermare periodo e processo",
            "Verificare turno, ricetta, manutenzione e versione della baseline osservata.",
        ),
        PlaybookTask(
            "Classificare la deviazione",
            "Stabilire se il comportamento è atteso, nuovo autorizzato o anomalo.",
        ),
        PlaybookTask(
            "Approvare o escalare",
            "Aggiornare la baseline solo con owner OT; altrimenti proseguire l'indagine.",
        ),
        _COMMON_CLOSE,
    ),
    "vulnerability": (
        PlaybookTask(
            "Confermare l'esposizione Cisco",
            "Verificare che la vulnerabilità sia associata esplicitamente all'asset, "
            "non solo al catalogo.",
        ),
        PlaybookTask(
            "Valutare rischio e compatibilità",
            "Confrontare CVSS, score Cisco, ruolo asset, firmware e vincoli del processo.",
        ),
        PlaybookTask(
            "Pianificare la mitigazione",
            "Definire patch, compensazione o rischio accettato con owner e finestra di change.",
        ),
        _COMMON_CLOSE,
    ),
    "new_ui_alert": (
        PlaybookTask(
            "Confermare alert e stato New UI",
            "Verificare instance ID, stato Active/Cleared/Muted, severità e ultima "
            "occorrenza nella sorgente Cisco read-only.",
        ),
        PlaybookTask(
            "Validare il profilo asset New UI",
            "Usare l'associazione esplicita restituita dalla New UI; non collegare un "
            "Device Classic tramite nome, IP o prossimità temporale.",
        ),
        PlaybookTask(
            "Concordare la risposta con OT",
            "Confermare impatto e finestra operativa prima di qualunque azione su PLC, "
            "VM o rete.",
        ),
        _COMMON_CLOSE,
    ),
    "new_ui_vulnerability": (
        PlaybookTask(
            "Confermare l'associazione New UI",
            "Verificare CVE e profilo asset esattamente come restituiti dalla New UI, "
            "senza estendere l'associazione ai Device Classic.",
        ),
        PlaybookTask(
            "Valutare CVSS e CSRS separatamente",
            "Confrontare i valori API con firmware, ruolo del profilo e vincoli del "
            "processo, mantenendoli distinti dal risk score Classic.",
        ),
        PlaybookTask(
            "Pianificare una mitigazione approvata",
            "Definire patch o compensazione con owner OT, pre-check, finestra di change "
            "e rollback documentato.",
        ),
        _COMMON_CLOSE,
    ),
}


def tasks_for_signal(signal_type: str) -> tuple[PlaybookTask, ...]:
    """Return the immutable manual-first playbook for a normalized signal type."""

    return PLAYBOOKS.get(signal_type, (_COMMON_CLOSE,))
