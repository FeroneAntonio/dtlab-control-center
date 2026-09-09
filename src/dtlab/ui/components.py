"""Escaped reusable UI components."""

from __future__ import annotations

import html
from datetime import datetime
from typing import Any

import pandas as pd
import streamlit as st

from dtlab.contract import truth_label_it
from dtlab.ui.context import DashboardContext

_STATE_LABELS = {
    "fresh": "Aggiornato",
    "partial": "Parziale",
    "stale": "Obsoleto",
    "offline": "Offline",
    "failed": "Errore",
}
_STATUS_LABELS = {
    "connected": "Connessa",
    "degraded": "Degradata",
    "unavailable": "Non disponibile",
    "not_configured": "Da configurare",
    "stale": "Obsoleta",
}


def clean(value: Any, fallback: str = "—") -> str:
    if value is None:
        return fallback
    text = str(value).strip()
    return text if text and text.lower() not in {"nan", "nat", "none"} else fallback


def safe(value: Any, fallback: str = "—") -> str:
    return html.escape(clean(value, fallback), quote=True)


def format_local_time(value: Any) -> str:
    parsed = pd.to_datetime(value, utc=True, errors="coerce")
    if pd.isna(parsed):
        return "—"
    return parsed.tz_convert("Europe/Rome").strftime("%d/%m/%Y · %H:%M:%S")


def format_age(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds} s"
    if seconds < 3600:
        return f"{seconds // 60} min"
    hours, remainder = divmod(seconds, 3600)
    return f"{hours} h {remainder // 60} min"


def chip(label: str, tone: str, *, dot: bool = True) -> str:
    marker = "<span class='dt-dot'></span>" if dot else ""
    return f"<span class='dt-chip {safe(tone)}'>{marker}{safe(label)}</span>"


def _source_presence(source: dict[str, Any]) -> tuple[str, str] | None:
    """Return the useful data presence for the hero, not its diagnostic status.

    Exact source health and capability errors remain visible in ``/sources``. The
    page hero omits sources that supplied no usable data and avoids presenting one
    failed optional capability as if the whole source were absent.
    """

    status = source.get("status")
    if status == "connected":
        return "Connessa", "real"
    capabilities = source.get("capabilities", {})
    has_usable_capability = any(
        isinstance(capability, dict)
        and capability.get("status") in {"available", "partial", "truncated"}
        for capability in capabilities.values()
    )
    record_counts = source.get("record_counts", {})
    has_records = any(
        isinstance(count, int) and not isinstance(count, bool) and count > 0
        for count in record_counts.values()
    )
    has_data = bool(source.get("last_success_at")) and (
        has_usable_capability or has_records
    )
    if status == "degraded" and has_data:
        return "Dati disponibili", "observed"
    if status == "stale" and has_data:
        return "Dati obsoleti", "stale"
    return None


def page_intro(
    context: DashboardContext,
    eyebrow: str,
    title: str,
    description: str,
) -> None:
    source_chips = []
    for source_type in (
        "vmware_esxi",
        "cisco_cyber_vision",
        "cisco_cyber_vision_new_ui",
    ):
        source = context.sources_by_type.get(source_type)
        if not source:
            continue
        presence = _source_presence(source)
        if presence is None:
            continue
        presence_label, tone = presence
        source_chips.append(
            chip(
                f"{source['label']}: {presence_label}",
                tone,
            )
        )
    source_chips.append(
        chip(
            f"Snapshot: {_STATE_LABELS.get(context.effective_state, context.effective_state)}",
            "real" if context.effective_state == "fresh" else "stale",
        )
    )
    st.markdown(
        "<section class='dt-hero'>"
        f"<div class='dt-eyebrow'>{safe(eyebrow)}</div>"
        f"<h1>{safe(title)}</h1>"
        f"<p>{safe(description)}</p>"
        f"<div class='dt-status-row'>{''.join(source_chips)}</div>"
        "</section>",
        unsafe_allow_html=True,
    )
    if context.pointer != "current":
        st.warning(
            f"Pointer current non valido: visualizzato {context.pointer} verificato."
        )
    if context.effective_state == "stale":
        st.warning(
            f"Ultimo snapshot valido vecchio di {format_age(context.age_seconds)}. "
            "I dati restano visibili ma sono marcati Obsoleti."
        )
    elif context.snapshot["sync"]["state"] == "partial":
        st.info(
            "Sincronizzazione parziale: i dati mancanti restano Non disponibili e non "
            "vengono sostituiti da valori demo."
        )


def capability_notice(
    context: DashboardContext,
    capability_name: str,
    label: str,
) -> None:
    capability = (context.cybervision_source or {}).get("capabilities", {}).get(
        capability_name, {}
    )
    if capability.get("status") not in {"partial", "truncated"}:
        return
    attempted = capability.get("attempted")
    successful = capability.get("successful")
    coverage = (
        f"{successful}/{attempted} richieste riuscite"
        if isinstance(attempted, int) and isinstance(successful, int)
        else "copertura parziale"
    )
    st.warning(
        f"{label}: {coverage}. Le righe riuscite sono reali, ma l'elenco non è completo."
    )


def metric_card(label: str, value: Any, meta: str) -> None:
    st.markdown(
        "<div class='dt-metric'>"
        f"<div class='label'>{safe(label)}</div>"
        f"<div class='value'>{safe(value)}</div>"
        f"<div class='meta'>{safe(meta)}</div>"
        "</div>",
        unsafe_allow_html=True,
    )


def baseline_detection_banner(
    readiness: dict[str, Any],
    *,
    show_unattributed_only: bool = True,
) -> None:
    """Render truth-qualified baseline evidence without claiming an attack."""

    rows = readiness.get("rows")
    if not isinstance(rows, list):
        rows = []
    linked_rows = [
        row
        for row in rows
        if isinstance(row, dict)
        and isinstance(row.get("baseline_difference"), dict)
        and row["baseline_difference"].get("state") == "linked_difference"
    ]
    evidence = readiness.get("baseline_evidence")
    if not isinstance(evidence, dict):
        evidence = {}
    global_count = len(evidence.get("global_unattributed_record_ids") or [])
    unmapped_count = len(evidence.get("unmapped_explicit_record_ids") or [])
    if not linked_rows and (not show_unattributed_only or not (global_count or unmapped_count)):
        return

    record_count = sum(
        len(row["baseline_difference"].get("record_ids") or []) for row in linked_rows
    )
    linked_labels = [str(row.get("origin_label") or "Origine N/D") for row in linked_rows]
    linked_types = {
        str(difference_type)
        for row in linked_rows
        for difference_type in row["baseline_difference"].get("difference_types") or []
    }
    kali_only = len(linked_rows) == 1 and linked_rows[0].get("origin_key") == "kali"
    if kali_only and "new_component" in linked_types:
        title = "Kali · nuovo componente rilevato"
        detail = (
            "Cisco Cyber Vision ha associato una differenza new_component all'asset Kali "
            "confermato. Richiede triage: non prova un attacco, una tecnica o l'origine "
            "della nuova attività."
        )
    elif linked_rows:
        title = (
            f"{linked_labels[0]} · differenza baseline rilevata"
            if len(linked_labels) == 1
            else f"Differenze baseline associate a {len(linked_labels)} origini"
        )
        detail = (
            "Associazione basata esclusivamente sugli asset_ids espliciti restituiti da "
            "Cisco Cyber Vision. L'evidenza è da classificare e non costituisce da sola "
            "una rilevazione di attacco."
        )
    else:
        title = "Differenze baseline senza origine attribuita"
        detail = (
            "Cisco Cyber Vision ha restituito differenze correnti prive di un collegamento "
            "esplicito a Kali, HMI o PLC. Restano disponibili per il triage, senza indicare "
            "origine o classificazione di sicurezza."
        )

    pills: list[str] = []
    if record_count:
        pills.append(
            f"<span class='dt-evidence-pill'>{record_count} "
            f"{'differenza associata' if record_count == 1 else 'differenze associate'}</span>"
        )
    if global_count:
        global_label = (
            "record globale non attribuito"
            if global_count == 1
            else "record globali non attribuiti"
        )
        pills.append(
            f"<span class='dt-evidence-pill'>{global_count} "
            f"{global_label}</span>"
        )
    if unmapped_count:
        unmapped_label = (
            "record con asset non mappato"
            if unmapped_count == 1
            else "record con asset non mappati"
        )
        pills.append(
            f"<span class='dt-evidence-pill'>{unmapped_count} "
            f"{unmapped_label}</span>"
        )
    tone = "linked" if linked_rows else "unattributed"
    st.markdown(
        f"""
<section class="dt-baseline-signal {tone}" aria-label="Evidenza baseline Cisco Cyber Vision">
  <span class="dt-baseline-icon" aria-hidden="true">!</span>
  <div class="dt-baseline-content">
    <small>Baseline Cisco Cyber Vision · evidenza corrente</small>
    <strong>{safe(title)}</strong>
    <p>{safe(detail)}</p>
    <div class="dt-evidence-pills">{''.join(pills)}</div>
  </div>
</section>
""",
        unsafe_allow_html=True,
    )


def empty_state(title: str, detail: str) -> None:
    st.markdown(
        "<div class='dt-empty'>"
        f"<strong>{safe(title)}</strong>{safe(detail)}"
        "</div>",
        unsafe_allow_html=True,
    )


def finding_card(item: dict[str, Any]) -> None:
    severity = clean(item.get("severity"), "info").lower()
    tone = severity if severity in {"critical", "high", "medium", "low"} else "info"
    st.markdown(
        f"<div class='dt-finding {tone}'>"
        f"<div class='sev'>{safe(severity)} · {safe(item.get('status'))}</div>"
        f"<div class='title'>{safe(item.get('title'))}</div>"
        f"<div class='detail'>{safe(item.get('description'))}</div>"
        "</div>",
        unsafe_allow_html=True,
    )


def truth_badge(record: dict[str, Any]) -> str:
    truth = record.get("evidence", {}).get("truth", "unavailable")
    return truth_label_it(str(truth))


def dataframe(records: list[dict[str, Any]], *, height: int = 390) -> None:
    if not records:
        empty_state("Nessun record", "La sorgente non ha restituito righe per questa vista.")
        return
    st.dataframe(
        pd.DataFrame(records),
        use_container_width=True,
        hide_index=True,
        height=height,
    )


def source_status(source: dict[str, Any] | None) -> str:
    if not source:
        return "Non disponibile"
    return _STATUS_LABELS.get(source["status"], source["status"])


def as_datetime(value: Any) -> datetime | None:
    parsed = pd.to_datetime(value, utc=True, errors="coerce")
    return None if pd.isna(parsed) else parsed.to_pydatetime()
