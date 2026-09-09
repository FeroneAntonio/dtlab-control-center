"""Truth-first coverage matrix for OT write-detection readiness.

The projection deliberately keeps identity, write activity and alert evidence
separate.  It consumes only facts already present in a v2 snapshot and never
turns labels, names or free-text event titles into security evidence.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from dtlab.ui.topology import verified_identity_links

_USABLE_CAPABILITY_STATES = frozenset({"available", "partial", "truncated"})
_CURRENT_TRUTHS = frozenset({"real", "observed"})
_STALE_STATES = frozenset({"stale"})
_UNAVAILABLE_SOURCE_STATES = frozenset(
    {"unavailable", "not_configured", "offline", "failed", "error"}
)

_ORIGINS = (
    ("kali", "Kali / security testing", "security_testing", False),
    ("hmi", "HMI", "hmi", False),
    ("plc", "PLC ufficiale", "plc", True),
)


def _mappings(value: object) -> list[Mapping[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return []
    return [item for item in value if isinstance(item, Mapping)]


def _strings(value: object) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return []
    return [str(item) for item in value if item is not None and str(item)]


def _source_ids(snapshot: Mapping[str, Any], source_type: str) -> frozenset[str]:
    return frozenset(
        str(source.get("id"))
        for source in _mappings(snapshot.get("sources"))
        if source.get("id") and source.get("type") == source_type
    )


def _cybervision_source(snapshot: Mapping[str, Any]) -> Mapping[str, Any] | None:
    return next(
        (
            source
            for source in _mappings(snapshot.get("sources"))
            if source.get("type") == "cisco_cyber_vision"
        ),
        None,
    )


def _capability_state(
    snapshot: Mapping[str, Any], capability_name: str
) -> dict[str, str]:
    source = _cybervision_source(snapshot)
    sync = snapshot.get("sync")
    sync_state = (
        str(sync.get("state") or "").casefold() if isinstance(sync, Mapping) else ""
    )
    if source is None:
        return {
            "state": "unavailable",
            "label": "N/D",
            "copy": "Sorgente Cisco Cyber Vision non disponibile.",
        }

    source_state = str(source.get("status") or "").casefold()
    if source_state in _STALE_STATES or sync_state in _STALE_STATES:
        return {
            "state": "stale",
            "label": "N/D",
            "copy": "Dati Cisco scaduti: nessuna conclusione corrente.",
        }
    if source_state in _UNAVAILABLE_SOURCE_STATES or sync_state in {
        "offline",
        "failed",
    }:
        return {
            "state": "unavailable",
            "label": "N/D",
            "copy": "Sorgente Cisco non utilizzabile nella snapshot corrente.",
        }

    capabilities = source.get("capabilities")
    capability = capabilities.get(capability_name) if isinstance(capabilities, Mapping) else None
    status = (
        str(capability.get("status") or "").casefold()
        if isinstance(capability, Mapping)
        else ""
    )
    if status not in _USABLE_CAPABILITY_STATES:
        return {
            "state": "unavailable",
            "label": "N/D",
            "copy": f"Capability Cisco {capability_name} non utilizzabile.",
        }
    label = "Utilizzabile" if status == "available" else "Utilizzabile con copertura parziale"
    return {
        "state": "usable",
        "label": label,
        "copy": f"Capability Cisco {capability_name}: {status}.",
    }


def _current_source_owned(record: Mapping[str, Any], source_ids: frozenset[str]) -> bool:
    evidence = record.get("evidence")
    return bool(
        isinstance(evidence, Mapping)
        and str(evidence.get("source_id") or "") in source_ids
        and str(evidence.get("truth") or "").casefold() in _CURRENT_TRUTHS
    )


def _stale_source_owned(record: Mapping[str, Any], source_ids: frozenset[str]) -> bool:
    evidence = record.get("evidence")
    return bool(
        isinstance(evidence, Mapping)
        and str(evidence.get("source_id") or "") in source_ids
        and str(evidence.get("truth") or "").casefold() == "stale"
    )


def _is_explicit_modbus_write(activity: Mapping[str, Any]) -> bool:
    details = activity.get("details")
    tags = details.get("tags") if isinstance(details, Mapping) else []
    normalized_tags = {tag.strip().casefold() for tag in _strings(tags)}
    protocol = str(activity.get("protocol") or "").strip().casefold()
    # A protocol alone does not prove a write.  "Write Var" must be explicit;
    # Modbus must likewise be explicit either as protocol or tag.
    return "write var" in normalized_tags and (
        protocol == "modbus" or "modbus" in normalized_tags
    )


def _activity_direction(activity: Mapping[str, Any]) -> str:
    details = activity.get("details")
    if not isinstance(details, Mapping):
        return "unknown"
    return str(details.get("direction") or "unknown").casefold()


def _activity_origin_asset(activity: Mapping[str, Any]) -> str | None:
    details = activity.get("details")
    if not isinstance(details, Mapping):
        return None
    direction = _activity_direction(activity)
    if direction == "left_to_right":
        origin = details.get("left_asset_id")
        return str(origin) if origin else None
    if direction == "right_to_left":
        origin = details.get("right_asset_id")
        return str(origin) if origin else None
    return None


def _axis(state: str, label: str, copy: str, **facts: Any) -> dict[str, Any]:
    return {"state": state, "label": label, "copy": copy, **facts}


def _identity_axis(vm_ids: list[str], links: list[Mapping[str, Any]]) -> dict[str, Any]:
    linked_vm_ids = {str(link.get("virtual_machine_id") or "") for link in links}
    link_ids = sorted(str(link.get("id")) for link in links if link.get("id"))
    asset_ids = sorted(str(link.get("asset_id")) for link in links if link.get("asset_id"))
    if not vm_ids:
        return _axis(
            "not_defined",
            "Non definita",
            "Nessuna VM con contesto operativo esplicito per questa origine.",
            link_ids=link_ids,
            asset_ids=asset_ids,
        )
    if len(linked_vm_ids) == len(vm_ids):
        return _axis(
            "confirmed",
            "Confermata",
            "Identità VM↔asset confermata dall'operatore e univoca.",
            link_ids=link_ids,
            asset_ids=asset_ids,
        )
    if linked_vm_ids:
        return _axis(
            "partial",
            "Parziale",
            "Solo una parte delle VM ha un'identità VM↔asset verificabile.",
            link_ids=link_ids,
            asset_ids=asset_ids,
        )
    return _axis(
        "not_confirmed",
        "Non confermata",
        "Nessuna identità VM↔asset verificabile; non si attribuisce telemetria.",
        link_ids=[],
        asset_ids=[],
    )


def _write_axis(
    *,
    asset_ids: set[str],
    activities: list[Mapping[str, Any]],
    capability: Mapping[str, str],
    source_ids: frozenset[str],
) -> dict[str, Any]:
    base_facts: dict[str, Any] = {
        "record_ids": [],
        "origin_record_ids": [],
        "involved_record_ids": [],
        "origin_attributed": False,
    }
    if capability["state"] != "usable":
        return _axis("nd", "N/D", capability["copy"], **base_facts)
    if not asset_ids:
        return _axis(
            "nd",
            "N/D",
            "Identità asset non confermata: attività non attribuibile.",
            **base_facts,
        )

    relevant = [
        activity
        for activity in activities
        if _is_explicit_modbus_write(activity)
        and asset_ids.intersection(_strings(activity.get("asset_ids")))
        and _current_source_owned(activity, source_ids)
    ]
    stale_relevant = [
        activity
        for activity in activities
        if _is_explicit_modbus_write(activity)
        and asset_ids.intersection(_strings(activity.get("asset_ids")))
        and _stale_source_owned(activity, source_ids)
    ]
    if not relevant and stale_relevant:
        return _axis(
            "nd",
            "N/D",
            "Sono presenti attività collegate solo stale; origine corrente non valutabile.",
            **base_facts,
        )

    record_ids = sorted(str(item.get("id")) for item in relevant if item.get("id"))
    origin_records = [
        item for item in relevant if _activity_origin_asset(item) in asset_ids
    ]
    origin_ids = sorted(str(item.get("id")) for item in origin_records if item.get("id"))
    involved_records = [item for item in relevant if item not in origin_records]
    involved_ids = sorted(
        str(item.get("id")) for item in involved_records if item.get("id")
    )
    facts = {
        "record_ids": record_ids,
        "origin_record_ids": origin_ids,
        "involved_record_ids": involved_ids,
        "origin_attributed": bool(origin_ids),
    }
    if origin_ids:
        return _axis(
            "origin_observed",
            "Origine osservata",
            "Scrittura Modbus con origine esplicita associata all'asset.",
            **facts,
        )
    if involved_ids:
        return _axis(
            "involved_origin_unknown",
            "Coinvolta · origine N/D",
            "Asset coinvolto in una scrittura Modbus; direzione non determinata "
            "o non attribuibile.",
            **facts,
        )
    return _axis(
        "no_linked_records",
        "Nessun record collegato",
        "Capability utilizzabile, ma nessuna scrittura Modbus esplicita collegata.",
        **facts,
    )


def _event_axis(
    *,
    asset_ids: set[str],
    events: list[Mapping[str, Any]],
    capability: Mapping[str, str],
    source_ids: frozenset[str],
) -> dict[str, Any]:
    if capability["state"] != "usable":
        return _axis("nd", "N/D", capability["copy"], record_ids=[])
    if not asset_ids:
        return _axis(
            "nd",
            "N/D",
            "Identità asset non confermata: eventi non attribuibili.",
            record_ids=[],
        )
    linked = [
        event
        for event in events
        if asset_ids.intersection(_strings(event.get("asset_ids")))
        and _current_source_owned(event, source_ids)
    ]
    stale_linked = [
        event
        for event in events
        if asset_ids.intersection(_strings(event.get("asset_ids")))
        and _stale_source_owned(event, source_ids)
    ]
    if not linked and stale_linked:
        return _axis(
            "nd",
            "N/D",
            "Sono presenti eventi collegati solo stale; stato corrente non valutabile.",
            record_ids=[],
        )
    record_ids = sorted(str(item.get("id")) for item in linked if item.get("id"))
    if record_ids:
        return _axis(
            "linked_event",
            "Evento Cisco associato",
            "Evento Cisco source-owned con asset_ids espliciti associato all'asset.",
            record_ids=record_ids,
        )
    return _axis(
        "no_linked_records",
        "Nessun evento collegato",
        "Capability utilizzabile, ma nessun evento Cisco con asset_ids espliciti è collegato.",
        record_ids=[],
    )


def _baseline_axis(
    *,
    asset_ids: set[str],
    differences: list[Mapping[str, Any]],
    capability: Mapping[str, str],
    source_ids: frozenset[str],
) -> dict[str, Any]:
    facts: dict[str, Any] = {
        "record_ids": [],
        "difference_types": [],
        "attribution": "explicit_asset_ids_only",
        "evidence_class": "baseline_difference",
        "security_interpretation": "unclassified",
    }
    if not asset_ids:
        return _axis(
            "nd",
            "N/D",
            "Identità asset non confermata: differenze baseline non attribuibili.",
            **facts,
        )
    if capability["state"] != "usable":
        return _axis("nd", "N/D", capability["copy"], **facts)

    linked = [
        difference
        for difference in differences
        if asset_ids.intersection(_strings(difference.get("asset_ids")))
        and _current_source_owned(difference, source_ids)
    ]
    if linked:
        return _axis(
            "linked_difference",
            "Differenza baseline rilevata",
            "Evidenza anomala baseline source-owned e corrente, attribuita solo "
            "tramite asset_ids espliciti; non classifica origine o attacco.",
            **{
                **facts,
                "record_ids": sorted(
                    str(item.get("id")) for item in linked if item.get("id")
                ),
                "difference_types": sorted(
                    {
                        str(item.get("difference_type"))
                        for item in linked
                        if item.get("difference_type")
                    }
                ),
            },
        )
    return _axis(
        "no_linked_records",
        "Nessuna differenza collegata",
        "Capability utilizzabile, ma nessuna differenza baseline corrente con asset_ids "
        "espliciti è collegata.",
        **facts,
    )


def _overall_axis(
    identity: Mapping[str, Any],
    write_activity: Mapping[str, Any],
    alert_event: Mapping[str, Any],
    baseline_difference: Mapping[str, Any] | None = None,
) -> dict[str, str]:
    if alert_event["state"] == "linked_event":
        return _axis(
            "alert_event_linked",
            "Evento Cisco associato",
            "Esiste evidenza evento Cisco esplicitamente associata; "
            "classificarla richiede analisi operatore.",
        )
    if write_activity["state"] == "origin_observed":
        return _axis(
            "write_origin_observed",
            "Scrittura con origine osservata",
            "Attività Write Var/Modbus source-owned con direzione esplicita; "
            "nessun evento associato.",
        )
    if write_activity["state"] == "involved_origin_unknown":
        return _axis(
            "involved_origin_unknown",
            "Coinvolta · origine N/D",
            "Attività di scrittura collegata, ma la direzione non consente "
            "di attribuire l'origine.",
        )
    if baseline_difference and baseline_difference["state"] == "linked_difference":
        return _axis(
            "baseline_difference_linked",
            "Differenza baseline rilevata",
            "Esiste evidenza anomala baseline esplicitamente associata; non prova "
            "origine, tecnica o attacco.",
        )
    if identity["state"] not in {"confirmed", "partial"}:
        return _axis(
            "nd",
            "N/D",
            "Identità non verificabile: nessuna conclusione di copertura per questa origine.",
        )
    if (
        write_activity["state"] == "nd"
        or alert_event["state"] == "nd"
        or (baseline_difference and baseline_difference["state"] == "nd")
    ):
        return _axis(
            "nd",
            "N/D",
            "Una o più capability necessarie non sono valutabili con dati correnti.",
        )
    return _axis(
        "no_linked_records",
        "Non verificato · nessun record",
        "Identità confermata, ma nessuna scrittura o evento esplicito collegato; "
        "nessuna evidenza di sicurezza è verificata.",
    )


def build_detection_readiness(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Build a JSON-serializable, conservative detection-readiness matrix."""

    operator_source_ids = _source_ids(snapshot, "operator")
    cybervision_source_ids = _source_ids(snapshot, "cisco_cyber_vision")
    links = verified_identity_links(
        _mappings(snapshot.get("identity_links")),
        operator_source_ids=operator_source_ids,
    )
    activities = _mappings(snapshot.get("activities"))
    events = _mappings(snapshot.get("events"))
    baseline_differences = _mappings(snapshot.get("baseline_differences"))
    activity_capability = _capability_state(snapshot, "activities")
    event_capability = _capability_state(snapshot, "event_severities")
    baseline_capability = _capability_state(snapshot, "baseline_differences")

    rows: list[dict[str, Any]] = []
    virtual_machines = _mappings(snapshot.get("virtual_machines"))
    for key, label, purpose, official_target_required in _ORIGINS:
        matching_vms = []
        for vm in virtual_machines:
            context = vm.get("operational_context")
            if not isinstance(context, Mapping):
                continue
            if str(context.get("purpose") or "").casefold() != purpose:
                continue
            if official_target_required and context.get("official_target") is not True:
                continue
            if vm.get("id"):
                matching_vms.append(str(vm["id"]))
        matching_vms.sort()
        matching_links = [
            link
            for link in links
            if str(link.get("virtual_machine_id") or "") in matching_vms
        ]
        identity = _identity_axis(matching_vms, matching_links)
        asset_ids = set(identity["asset_ids"])
        write_activity = _write_axis(
            asset_ids=asset_ids,
            activities=activities,
            capability=activity_capability,
            source_ids=cybervision_source_ids,
        )
        alert_event = _event_axis(
            asset_ids=asset_ids,
            events=events,
            capability=event_capability,
            source_ids=cybervision_source_ids,
        )
        baseline_difference = _baseline_axis(
            asset_ids=asset_ids,
            differences=baseline_differences,
            capability=baseline_capability,
            source_ids=cybervision_source_ids,
        )
        rows.append(
            {
                "origin_key": key,
                "origin_label": label,
                "vm_ids": matching_vms,
                "asset_ids": sorted(asset_ids),
                "identity": identity,
                "write_activity": write_activity,
                "alert_event": alert_event,
                "baseline_difference": baseline_difference,
                "overall": _overall_axis(
                    identity, write_activity, alert_event, baseline_difference
                ),
            }
        )

    overall_counts = {
        state: sum(row["overall"]["state"] == state for row in rows)
        for state in sorted({str(row["overall"]["state"]) for row in rows})
    }
    linked_events = sum(row["alert_event"]["state"] == "linked_event" for row in rows)
    linked_baseline_differences = sum(
        row["baseline_difference"]["state"] == "linked_difference" for row in rows
    )
    current_baseline_differences = [
        item
        for item in baseline_differences
        if baseline_capability["state"] == "usable"
        and _current_source_owned(item, cybervision_source_ids)
    ]
    global_baseline_differences = [
        item for item in current_baseline_differences if not _strings(item.get("asset_ids"))
    ]
    mapped_asset_ids = {
        asset_id for row in rows for asset_id in _strings(row.get("asset_ids"))
    }
    unmapped_baseline_differences = [
        item
        for item in current_baseline_differences
        if _strings(item.get("asset_ids"))
        and not mapped_asset_ids.intersection(_strings(item.get("asset_ids")))
    ]
    summary_state = (
        "evidence_present"
        if linked_events or linked_baseline_differences
        else "partial"
        if any(row["overall"]["state"] != "nd" for row in rows)
        else "nd"
    )
    summary_label = {
        "evidence_present": "Evidenze associate presenti",
        "partial": "Copertura parziale",
        "nd": "Copertura N/D",
    }[summary_state]
    return {
        "matrix_version": "1.1",
        "rows": rows,
        "capabilities": {
            "activities": activity_capability,
            "events": event_capability,
            "baseline_differences": baseline_capability,
        },
        "baseline_evidence": {
            "policy": "source_owned_current_explicit_asset_ids_only",
            "security_interpretation": "unclassified",
            "current_record_ids": sorted(
                str(item.get("id"))
                for item in current_baseline_differences
                if item.get("id")
            ),
            "global_unattributed_record_ids": sorted(
                str(item.get("id"))
                for item in global_baseline_differences
                if item.get("id")
            ),
            "unmapped_explicit_record_ids": sorted(
                str(item.get("id"))
                for item in unmapped_baseline_differences
                if item.get("id")
            ),
            "linked_row_count": linked_baseline_differences,
            "copy": (
                "Le differenze senza asset_ids restano globali e non attribuite; non si "
                "correlano per timestamp, testo libero o protocollo."
            ),
        },
        "summary": {
            "state": summary_state,
            "label": summary_label,
            "copy": (
                "La matrice separa identità, scritture, eventi e differenze baseline; "
                "assenza di record non equivale ad assenza di rischio e ogni evidenza "
                "associata richiede classificazione operatore."
            ),
            "origins_total": len(rows),
            "identity_confirmed": sum(
                row["identity"]["state"] == "confirmed" for row in rows
            ),
            "write_origin_observed": sum(
                row["write_activity"]["state"] == "origin_observed" for row in rows
            ),
            "write_involved_origin_unknown": sum(
                row["write_activity"]["state"] == "involved_origin_unknown"
                for row in rows
            ),
            "alert_events_linked": linked_events,
            "baseline_differences_linked": linked_baseline_differences,
            "baseline_differences_global_unattributed": len(
                global_baseline_differences
            ),
            "baseline_differences_unmapped_explicit": len(
                unmapped_baseline_differences
            ),
            "overall_counts": overall_counts,
        },
        "copy": {
            "title": "Prontezza rilevamento scritture OT",
            "scope": (
                "Origini definite esclusivamente dal contesto operativo; correlazioni basate "
                "solo su identity link operator-confirmed univoci e telemetria Cisco source-owned."
            ),
            "caution": (
                "Direzione unknown/undetermined significa coinvolgimento, non origine. "
                "Titoli, descrizioni e coincidenza temporale non sono usati come prova."
            ),
        },
    }
