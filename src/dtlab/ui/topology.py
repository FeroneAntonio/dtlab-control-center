"""Topology figures derived only from validated relationships."""

from __future__ import annotations

import html
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import plotly.graph_objects as go

_SECURITY_TEST_COLOR = "#ba1a1a"
_HOST_OT_ACTIVE_COLOR = "#00639b"
_HOST_OT_STALE_COLOR = "#ba1a1a"
_PRIMARY_OT_COLOR = "#006b5f"
_OPERATIONAL_COLOR = "#416277"
_SUPPORT_COLOR = "#65558f"
_LEGACY_COLOR = "#7b8581"
_UNLINKED_ASSET_COLOR = "#526b63"
_TEST_COLOR = "#8a5100"


@dataclass(frozen=True, slots=True)
class _NodeStyle:
    kind: str
    label: str
    color: str
    symbol: str


def _escaped(value: object, fallback: str = "N/D") -> str:
    text = str(value).strip() if value is not None else ""
    return html.escape(text or fallback)


def _context(record: Mapping[str, Any]) -> Mapping[str, Any]:
    value = record.get("operational_context")
    return value if isinstance(value, Mapping) else {}


def _context_truth(record: Mapping[str, Any]) -> str:
    evidence = _context(record).get("evidence")
    if not isinstance(evidence, Mapping):
        return "unavailable"
    return str(evidence.get("truth") or "unavailable").casefold()


def _source_owned_observation(
    record: Mapping[str, Any],
    source_ids: set[str],
) -> bool:
    evidence = record.get("evidence")
    if not isinstance(evidence, Mapping):
        return False
    return str(evidence.get("source_id") or "") in source_ids and str(
        evidence.get("truth") or ""
    ).casefold() in {"real", "observed", "stale"}


def _vm_style(vm: Mapping[str, Any]) -> _NodeStyle:
    context = _context(vm)
    purpose = str(context.get("purpose") or "").casefold()
    lifecycle = str(context.get("lifecycle_role") or "").casefold()
    scope = str(context.get("kpi_scope") or "").casefold()
    if purpose == "security_testing":
        return _NodeStyle(
            "red_team",
            "Sorgente ostile di test",
            _SECURITY_TEST_COLOR,
            "x",
        )
    if scope == "excluded_test" or lifecycle == "test":
        return _NodeStyle("test", "Sistema di test", _TEST_COLOR, "diamond-open")
    if scope == "excluded_legacy" or lifecycle == "legacy":
        return _NodeStyle("legacy", "Legacy esclusa", _LEGACY_COLOR, "circle-open")
    if bool(context.get("official_target")) or scope == "primary":
        return _NodeStyle("primary_ot", "Target OT", _PRIMARY_OT_COLOR, "circle")
    if purpose == "cyber_vision" or lifecycle == "support":
        return _NodeStyle("support", "Infrastruttura", _SUPPORT_COLOR, "hexagon")
    if lifecycle == "operational":
        return _NodeStyle("operational", "Sistema operativo", _OPERATIONAL_COLOR, "circle")
    return _NodeStyle("other", "VM osservata", _UNLINKED_ASSET_COLOR, "circle")


def _confirmed_vm_by_asset(
    virtual_machines: Sequence[Mapping[str, Any]],
    identity_links: Sequence[Mapping[str, Any]],
    *,
    operator_source_ids: set[str] | frozenset[str],
) -> dict[str, Mapping[str, Any]]:
    vm_by_id = {str(vm.get("id")): vm for vm in virtual_machines if vm.get("id")}
    result: dict[str, Mapping[str, Any]] = {}
    for link in verified_identity_links(
        identity_links,
        operator_source_ids=operator_source_ids,
    ):
        vm = vm_by_id.get(str(link.get("virtual_machine_id")))
        asset_id = link.get("asset_id")
        if vm is not None and asset_id:
            result[str(asset_id)] = vm
    return result


def identity_link_is_confirmed(
    link: Mapping[str, Any],
    *,
    operator_source_ids: set[str] | frozenset[str],
) -> bool:
    """Accept a confirmed identity only when its evidence was source-owned.

    Dashboard ageing can relabel previously verified evidence as ``stale``; this
    preserves the historical confirmation while the separate telemetry axis exposes
    that it must not be treated as current.
    """

    if link.get("status") != "confirmed" or link.get("method") != "operator_confirmed":
        return False
    evidence = link.get("evidence")
    if not isinstance(evidence, Mapping):
        return False
    return str(evidence.get("source_id") or "") in operator_source_ids and str(
        evidence.get("truth") or ""
    ).casefold() in {"real", "observed", "stale"}


def verified_identity_links(
    identity_links: Sequence[Mapping[str, Any]],
    *,
    operator_source_ids: set[str] | frozenset[str],
) -> tuple[Mapping[str, Any], ...]:
    """Resolve only one-to-one operator-confirmed VM↔asset identities."""

    candidates = [
        link
        for link in identity_links
        if identity_link_is_confirmed(
            link,
            operator_source_ids=operator_source_ids,
        )
    ]
    vm_counts = Counter(str(link.get("virtual_machine_id")) for link in candidates)
    asset_counts = Counter(str(link.get("asset_id")) for link in candidates)
    return tuple(
        link
        for link in candidates
        if vm_counts[str(link.get("virtual_machine_id"))] == 1
        and asset_counts[str(link.get("asset_id"))] == 1
    )


def verified_identity_link_ids(snapshot: Mapping[str, Any]) -> frozenset[str]:
    operator_source_ids = {
        str(source.get("id"))
        for source in snapshot.get("sources", [])
        if isinstance(source, Mapping) and source.get("id") and source.get("type") == "operator"
    }
    links = [link for link in snapshot.get("identity_links", []) if isinstance(link, Mapping)]
    return frozenset(
        str(link.get("id"))
        for link in verified_identity_links(
            links,
            operator_source_ids=operator_source_ids,
        )
        if link.get("id")
    )


def _asset_style(
    asset: Mapping[str, Any],
    vm_by_asset: Mapping[str, Mapping[str, Any]],
) -> _NodeStyle:
    vm = vm_by_asset.get(str(asset.get("id")))
    if vm is None:
        return _NodeStyle(
            "unlinked_asset",
            "Asset Cisco non correlato",
            _UNLINKED_ASSET_COLOR,
            "square-open",
        )
    vm_style = _vm_style(vm)
    if vm_style.kind == "red_team":
        return _NodeStyle("red_team", vm_style.label, _SECURITY_TEST_COLOR, "x")
    if vm_style.kind == "primary_ot":
        return _NodeStyle("primary_ot", "Target OT", _PRIMARY_OT_COLOR, "square")
    if vm_style.kind == "operational":
        return _NodeStyle("operational", "Sistema OT", _OPERATIONAL_COLOR, "square")
    if vm_style.kind == "support":
        return _NodeStyle("support", "Infrastruttura", _SUPPORT_COLOR, "hexagon")
    if vm_style.kind == "legacy":
        return _NodeStyle("legacy", "Legacy esclusa", _LEGACY_COLOR, "square-open")
    if vm_style.kind == "test":
        return _NodeStyle("test", "Sistema di test", _TEST_COLOR, "diamond-open")
    return _NodeStyle("asset", "Asset Cyber Vision", _OPERATIONAL_COLOR, "square")


def _node_text(name: object, style: _NodeStyle) -> str:
    label = html.escape(str(name).removeprefix("[Relatech] "))
    if style.kind == "red_team":
        return f"☠ {label}<br><b>SORGENTE OSTILE DI TEST</b>"
    return label


def _vm_node_text(
    vm: Mapping[str, Any],
    style: _NodeStyle,
    *,
    highlighted: bool,
    total_count: int,
) -> str:
    """Keep dense topology rows readable while preserving every node on hover."""

    if total_count <= 4 or highlighted or style.kind in {"red_team", "primary_ot"}:
        return _node_text(vm.get("name") or vm.get("id"), style)
    return ""


def _asset_node_text(
    asset: Mapping[str, Any],
    style: _NodeStyle,
    *,
    highlighted: bool,
    total_count: int,
) -> str:
    if total_count <= 2 or highlighted or style.kind in {"red_team", "primary_ot"}:
        return _node_text(asset.get("name") or asset.get("id"), style)
    return ""


def _node_text_position(style: _NodeStyle) -> str:
    if style.kind == "red_team":
        return "top left"
    if style.kind == "primary_ot":
        return "top right"
    return "top center"


def security_topology_summary(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Return only explicit security-testing roles and source-owned observations.

    A declared security-testing role is never promoted to an observed attack.  Flow,
    activity and event counts remain separate source-owned observations; attack
    classification belongs to an explicit detection or a labelled Scenario Lab run.
    """

    virtual_machines = [
        vm for vm in snapshot.get("virtual_machines", []) if isinstance(vm, Mapping)
    ]
    assets = [asset for asset in snapshot.get("assets", []) if isinstance(asset, Mapping)]
    links = [link for link in snapshot.get("identity_links", []) if isinstance(link, Mapping)]
    sources = [source for source in snapshot.get("sources", []) if isinstance(source, Mapping)]
    operator_source_ids = {
        str(source.get("id"))
        for source in sources
        if source.get("id") and source.get("type") == "operator"
    }
    cybervision_source = next(
        (source for source in sources if source.get("type") == "cisco_cyber_vision"),
        {},
    )
    cybervision_source_ids = (
        {str(cybervision_source.get("id"))} if cybervision_source.get("id") else set()
    )
    red_team_vms = [vm for vm in virtual_machines if _vm_style(vm).kind == "red_team"]
    red_team_vm_ids = {str(vm.get("id")) for vm in red_team_vms if vm.get("id")}
    vm_by_asset = _confirmed_vm_by_asset(
        virtual_machines,
        links,
        operator_source_ids=operator_source_ids,
    )
    red_team_asset_ids = {
        str(asset_id) for asset_id, vm in vm_by_asset.items() if _vm_style(vm).kind == "red_team"
    }
    asset_by_id = {str(asset.get("id")): asset for asset in assets if asset.get("id")}
    observed_flows = [
        flow
        for flow in snapshot.get("flows", [])
        if isinstance(flow, Mapping)
        and _source_owned_observation(flow, cybervision_source_ids)
        and (
            str(flow.get("left_asset_id")) in red_team_asset_ids
            or str(flow.get("right_asset_id")) in red_team_asset_ids
        )
    ]
    observed_events = [
        event
        for event in snapshot.get("events", [])
        if isinstance(event, Mapping)
        and _source_owned_observation(event, cybervision_source_ids)
        and red_team_asset_ids.intersection(
            str(asset_id) for asset_id in event.get("asset_ids", [])
        )
    ]
    observed_activities = [
        activity
        for activity in snapshot.get("activities", [])
        if isinstance(activity, Mapping)
        and _source_owned_observation(activity, cybervision_source_ids)
        and red_team_asset_ids.intersection(
            str(asset_id) for asset_id in activity.get("asset_ids", [])
        )
    ]
    counterparty_ids: set[str] = set()
    for flow in observed_flows:
        for key in ("left_asset_id", "right_asset_id"):
            asset_id = str(flow.get(key))
            if asset_id and asset_id not in red_team_asset_ids:
                counterparty_ids.add(asset_id)

    relevant_links = [
        link for link in links if str(link.get("virtual_machine_id")) in red_team_vm_ids
    ]
    if red_team_asset_ids:
        identity_state = "confirmed"
    elif any(link.get("status") == "proposed" for link in relevant_links):
        identity_state = "proposed"
    elif relevant_links:
        identity_state = "ambiguous"
    else:
        identity_state = "none"

    role_truths = tuple(sorted({_context_truth(vm) for vm in red_team_vms}))
    role_source_ids = {
        str(evidence.get("source_id"))
        for vm in red_team_vms
        if isinstance((evidence := _context(vm).get("evidence")), Mapping)
        and evidence.get("source_id")
    }
    role_status = (
        "operator_confirmed"
        if role_truths
        and set(role_truths).issubset({"real", "observed"})
        and role_source_ids
        and role_source_ids.issubset(operator_source_ids)
        else "expected"
        if red_team_vms
        else "unknown"
    )
    role_evidence_refs: set[str] = set()
    for vm in red_team_vms:
        evidence = _context(vm).get("evidence")
        if not isinstance(evidence, Mapping):
            continue
        source_id = evidence.get("source_id")
        record_id = evidence.get("source_record_id")
        if source_id or record_id:
            role_evidence_refs.add(f"{source_id or 'N/D'} · {record_id or 'N/D'}")

    capabilities = cybervision_source.get("capabilities")
    flow_capability = capabilities.get("flows") if isinstance(capabilities, Mapping) else None
    flow_capability_status = (
        str(flow_capability.get("status") or "unknown").casefold()
        if isinstance(flow_capability, Mapping)
        else "unknown"
    )
    sync = snapshot.get("sync")
    sync_state = (
        str(sync.get("state") or "unknown").casefold() if isinstance(sync, Mapping) else "unknown"
    )
    cybervision_source_status = str(cybervision_source.get("status") or "unknown").casefold()
    usable_flow_states = {"available", "partial", "truncated"}
    unavailable_flow_states = {
        "error",
        "not_configured",
        "unavailable",
        "endpoint_unavailable",
        "feature_unlicensed",
    }
    if cybervision_source_status in {"unavailable", "not_configured"} or sync_state in {
        "offline",
        "failed",
    }:
        telemetry_state = "unavailable"
    elif cybervision_source_status == "stale" or sync_state == "stale":
        telemetry_state = "stale"
    elif cybervision_source_status not in {"connected", "degraded"}:
        telemetry_state = "unknown"
    elif flow_capability_status == "available" and sync_state == "fresh":
        telemetry_state = "available"
    elif flow_capability_status in usable_flow_states and sync_state in {
        "fresh",
        "partial",
    }:
        telemetry_state = "partial"
    elif flow_capability_status in unavailable_flow_states:
        telemetry_state = "unavailable"
    else:
        telemetry_state = "unknown"

    if telemetry_state in {"stale", "unavailable", "unknown"}:
        activity_state = "unavailable"
    elif observed_flows:
        activity_state = "communication_observed"
    else:
        activity_state = "no_linked_records_returned"
    return {
        "role_assertion": {
            "status": role_status,
            "evidence_refs": tuple(sorted(role_evidence_refs)),
        },
        "identity_state": identity_state,
        "telemetry_state": telemetry_state,
        "flow_capability_status": flow_capability_status,
        "activity_state": activity_state,
        "exercise_state": "not_evaluated",
        "vm_names": tuple(str(vm.get("name") or vm.get("id")) for vm in red_team_vms),
        "asset_ids": tuple(sorted(red_team_asset_ids)),
        "asset_names": tuple(
            str(asset_by_id[asset_id].get("name") or asset_id)
            for asset_id in sorted(red_team_asset_ids)
            if asset_id in asset_by_id
        ),
        "role_truths": role_truths,
        "observed_flow_count": len(observed_flows),
        "observed_event_count": len(observed_events),
        "observed_activity_count": len(observed_activities),
        "counterparty_names": tuple(
            str(asset_by_id[asset_id].get("name") or asset_id)
            for asset_id in sorted(counterparty_ids)
            if asset_id in asset_by_id
        ),
    }


def _layout(names: list[str], y: float, width: float = 1.0) -> dict[str, tuple[float, float]]:
    if not names:
        return {}
    center = (len(names) - 1) / 2
    return {name: ((index - center) * width, y) for index, name in enumerate(names)}


def _base_figure(height: int = 650) -> go.Figure:
    figure = go.Figure()
    figure.update_layout(
        height=height,
        margin={"l": 10, "r": 10, "t": 42, "b": 165},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        showlegend=True,
        legend={
            "orientation": "h",
            "yanchor": "top",
            "y": -0.1,
            "xanchor": "left",
            "x": 0,
            "font": {"size": 11},
        },
        xaxis={"visible": False},
        yaxis={"visible": False},
        hoverlabel={"bgcolor": "#17201e", "font": {"color": "#ffffff"}},
        hovermode="closest",
    )
    return figure


def _endpoint_group_label(
    flows: Sequence[Mapping[str, Any]],
    asset_id: str,
) -> str:
    sides = [
        "left" if str(flow.get("left_asset_id") or "") == asset_id else "right" for flow in flows
    ]
    labels = sorted(
        {
            str(flow.get(f"{side}_label") or flow.get(f"{side}_ip") or "N/D")
            for flow, side in zip(flows, sides, strict=True)
        }
    )
    ports = sorted(
        {
            str(flow[f"{side}_port"])
            for flow, side in zip(flows, sides, strict=True)
            if flow.get(f"{side}_port") is not None
        }
    )
    label = ", ".join(labels)
    if ports:
        visible_ports = ", ".join(ports[:5])
        if len(ports) > 5:
            visible_ports += f" (+{len(ports) - 5})"
        label = f"{label} · porte {visible_ports}"
    return html.escape(label)


def _flow_direction_from_a(flow: Mapping[str, Any], endpoint_a: str) -> str:
    direction = str(flow.get("direction") or "unknown")
    left_is_a = str(flow.get("left_asset_id") or "") == endpoint_a
    if direction == "left_to_right":
        return "A → B" if left_is_a else "B → A"
    if direction == "right_to_left":
        return "B → A" if left_is_a else "A → B"
    if direction == "bidirectional":
        return "A ↔ B"
    return "Non determinata"


def _count_breakdown(values: Sequence[str]) -> str:
    counts = Counter(values)
    return html.escape(
        " · ".join(
            f"{label} × {count}"
            for label, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
        )
        or "N/D"
    )


def _add_flow_hover_points(
    figure: go.Figure,
    flows: Sequence[Mapping[str, Any]],
    positions: Mapping[str, tuple[float, float]],
) -> None:
    grouped: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    for flow in flows:
        left = str(flow.get("left_asset_id") or "")
        right = str(flow.get("right_asset_id") or "")
        if left not in positions or right not in positions:
            continue
        key = tuple(sorted((left, right)))
        grouped.setdefault(key, []).append(flow)
    x_values: list[float] = []
    y_values: list[float] = []
    customdata: list[list[str]] = []
    for (endpoint_a, endpoint_b), records in grouped.items():
        x0, y0 = positions[endpoint_a]
        x1, y1 = positions[endpoint_b]
        truths = sorted(
            {
                str(evidence.get("truth") or "N/D")
                for record in records
                if isinstance((evidence := record.get("evidence")), Mapping)
            }
        )
        first_seen = [
            str(record["first_seen_at"]) for record in records if record.get("first_seen_at")
        ]
        last_seen = [
            str(record["last_seen_at"]) for record in records if record.get("last_seen_at")
        ]
        x_values.append((x0 + x1) / 2)
        y_values.append((y0 + y1) / 2)
        customdata.append(
            [
                _endpoint_group_label(records, endpoint_a),
                _endpoint_group_label(records, endpoint_b),
                str(len(records)),
                _count_breakdown([str(record.get("protocol") or "N/D") for record in records]),
                _count_breakdown(
                    [_flow_direction_from_a(record, endpoint_a) for record in records]
                ),
                html.escape(min(first_seen) if first_seen else "N/D"),
                html.escape(max(last_seen) if last_seen else "N/D"),
                str(sum(int(record.get("packet_count") or 0) for record in records)),
                str(sum(int(record.get("byte_count") or 0) for record in records)),
                html.escape(", ".join(truths) or "N/D"),
            ]
        )
    if not x_values:
        return
    figure.add_trace(
        go.Scatter(
            x=x_values,
            y=y_values,
            mode="markers",
            marker={"size": 18, "color": "rgba(0,0,0,0)"},
            customdata=customdata,
            hovertemplate=(
                "<b>Endpoint A: %{customdata[0]}</b><br>Endpoint B: %{customdata[1]}"
                "<br>Record aggregati: %{customdata[2]}"
                "<br>Protocolli: %{customdata[3]}"
                "<br>Direzioni dichiarate rispetto ad A/B: %{customdata[4]}"
                "<br>Prima: %{customdata[5]}<br>Ultima: %{customdata[6]}"
                "<br>Pacchetti: %{customdata[7]} · Byte: %{customdata[8]}"
                "<br>Dato: %{customdata[9]}<extra></extra>"
            ),
            showlegend=False,
            name="Dettaglio flow",
        )
    )


def vmware_topology(
    virtual_machines: list[dict[str, Any]],
    networks: list[dict[str, Any]],
    *,
    highlight_id: str | None = None,
) -> go.Figure:
    figure = _base_figure()
    vm_positions = _layout([vm["id"] for vm in virtual_machines], 1.0, 1.3)
    network_positions = _layout([network["id"] for network in networks], 0.0, 1.8)
    active_highlight = highlight_id if highlight_id in vm_positions else None
    edge_x: list[float | None] = []
    edge_y: list[float | None] = []
    for vm in virtual_machines:
        for interface in vm["interfaces"]:
            network_id = interface.get("network_id")
            if network_id not in network_positions:
                continue
            x0, y0 = vm_positions[vm["id"]]
            x1, y1 = network_positions[network_id]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
    figure.add_trace(
        go.Scatter(
            x=edge_x,
            y=edge_y,
            mode="lines",
            line={"color": "#9eaaa6", "width": 2},
            hoverinfo="skip",
            name="NIC osservata",
        )
    )
    grouped_vms: dict[_NodeStyle, list[dict[str, Any]]] = {}
    for vm in virtual_machines:
        grouped_vms.setdefault(_vm_style(vm), []).append(vm)
    for style, records in grouped_vms.items():
        figure.add_trace(
            go.Scatter(
                x=[vm_positions[vm["id"]][0] for vm in records],
                y=[1.0] * len(records),
                mode="markers+text",
                text=[
                    _vm_node_text(
                        vm,
                        style,
                        highlighted=active_highlight == vm["id"],
                        total_count=len(virtual_machines),
                    )
                    for vm in records
                ],
                textposition=_node_text_position(style),
                marker={
                    "size": [
                        (44 if style.kind == "red_team" else 40)
                        if active_highlight == vm["id"]
                        else (38 if style.kind == "red_team" else 34)
                        for vm in records
                    ],
                    "color": style.color,
                    "symbol": style.symbol,
                    "opacity": [
                        1.0 if active_highlight in {None, vm["id"]} else 0.22 for vm in records
                    ],
                    "line": {"color": "#ffffff", "width": 3},
                },
                customdata=[
                    [
                        _escaped(vm.get("power_state")),
                        _escaped(style.label),
                        _escaped(_context(vm).get("kpi_scope")),
                        _escaped((vm.get("evidence") or {}).get("truth")),
                    ]
                    for vm in records
                ],
                hovertemplate=(
                    "<b>%{text}</b><br>Power: %{customdata[0]}"
                    "<br>Ruolo: %{customdata[1]}<br>Ambito KPI: %{customdata[2]}"
                    "<br>Dato: %{customdata[3]}<extra></extra>"
                ),
                name=f"VM · {style.label}",
            )
        )
    figure.add_trace(
        go.Scatter(
            x=[network_positions[network["id"]][0] for network in networks],
            y=[0.0] * len(networks),
            mode="markers+text",
            text=[html.escape(network["name"]) for network in networks],
            textposition="bottom center",
            marker={
                "size": 42,
                "symbol": "diamond",
                "color": "#9ef2df",
                "line": {"color": "#006b5f", "width": 2},
            },
            hovertemplate="<b>%{text}</b><br>Port group osservato<extra></extra>",
            name="Port group",
        )
    )
    figure.update_yaxes(range=[-0.35, 1.35])
    figure.add_annotation(
        xref="paper",
        x=0,
        y=1.18,
        text="VMWARE",
        showarrow=False,
        font={"size": 10, "color": "#6f7976"},
        xanchor="left",
    )
    return figure


def flow_topology(
    assets: list[dict[str, Any]],
    flows: list[dict[str, Any]],
    *,
    virtual_machines: Sequence[Mapping[str, Any]] = (),
    identity_links: Sequence[Mapping[str, Any]] = (),
    cybervision_source_ids: set[str] | frozenset[str] = frozenset(),
    operator_source_ids: set[str] | frozenset[str] = frozenset(),
    highlight_id: str | None = None,
) -> go.Figure:
    figure = _base_figure()
    positions = _layout([asset["id"] for asset in assets], 0.5, 1.4)
    active_highlight = highlight_id if highlight_id in positions else None
    vm_by_asset = _confirmed_vm_by_asset(
        virtual_machines,
        identity_links,
        operator_source_ids=operator_source_ids,
    )
    red_team_asset_ids = {
        asset_id for asset_id, vm in vm_by_asset.items() if _vm_style(vm).kind == "red_team"
    }

    def add_flow_edges(records: Sequence[Mapping[str, Any]], *, red_team: bool) -> None:
        edge_x: list[float | None] = []
        edge_y: list[float | None] = []
        for flow in records:
            left = flow.get("left_asset_id")
            right = flow.get("right_asset_id")
            if left not in positions or right not in positions:
                continue
            x0, y0 = positions[str(left)]
            x1, y1 = positions[str(right)]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
        if edge_x:
            figure.add_trace(
                go.Scatter(
                    x=edge_x,
                    y=edge_y,
                    mode="lines",
                    line={
                        "color": _SECURITY_TEST_COLOR if red_team else "#d65f00",
                        "width": 5 if red_team else 3,
                    },
                    hoverinfo="skip",
                    name=("Comunicazione con host di test" if red_team else "Flow Cisco"),
                )
            )

    red_team_flows: list[Mapping[str, Any]] = []
    regular_flows: list[Mapping[str, Any]] = []
    verified_flows = [
        flow for flow in flows if _source_owned_observation(flow, set(cybervision_source_ids))
    ]
    for flow in verified_flows:
        if (
            str(flow.get("left_asset_id")) in red_team_asset_ids
            or str(flow.get("right_asset_id")) in red_team_asset_ids
        ):
            red_team_flows.append(flow)
        else:
            regular_flows.append(flow)
    add_flow_edges(regular_flows, red_team=False)
    add_flow_edges(red_team_flows, red_team=True)
    _add_flow_hover_points(figure, verified_flows, positions)

    grouped_assets: dict[_NodeStyle, list[dict[str, Any]]] = {}
    for asset in assets:
        grouped_assets.setdefault(_asset_style(asset, vm_by_asset), []).append(asset)
    for style, records in grouped_assets.items():
        figure.add_trace(
            go.Scatter(
                x=[positions[asset["id"]][0] for asset in records],
                y=[0.5] * len(records),
                mode="markers+text",
                text=[
                    _asset_node_text(
                        asset,
                        style,
                        highlighted=active_highlight == asset["id"],
                        total_count=len(assets),
                    )
                    for asset in records
                ],
                textposition="top center",
                marker={
                    "size": [
                        (48 if style.kind == "red_team" else 44)
                        if active_highlight == asset["id"]
                        else (42 if style.kind == "red_team" else 38)
                        for asset in records
                    ],
                    "color": style.color,
                    "symbol": style.symbol,
                    "opacity": [
                        1.0 if active_highlight in {None, asset["id"]} else 0.22
                        for asset in records
                    ],
                    "line": {"color": "#ffffff", "width": 3},
                },
                customdata=[
                    [
                        _escaped(asset.get("device_type")),
                        _escaped(", ".join(asset.get("ip_addresses", [])), "—"),
                        _escaped(style.label),
                        _escaped((asset.get("evidence") or {}).get("truth")),
                    ]
                    for asset in records
                ],
                hovertemplate=(
                    "<b>%{text}</b><br>Tipo: %{customdata[0]}<br>IP: %{customdata[1]}"
                    "<br>Ruolo: %{customdata[2]}<br>Dato: %{customdata[3]}<extra></extra>"
                ),
                name=style.label,
            )
        )
    figure.update_yaxes(range=[0.0, 1.15])
    return figure


def integrated_topology(
    snapshot: dict[str, Any],
    *,
    highlight_id: str | None = None,
    host_ot_sensors: Sequence[Mapping[str, Any]] | None = None,
) -> go.Figure:
    figure = _base_figure(height=850)
    vms = snapshot["virtual_machines"]
    assets = snapshot["assets"]
    networks = snapshot["networks"]
    vm_positions = _layout([vm["id"] for vm in vms], 2.0, 1.35)
    asset_positions = _layout([asset["id"] for asset in assets], 1.0, 1.5)
    network_positions = _layout([network["id"] for network in networks], 0.0, 1.8)
    operator_source_ids = {
        str(source.get("id"))
        for source in snapshot.get("sources", [])
        if isinstance(source, Mapping) and source.get("id") and source.get("type") == "operator"
    }
    verified_links = verified_identity_links(
        snapshot["identity_links"],
        operator_source_ids=operator_source_ids,
    )
    vm_by_asset = _confirmed_vm_by_asset(
        vms,
        verified_links,
        operator_source_ids=operator_source_ids,
    )
    cybervision_source_ids = {
        str(source.get("id"))
        for source in snapshot.get("sources", [])
        if isinstance(source, Mapping)
        and source.get("id")
        and source.get("type") == "cisco_cyber_vision"
    }
    red_team_asset_ids = {
        asset_id for asset_id, vm in vm_by_asset.items() if _vm_style(vm).kind == "red_team"
    }
    highlight_ids = {highlight_id} if highlight_id else set()
    if highlight_id:
        for link in verified_links:
            vm_id = str(link.get("virtual_machine_id"))
            asset_id = str(link.get("asset_id"))
            if highlight_id == vm_id:
                highlight_ids.add(asset_id)
            elif highlight_id == asset_id:
                highlight_ids.add(vm_id)

    host_ot_records = [record for record in (host_ot_sensors or ()) if isinstance(record, Mapping)]
    host_ot_positions: dict[str, tuple[float, float]] = {}
    host_ot_targets: list[tuple[str, str]] = []
    target_vm = next(
        (
            vm
            for vm in vms
            if bool(_context(vm).get("official_target"))
            or "plc-desktop" in str(vm.get("name") or "").casefold()
        ),
        None,
    )
    for index, record in enumerate(host_ot_records):
        sensor_id = str(record.get("sensor_id") or f"sensor-{index + 1}")
        node_id = f"host-ot:{sensor_id}"
        target_x = vm_positions.get(str((target_vm or {}).get("id")), (0.0, 2.0))[0]
        host_ot_positions[node_id] = (target_x + (index * 0.34), 2.78)
        if target_vm is not None:
            host_ot_targets.append((node_id, str(target_vm["id"])))
        if highlight_id == node_id:
            highlight_ids.add(node_id)
            if target_vm is not None:
                highlight_ids.add(str(target_vm["id"]))

    def add_edges(
        pairs: list[tuple[str, str]],
        positions_a: dict[str, tuple[float, float]],
        positions_b: dict[str, tuple[float, float]],
        *,
        name: str,
        color: str,
        dash: str = "solid",
        width: int = 2,
    ) -> None:
        x_values: list[float | None] = []
        y_values: list[float | None] = []
        for source, destination in pairs:
            if source not in positions_a or destination not in positions_b:
                continue
            x0, y0 = positions_a[source]
            x1, y1 = positions_b[destination]
            x_values.extend([x0, x1, None])
            y_values.extend([y0, y1, None])
        if x_values:
            figure.add_trace(
                go.Scatter(
                    x=x_values,
                    y=y_values,
                    mode="lines",
                    line={"color": color, "width": width, "dash": dash},
                    hoverinfo="skip",
                    name=name,
                )
            )

    add_edges(
        [
            (vm["id"], interface["network_id"])
            for vm in vms
            for interface in vm["interfaces"]
            if interface.get("network_id")
        ],
        vm_positions,
        network_positions,
        name="VM ↔ Port group",
        color="#b2bcb8",
    )
    add_edges(
        host_ot_targets,
        host_ot_positions,
        vm_positions,
        name="Copertura Host OT / EDR",
        color=_HOST_OT_ACTIVE_COLOR,
        width=5,
    )
    add_edges(
        [(link["virtual_machine_id"], link["asset_id"]) for link in verified_links],
        vm_positions,
        asset_positions,
        name="Identità confermata",
        color="#006b5f",
        width=4,
    )
    add_edges(
        [
            (link["virtual_machine_id"], link["asset_id"])
            for link in snapshot["identity_links"]
            if link["status"] == "proposed"
        ],
        vm_positions,
        asset_positions,
        name="Identità proposta",
        color="#6f7976",
        dash="dash",
    )
    verified_flows = [
        flow
        for flow in snapshot["flows"]
        if _source_owned_observation(flow, cybervision_source_ids)
    ]
    regular_flow_pairs = [
        (flow["left_asset_id"], flow["right_asset_id"])
        for flow in verified_flows
        if flow.get("left_asset_id")
        and flow.get("right_asset_id")
        and not (
            str(flow["left_asset_id"]) in red_team_asset_ids
            or str(flow["right_asset_id"]) in red_team_asset_ids
        )
    ]
    red_team_flow_pairs = [
        (flow["left_asset_id"], flow["right_asset_id"])
        for flow in verified_flows
        if flow.get("left_asset_id")
        and flow.get("right_asset_id")
        and (
            str(flow["left_asset_id"]) in red_team_asset_ids
            or str(flow["right_asset_id"]) in red_team_asset_ids
        )
    ]
    add_edges(
        regular_flow_pairs,
        asset_positions,
        asset_positions,
        name="Flow Cyber Vision",
        color="#d65f00",
        width=3,
    )
    add_edges(
        red_team_flow_pairs,
        asset_positions,
        asset_positions,
        name="Comunicazione con host di test",
        color=_SECURITY_TEST_COLOR,
        width=5,
    )
    _add_flow_hover_points(figure, verified_flows, asset_positions)

    if host_ot_records:
        node_ids = [
            f"host-ot:{str(record.get('sensor_id') or f'sensor-{index + 1}')}"
            for index, record in enumerate(host_ot_records)
        ]
        states = [
            "active" if str(record.get("coverage_state")) == "active" else "stale"
            for record in host_ot_records
        ]
        figure.add_trace(
            go.Scatter(
                x=[host_ot_positions[node_id][0] for node_id in node_ids],
                y=[host_ot_positions[node_id][1] for node_id in node_ids],
                mode="markers+text",
                text=[
                    "🛡 HOST OT / EDR<br><b>ATTIVO</b>"
                    if state == "active"
                    else "⚠ HOST OT / EDR<br><b>NON RECENTE</b>"
                    for state in states
                ],
                textposition="top center",
                marker={
                    "size": [50 if node_id in highlight_ids else 44 for node_id in node_ids],
                    "color": [
                        _HOST_OT_ACTIVE_COLOR if state == "active" else _HOST_OT_STALE_COLOR
                        for state in states
                    ],
                    "symbol": "hexagon2",
                    "opacity": [
                        1.0 if not highlight_ids or node_id in highlight_ids else 0.22
                        for node_id in node_ids
                    ],
                    "line": {"color": "#ffffff", "width": 3},
                },
                customdata=[
                    [
                        _escaped(record.get("sensor_id"), "sensore PLC"),
                        "Attiva" if state == "active" else "Non recente",
                        _escaped(record.get("received_at")),
                        _escaped(record.get("event_type"), "heartbeat"),
                    ]
                    for record, state in zip(host_ot_records, states, strict=True)
                ],
                hovertemplate=(
                    "<b>%{text}</b><br>Sensore: %{customdata[0]}"
                    "<br>Copertura: %{customdata[1]}<br>Ultima ricezione: %{customdata[2]}"
                    "<br>Ultimo record: %{customdata[3]}"
                    "<br>Fonte: sensore endpoint autenticato, non Cisco<extra></extra>"
                ),
                name="Host OT / EDR",
            )
        )

    grouped_vms: dict[_NodeStyle, list[dict[str, Any]]] = {}
    for vm in vms:
        grouped_vms.setdefault(_vm_style(vm), []).append(vm)
    for style, records in grouped_vms.items():
        figure.add_trace(
            go.Scatter(
                x=[vm_positions[record["id"]][0] for record in records],
                y=[2.0] * len(records),
                mode="markers+text",
                text=[
                    _vm_node_text(
                        record,
                        style,
                        highlighted=record["id"] in highlight_ids,
                        total_count=len(vms),
                    )
                    for record in records
                ],
                textposition=_node_text_position(style),
                marker={
                    "size": [
                        (44 if style.kind == "red_team" else 40)
                        if record["id"] in highlight_ids
                        else (38 if style.kind == "red_team" else 34)
                        for record in records
                    ],
                    "color": style.color,
                    "symbol": style.symbol,
                    "opacity": [
                        1.0 if not highlight_ids or record["id"] in highlight_ids else 0.22
                        for record in records
                    ],
                    "line": {"color": "#ffffff", "width": 2},
                },
                customdata=[
                    [
                        _escaped(style.label),
                        _escaped(record.get("power_state")),
                        _escaped(_context(record).get("kpi_scope")),
                    ]
                    for record in records
                ],
                hovertemplate=(
                    "<b>%{text}</b><br>Ruolo: %{customdata[0]}"
                    "<br>Power: %{customdata[1]}<br>Ambito KPI: %{customdata[2]}"
                    "<extra></extra>"
                ),
                name=f"VM · {style.label}",
            )
        )

    grouped_assets: dict[_NodeStyle, list[dict[str, Any]]] = {}
    for asset in assets:
        grouped_assets.setdefault(_asset_style(asset, vm_by_asset), []).append(asset)
    for style, records in grouped_assets.items():
        figure.add_trace(
            go.Scatter(
                x=[asset_positions[record["id"]][0] for record in records],
                y=[1.0] * len(records),
                mode="markers+text",
                text=[
                    _asset_node_text(
                        record,
                        style,
                        highlighted=record["id"] in highlight_ids,
                        total_count=len(assets),
                    )
                    for record in records
                ],
                textposition="top center",
                marker={
                    "size": [
                        (48 if style.kind == "red_team" else 42)
                        if record["id"] in highlight_ids
                        else (42 if style.kind == "red_team" else 36)
                        for record in records
                    ],
                    "color": style.color,
                    "symbol": style.symbol,
                    "opacity": [
                        1.0 if not highlight_ids or record["id"] in highlight_ids else 0.22
                        for record in records
                    ],
                    "line": {"color": "#ffffff", "width": 2},
                },
                customdata=[
                    [
                        _escaped(style.label),
                        _escaped(record.get("device_type")),
                        _escaped(", ".join(record.get("ip_addresses", []))),
                    ]
                    for record in records
                ],
                hovertemplate=(
                    "<b>%{text}</b><br>Ruolo: %{customdata[0]}"
                    "<br>Tipo: %{customdata[1]}<br>IP: %{customdata[2]}<extra></extra>"
                ),
                name=f"Asset · {style.label}",
            )
        )

    figure.add_trace(
        go.Scatter(
            x=[network_positions[record["id"]][0] for record in networks],
            y=[0.0] * len(networks),
            mode="markers+text",
            text=[html.escape(record["name"]) for record in networks],
            textposition="bottom center",
            marker={
                "size": 42,
                "color": "#9ef2df",
                "symbol": "diamond",
                "line": {"color": _PRIMARY_OT_COLOR, "width": 2},
            },
            hovertemplate="<b>%{text}</b><br>Port group VMware osservato<extra></extra>",
            name="Rete",
        )
    )
    for y, label in (
        (3.13, "HOST OT / EDR"),
        (2.38, "VMWARE"),
        (1.38, "CYBER VISION"),
        (0.38, "RETI"),
    ):
        figure.add_annotation(
            xref="paper",
            x=0,
            y=y,
            text=label,
            showarrow=False,
            font={"size": 10, "color": "#6f7976"},
            xanchor="left",
        )
    figure.update_yaxes(range=[-0.35, 3.28])
    return figure
