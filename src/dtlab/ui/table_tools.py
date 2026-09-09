"""Reusable, truthful filtering and export controls for technical tables."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any, Protocol

import pandas as pd


class _Column(Protocol):
    def __enter__(self) -> object: ...

    def __exit__(self, *args: object) -> object: ...


class TableUI(Protocol):
    def columns(self, specification: Sequence[float] | int) -> Sequence[_Column]: ...

    def text_input(self, label: str, **kwargs: Any) -> str: ...

    def multiselect(self, label: str, options: Sequence[str], **kwargs: Any) -> list[str]: ...

    def caption(self, body: str, **kwargs: Any) -> object: ...

    def dataframe(self, data: Any, **kwargs: Any) -> object: ...

    def download_button(self, label: str, **kwargs: Any) -> object: ...


def _search_text(value: object) -> str:
    if isinstance(value, Mapping):
        return " ".join(
            f"{_search_text(key)} {_search_text(item)}" for key, item in value.items()
        )
    if isinstance(value, (list, tuple, set, frozenset)):
        return " ".join(_search_text(item) for item in value)
    return "" if value is None else str(value)


def filter_table_rows(
    rows: Sequence[Mapping[str, Any]],
    *,
    query: str = "",
    categorical_filters: Mapping[str, Sequence[str]] | None = None,
    search_columns: Sequence[str] | None = None,
) -> list[dict[str, Any]]:
    """Return only rows matching the free-text query and explicit column filters."""

    normalized_query = query.strip().casefold()
    filters = {
        column: {str(value) for value in selected}
        for column, selected in (categorical_filters or {}).items()
        if selected
    }
    filtered: list[dict[str, Any]] = []
    for source_row in rows:
        row = dict(source_row)
        searchable_values = (
            (row.get(column) for column in search_columns)
            if search_columns is not None
            else row.values()
        )
        if normalized_query and normalized_query not in " ".join(
            _search_text(value) for value in searchable_values
        ).casefold():
            continue
        if any(str(row.get(column)) not in selected for column, selected in filters.items()):
            continue
        filtered.append(row)
    return filtered


def table_json_bytes(rows: Sequence[Mapping[str, Any]]) -> bytes:
    """Serialize the exact filtered rows as deterministic UTF-8 JSON."""

    return (
        json.dumps(
            [dict(row) for row in rows],
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            default=str,
        )
        + "\n"
    ).encode("utf-8")


def table_csv_bytes(
    rows: Sequence[Mapping[str, Any]],
    *,
    columns: Sequence[str] | None = None,
) -> bytes:
    """Serialize the exact filtered rows as an Excel-friendly UTF-8 CSV."""

    frame = pd.DataFrame([dict(row) for row in rows], columns=columns)
    return frame.to_csv(index=False).encode("utf-8-sig")


def render_filterable_table(
    ui: TableUI,
    rows: Sequence[Mapping[str, Any]],
    *,
    key: str,
    filename_stem: str,
    filter_columns: Sequence[str] = (),
    search_columns: Sequence[str] | None = None,
    search_placeholder: str = "Cerca in tutti i campi…",
    hidden_columns: Sequence[str] = (),
    height: int | None = None,
) -> list[dict[str, Any]]:
    """Render table controls and downloads, returning the exact visible subset."""

    normalized_rows = [dict(row) for row in rows]
    columns = list(
        dict.fromkeys(column for row in normalized_rows for column in row)
    )
    control_columns = ui.columns([1.5, *([1.0] * len(filter_columns))])
    with control_columns[0]:
        query = ui.text_input(
            "Cerca",
            placeholder=search_placeholder,
            key=f"{key}-search",
        )
    selected_filters: dict[str, list[str]] = {}
    for control, column in zip(control_columns[1:], filter_columns, strict=True):
        options = sorted(
            {str(row.get(column)) for row in normalized_rows},
            key=str.casefold,
        )
        with control:
            selected_filters[column] = ui.multiselect(
                column,
                options,
                key=f"{key}-filter-{column}",
            )
    filtered = filter_table_rows(
        normalized_rows,
        query=query,
        categorical_filters=selected_filters,
        search_columns=search_columns,
    )
    ui.caption(
        f"{len(filtered)} record filtrati su {len(normalized_rows)}. "
        "Seleziona righe nella tabella per limitarne il download."
    )
    display_frame = pd.DataFrame(filtered, columns=columns).drop(
        columns=list(hidden_columns),
        errors="ignore",
    )
    dataframe_options: dict[str, Any] = {
        "use_container_width": True,
        "hide_index": True,
    }
    if height is not None:
        dataframe_options["height"] = height
    table_state = ui.dataframe(
        display_frame,
        key=f"{key}-dataframe",
        on_select="rerun",
        selection_mode="multi-row",
        **dataframe_options,
    )
    try:
        selected_indexes = list(table_state.selection.rows)
    except (AttributeError, TypeError):
        selected_indexes = []
    selected_rows = [
        filtered[index]
        for index in selected_indexes
        if isinstance(index, int) and 0 <= index < len(filtered)
    ]
    export_rows = selected_rows or filtered
    if selected_rows:
        ui.caption(f"Download limitato alle {len(selected_rows)} righe selezionate.")

    download_columns = ui.columns(2)
    with download_columns[0]:
        ui.download_button(
            "Scarica selezione · JSON",
            data=table_json_bytes(export_rows),
            file_name=f"{filename_stem}.json",
            mime="application/json",
            icon=":material/download:",
            use_container_width=True,
            key=f"{key}-download-json",
        )
    with download_columns[1]:
        ui.download_button(
            "Scarica selezione · CSV",
            data=table_csv_bytes(export_rows, columns=columns),
            file_name=f"{filename_stem}.csv",
            mime="text/csv",
            icon=":material/download:",
            use_container_width=True,
            key=f"{key}-download-csv",
        )
    return filtered
