from __future__ import annotations

import csv
import io
import json
from types import SimpleNamespace
from typing import Any

from dtlab.ui.table_tools import (
    filter_table_rows,
    render_filterable_table,
    table_csv_bytes,
    table_json_bytes,
)


class _Context:
    def __enter__(self) -> _Context:
        return self

    def __exit__(self, *_args: object) -> None:
        return None


class _FakeUI:
    def __init__(self) -> None:
        self.frames: list[Any] = []
        self.downloads: list[dict[str, Any]] = []

    def columns(self, specification: int | list[float]) -> list[_Context]:
        count = specification if isinstance(specification, int) else len(specification)
        return [_Context() for _ in range(count)]

    def text_input(self, _label: str, **_kwargs: Any) -> str:
        return "plc"

    def multiselect(
        self,
        label: str,
        _options: list[str],
        **_kwargs: Any,
    ) -> list[str]:
        return ["high"] if label == "Severità" else []

    def caption(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def dataframe(self, data: Any, **_kwargs: Any) -> Any:
        self.frames.append(data)
        return SimpleNamespace(selection=SimpleNamespace(rows=[1]))

    def download_button(self, label: str, **kwargs: Any) -> None:
        self.downloads.append({"label": label, **kwargs})


def test_filter_table_rows_combines_search_and_explicit_filters() -> None:
    rows = [
        {
            "Asset": "PLC-Desktop",
            "Tipo": "PLC",
            "Indirizzi": ["172.16.10.10", "fe80::10"],
            "Dettagli": {"vendor": "Schneider"},
        },
        {
            "Asset": "HMI",
            "Tipo": "HMI",
            "Indirizzi": ["172.16.10.20"],
            "Dettagli": {"vendor": "Canonical"},
        },
    ]

    assert filter_table_rows(
        rows,
        query="schneider",
        categorical_filters={"Tipo": ["PLC"]},
    ) == [rows[0]]
    assert filter_table_rows(
        rows,
        query="172.16.10.20",
        categorical_filters={"Tipo": ["PLC"]},
    ) == []


def test_table_exports_contain_only_the_filtered_rows() -> None:
    rows = [
        {"Asset": "PLC-Desktop", "Score": 50, "Verità": "Reale"},
        {"Asset": "HMI", "Score": None, "Verità": "Non disponibile"},
    ]
    filtered = filter_table_rows(rows, query="plc")

    assert json.loads(table_json_bytes(filtered)) == [rows[0]]
    csv_rows = list(
        csv.DictReader(io.StringIO(table_csv_bytes(filtered).decode("utf-8-sig")))
    )
    assert csv_rows == [{"Asset": "PLC-Desktop", "Score": "50", "Verità": "Reale"}]


def test_empty_csv_keeps_the_declared_table_contract() -> None:
    content = table_csv_bytes([], columns=["Asset", "Score"]).decode("utf-8-sig")

    assert content == "Asset,Score\r\n"


def test_rendered_table_and_downloads_share_the_same_filtered_subset() -> None:
    ui = _FakeUI()
    rows = [
        {"ID": "asset:plc", "Asset": "PLC-Desktop", "Severità": "high"},
        {"ID": "asset:hmi", "Asset": "HMI", "Severità": "high"},
        {"ID": "asset:plc-legacy", "Asset": "PLC-Legacy", "Severità": "high"},
    ]

    filtered = render_filterable_table(
        ui,
        rows,
        key="test-table",
        filename_stem="test-table",
        filter_columns=("Severità",),
        hidden_columns=("ID",),
    )

    assert filtered == [rows[0], rows[2]]
    assert ui.frames[0].to_dict(orient="records") == [
        {"Asset": "PLC-Desktop", "Severità": "high"},
        {"Asset": "PLC-Legacy", "Severità": "high"},
    ]
    downloads = {item["mime"]: item["data"] for item in ui.downloads}
    assert json.loads(downloads["application/json"]) == [rows[2]]
    csv_rows = list(
        csv.DictReader(io.StringIO(downloads["text/csv"].decode("utf-8-sig")))
    )
    assert csv_rows == [
        {
            "ID": "asset:plc-legacy",
            "Asset": "PLC-Legacy",
            "Severità": "high",
        }
    ]
