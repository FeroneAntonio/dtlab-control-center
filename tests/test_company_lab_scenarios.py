from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from tools import run_company_lab_scenario as launcher

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_NAMES = {
    "attack_move_fill.py",
    "attack_move_fill2.py",
    "attack_shutdown.py",
    "attack_shutdown2.py",
    "attack_stop_fill.py",
    "attack_stop_fill2.py",
    "discovery.py",
    "set_registry.py",
}


def test_company_script_snapshot_is_complete_and_covered_by_detection() -> None:
    scripts = {
        path.name
        for path in (ROOT / "lab" / "beerfactory-company" / "scripts").glob("*.py")
    }
    rules = (ROOT / "config" / "cybervision-dtlab-modbus.rules").read_text(
        encoding="utf-8"
    )

    assert scripts == SCRIPT_NAMES
    assert set(launcher.SCENARIOS.values()) == SCRIPT_NAMES
    for name in SCRIPT_NAMES:
        assert name in rules


def test_launcher_accepts_only_private_targets() -> None:
    assert launcher._private_target("10.10.10.10") == "10.10.10.10"
    assert launcher._private_target("172.16.10.10") == "172.16.10.10"
    with pytest.raises(argparse.ArgumentTypeError, match="privati"):
        launcher._private_target("8.8.8.8")


def test_launcher_builds_bounded_scenarios_and_validates_registry_arguments() -> None:
    args = argparse.Namespace(
        scenario="attack_shutdown",
        target="172.16.10.10",
        interpreter="python2",
        register=None,
        value=None,
    )
    command = launcher.build_command(args)
    assert command[0] == "python2"
    assert command[-1] == "172.16.10.10"
    assert command[-2].endswith("attack_shutdown.py")

    args.scenario = "set_registry"
    with pytest.raises(ValueError, match="richiede"):
        launcher.build_command(args)
    args.register = 3
    args.value = 0
    assert launcher.build_command(args)[-2:] == ["3", "0"]


@pytest.mark.parametrize("value", ["1", "10", "60", "60.0"])
def test_duration_is_bounded(value: str) -> None:
    assert 1 <= launcher._duration(value) <= 60


@pytest.mark.parametrize("value", ["0.9", "61", "not-a-number"])
def test_duration_rejects_unsafe_values(value: str) -> None:
    with pytest.raises(argparse.ArgumentTypeError):
        launcher._duration(value)
