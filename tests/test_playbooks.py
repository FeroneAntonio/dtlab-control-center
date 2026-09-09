from __future__ import annotations

from dtlab.services.playbooks import tasks_for_signal


def test_every_supported_signal_has_manual_first_playbook() -> None:
    for signal_type in (
        "host_modbus_write",
        "event",
        "finding",
        "baseline_difference",
        "vulnerability",
        "new_ui_alert",
        "new_ui_vulnerability",
    ):
        tasks = tasks_for_signal(signal_type)
        assert len(tasks) == 4
        assert "evidenze" in tasks[-1].title.lower()


def test_new_ui_playbooks_keep_classic_and_source_scores_separate() -> None:
    alert_tasks = tasks_for_signal("new_ui_alert")
    vulnerability_tasks = tasks_for_signal("new_ui_vulnerability")

    assert any("non collegare" in task.description.lower() for task in alert_tasks)
    assert any("risk score classic" in task.description.lower() for task in vulnerability_tasks)


def test_unknown_signal_gets_safe_documentation_task() -> None:
    tasks = tasks_for_signal("future-signal")
    assert len(tasks) == 1
    assert "chiusura" in tasks[0].description.lower()
