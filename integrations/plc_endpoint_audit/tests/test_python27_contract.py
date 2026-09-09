from __future__ import annotations

import ast
import json
import re
import sys
import tempfile
import threading
import types
import unittest
from pathlib import Path
from unittest import mock

from dtlab_plc_audit import audit_hook
from dtlab_plc_audit.runtime import load_config


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
RUNTIME_ROOT = PACKAGE_ROOT / "dtlab_plc_audit"
ENCODING_COOKIE = re.compile(br"coding[:=][ \t]*utf-8", re.IGNORECASE)


class Python27ContractTests(unittest.TestCase):
    def test_runtime_sources_have_explicit_utf8_cookie(self) -> None:
        for path in sorted(RUNTIME_ROOT.glob("*.py")):
            source = path.read_bytes()
            first_two_lines = b"\n".join(source.splitlines()[:2])
            self.assertRegex(
                first_two_lines,
                ENCODING_COOKIE,
                "%s deve dichiarare UTF-8 nelle prime due righe per Python 2.7"
                % path.name,
            )
            source.decode("utf-8")

    def test_runtime_sources_avoid_python3_only_ast_constructs(self) -> None:
        forbidden_nodes = tuple(
            node
            for node in (
                getattr(ast, "AnnAssign", None),
                getattr(ast, "AsyncFor", None),
                getattr(ast, "AsyncFunctionDef", None),
                getattr(ast, "AsyncWith", None),
                getattr(ast, "JoinedStr", None),
                getattr(ast, "NamedExpr", None),
                getattr(ast, "Nonlocal", None),
                getattr(ast, "YieldFrom", None),
            )
            if node is not None
        )
        for path in sorted(RUNTIME_ROOT.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                self.assertNotIsInstance(node, forbidden_nodes, path.name)
                if isinstance(node, (ast.FunctionDef, ast.Lambda)):
                    self.assertFalse(node.args.kwonlyargs, path.name)
                    self.assertFalse(getattr(node.args, "posonlyargs", []), path.name)
                    self.assertIsNone(getattr(node, "returns", None), path.name)
                if isinstance(node, ast.arg):
                    self.assertIsNone(node.annotation, path.name)

    def test_installer_registers_and_preflights_python2_import_path(self) -> None:
        installer = (PACKAGE_ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn("dtlab_plc_endpoint_audit.pth", installer)
        self.assertIn("get_python_lib", installer)
        self.assertIn('PYTHONPATH="${install_root}"', installer)
        self.assertIn('"${python2_bin}" -m py_compile', installer)
        self.assertIn('pymodbus.__version__ == "2.5.3"', installer)
        self.assertIn('env -u PYTHONPATH "${python2_bin}"', installer)

    def test_config_rejects_sender_keys_or_delivery_mode_missing(self) -> None:
        config = json.loads((PACKAGE_ROOT / "config.example.json").read_text())
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.json"

            missing_cursor = dict(config)
            del missing_cursor["sender_cursor_path"]
            path.write_text(json.dumps(missing_cursor), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_config(str(path))

            both_delivery_modes = dict(config)
            both_delivery_modes["outbox_directory"] = "/tmp/dtlab-outbox"
            path.write_text(json.dumps(both_delivery_modes), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_config(str(path))

            no_delivery_mode = dict(config)
            no_delivery_mode["endpoint_url"] = None
            path.write_text(json.dumps(no_delivery_mode), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_config(str(path))

    def test_lab_config_matches_registered_receiver_identity(self) -> None:
        config = json.loads((PACKAGE_ROOT / "config.example.json").read_text())

        self.assertEqual(config["sensor_id"], "plc-endpoint-sensor")
        self.assertEqual(config["destination_ip"], "172.16.10.10")
        self.assertEqual(
            config["destination_asset_id"],
            "asset:cybervision:dtlab-01:f8ea1750-43e9-4f1f-b1ce-5fc72cb31323",
        )
        self.assertEqual(
            config["endpoint_url"],
            "https://modbus.sitoclone.it/api/host-ot/v1/events",
        )

    def test_main_thread_detection_matches_twisted_requirement(self) -> None:
        self.assertTrue(audit_hook._is_main_thread())
        observed: list[bool] = []
        worker = threading.Thread(target=lambda: observed.append(audit_hook._is_main_thread()))
        worker.start()
        worker.join()
        self.assertEqual(observed, [False])

    def test_server_passes_main_thread_decision_to_reactor(self) -> None:
        class FakeDefaults:
            Port = 502

        class FakeDecoder:
            def register(self, _function) -> None:
                pass

        class FakeFactory:
            def __init__(self, _context, _framer, _identity, **_kwargs) -> None:
                self.decoder = FakeDecoder()

        class FakeRuntime:
            def flush_expired(self) -> None:
                pass

            def flush_all(self) -> None:
                pass

        class FakeLoopingCall:
            def __init__(self, callback) -> None:
                self.callback = callback

            def start(self, _interval, now=False) -> None:
                self.now = now

        class FakeReactor:
            def __init__(self) -> None:
                self.run_kwargs = None

            def addSystemEventTrigger(self, *_args) -> None:
                pass

            def listenTCP(self, *_args, **_kwargs) -> None:
                pass

            def run(self, **kwargs) -> None:
                self.run_kwargs = kwargs

        reactor = FakeReactor()
        twisted_module = types.ModuleType("twisted")
        internet_module = types.ModuleType("twisted.internet")
        task_module = types.ModuleType("twisted.internet.task")
        internet_module.reactor = reactor
        task_module.LoopingCall = FakeLoopingCall
        twisted_module.internet = internet_module

        modules = {
            "twisted": twisted_module,
            "twisted.internet": internet_module,
            "twisted.internet.task": task_module,
        }
        with mock.patch.dict(sys.modules, modules):
            with mock.patch.object(audit_hook, "Defaults", FakeDefaults):
                with mock.patch.object(audit_hook, "ModbusServerFactory", FakeFactory):
                    with mock.patch.object(audit_hook, "ModbusSocketFramer", object()):
                        with mock.patch.object(
                            audit_hook,
                            "runtime_from_file",
                            return_value=FakeRuntime(),
                        ):
                            audit_hook.StartAuditedTcpServer(
                                object(),
                                "/tmp/audit.json",
                                address=("127.0.0.1", 1502),
                            )

                            main_thread_kwargs = reactor.run_kwargs
                            reactor.run_kwargs = None
                            worker = threading.Thread(
                                target=lambda: audit_hook.StartAuditedTcpServer(
                                    object(),
                                    "/tmp/audit.json",
                                    address=("127.0.0.1", 1502),
                                )
                            )
                            worker.start()
                            worker.join()
                            worker_thread_kwargs = reactor.run_kwargs

        self.assertEqual(main_thread_kwargs, {"installSignalHandlers": True})
        self.assertEqual(worker_thread_kwargs, {"installSignalHandlers": False})


if __name__ == "__main__":
    unittest.main()
