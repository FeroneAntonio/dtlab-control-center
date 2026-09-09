"""Run a company-provided BeerFactory scenario with a hard time bound.

The original laboratory scripts are preserved verbatim under ``lab/``. Several
contain an intentional infinite loop. This launcher makes the normal operator path
bounded and rejects non-private targets, reducing accidental traffic and ticket
flooding outside the authorized lab.
"""

from __future__ import annotations

import argparse
import ipaddress
import subprocess
from collections.abc import Sequence
from pathlib import Path

SCENARIO_ROOT = (
    Path(__file__).resolve().parents[1]
    / "lab"
    / "beerfactory-company"
    / "scripts"
)
SCENARIOS = {
    "attack_move_fill": "attack_move_fill.py",
    "attack_move_fill2": "attack_move_fill2.py",
    "attack_shutdown": "attack_shutdown.py",
    "attack_shutdown2": "attack_shutdown2.py",
    "attack_stop_fill": "attack_stop_fill.py",
    "attack_stop_fill2": "attack_stop_fill2.py",
    "discovery": "discovery.py",
    "set_registry": "set_registry.py",
}


def _private_target(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("target IP non valido") from exc
    if not address.is_private:
        raise argparse.ArgumentTypeError(
            "il launcher accetta esclusivamente target IP privati di laboratorio"
        )
    return str(address)


def _duration(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("duration deve essere numerica") from exc
    if not 1 <= parsed <= 60:
        raise argparse.ArgumentTypeError("duration deve essere compresa tra 1 e 60 secondi")
    return parsed


def _register_value(value: str) -> int:
    try:
        parsed = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("valore intero non valido") from exc
    if not 0 <= parsed <= 0xFFFF:
        raise argparse.ArgumentTypeError("valore fuori dall'intervallo Modbus 0..65535")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Esegue uno scenario BeerFactory aziendale con arresto automatico."
    )
    parser.add_argument("scenario", choices=sorted(SCENARIOS))
    parser.add_argument("--target", required=True, type=_private_target)
    parser.add_argument("--duration", default=10.0, type=_duration)
    parser.add_argument("--interpreter", default="python2")
    parser.add_argument("--register", type=_register_value)
    parser.add_argument("--value", type=_register_value)
    parser.add_argument(
        "--authorized-lab",
        action="store_true",
        help="conferma che il target appartiene a un laboratorio autorizzato",
    )
    parser.add_argument("--dry-run", action="store_true")
    return parser


def build_command(args: argparse.Namespace) -> list[str]:
    script = SCENARIO_ROOT / SCENARIOS[args.scenario]
    if not script.is_file():
        raise FileNotFoundError(f"script aziendale assente: {script}")
    command = [args.interpreter, str(script), args.target]
    if args.scenario == "set_registry":
        if args.register is None or args.value is None:
            raise ValueError("set_registry richiede --register e --value")
        command.extend([str(args.register), str(args.value)])
    elif args.register is not None or args.value is not None:
        raise ValueError("--register e --value sono validi soltanto per set_registry")
    return command


def _stop(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if not args.authorized_lab:
        parser.error("specificare --authorized-lab per confermare lo scope autorizzato")
    try:
        command = build_command(args)
    except (FileNotFoundError, ValueError) as exc:
        parser.error(str(exc))
    if args.dry_run:
        print("Comando validato:", " ".join(command))
        return 0

    process = subprocess.Popen(command)
    try:
        return process.wait(timeout=args.duration)
    except subprocess.TimeoutExpired:
        _stop(process)
        print(f"Scenario terminato automaticamente dopo {args.duration:g} secondi.")
        return 0
    except KeyboardInterrupt:
        _stop(process)
        print("Scenario interrotto dall'operatore.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
