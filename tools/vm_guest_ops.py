"""Run audited commands inside one ESXi guest through VMware Tools.

The utility is intentionally interactive: host and guest passwords are read with
``getpass`` and are never accepted as command-line options or written to disk.
It is useful when the OT guest network is not routed to the operator workstation.
"""

from __future__ import annotations

import argparse
import atexit
import getpass
import shlex
import ssl
import sys
import time
import uuid
from contextlib import suppress
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, urlopen

from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, help="ESXi/vCenter host")
    parser.add_argument("--host-user", required=True)
    parser.add_argument("--vm", required=True, help="Exact VM name")
    parser.add_argument("--guest-user", required=True)
    subparsers = parser.add_subparsers(dest="action", required=True)
    subparsers.add_parser("list")
    subparsers.add_parser("inspect")
    run = subparsers.add_parser("run")
    run.add_argument("command")
    run.add_argument("--timeout", type=int, default=120)
    upload = subparsers.add_parser("upload")
    upload.add_argument("local_path", type=Path)
    upload.add_argument("guest_path")
    return parser


def _find_vm(content: object, name: str) -> vim.VirtualMachine:
    view = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
    try:
        matches = [vm for vm in view.view if vm.name == name]
    finally:
        view.Destroy()
    if len(matches) != 1:
        raise RuntimeError(f"Expected one VM named {name!r}; found {len(matches)}")
    return matches[0]


def _list_vms(content: object) -> list[vim.VirtualMachine]:
    view = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
    try:
        return sorted(view.view, key=lambda vm: vm.name.casefold())
    finally:
        view.Destroy()


def _normalized_transfer_url(url: str, host: str) -> str:
    parsed = urlsplit(url)
    netloc = parsed.netloc.replace("*", host)
    return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))


def _open(request: Request, *, timeout: int = 60) -> bytes:
    context = ssl._create_unverified_context()  # ESXi lab uses a private certificate.
    with urlopen(request, timeout=timeout, context=context) as response:
        return response.read()


def _download(content: object, vm: vim.VirtualMachine, auth: object, path: str, host: str) -> bytes:
    transfer = content.guestOperationsManager.fileManager.InitiateFileTransferFromGuest(
        vm, auth, path
    )
    url = _normalized_transfer_url(transfer.url, host)
    return _open(Request(url, method="GET"))


def _upload(
    content: object,
    vm: vim.VirtualMachine,
    auth: object,
    local_path: Path,
    guest_path: str,
    host: str,
) -> None:
    payload = local_path.resolve().read_bytes()
    url = content.guestOperationsManager.fileManager.InitiateFileTransferToGuest(
        vm,
        auth,
        guest_path,
        vim.vm.guest.FileManager.FileAttributes(),
        len(payload),
        True,
    )
    url = _normalized_transfer_url(url, host)
    request = Request(
        url,
        data=payload,
        method="PUT",
        headers={"Content-Type": "application/octet-stream"},
    )
    _open(request)


def _run(
    content: object,
    vm: vim.VirtualMachine,
    auth: object,
    command: str,
    host: str,
    timeout: int,
) -> tuple[int, str]:
    output_path = f"/tmp/dtlab-guest-output-{uuid.uuid4().hex}.log"
    wrapped = f"{command} >{shlex.quote(output_path)} 2>&1"
    spec = vim.vm.guest.ProcessManager.ProgramSpec(
        programPath="/bin/bash",
        arguments=f"-lc {shlex.quote(wrapped)}",
    )
    manager = content.guestOperationsManager.processManager
    pid = manager.StartProgramInGuest(vm, auth, spec)
    deadline = time.monotonic() + timeout
    exit_code: int | None = None
    while time.monotonic() < deadline:
        processes = manager.ListProcessesInGuest(vm, auth, [pid])
        if processes and processes[0].endTime is not None:
            exit_code = int(processes[0].exitCode)
            break
        time.sleep(0.5)
    if exit_code is None:
        raise TimeoutError(f"Guest process {pid} exceeded {timeout}s")
    try:
        output = _download(content, vm, auth, output_path, host).decode("utf-8", errors="replace")
    finally:
        with suppress(vim.fault.FileNotFound):
            content.guestOperationsManager.fileManager.DeleteFileInGuest(vm, auth, output_path)
    return exit_code, output


def main() -> int:
    args = _parser().parse_args()
    host_password = getpass.getpass("ESXi password: ")
    service_instance = SmartConnect(
        host=args.host,
        user=args.host_user,
        pwd=host_password,
        disableSslCertValidation=True,
    )
    atexit.register(Disconnect, service_instance)
    content = service_instance.RetrieveContent()
    if args.action == "list":
        for candidate in _list_vms(content):
            print(
                f"{candidate.name}\tpower={candidate.runtime.powerState}\t"
                f"tools={candidate.guest.toolsRunningStatus}\t"
                f"ip={candidate.guest.ipAddress or 'N/D'}"
            )
        return 0
    vm = _find_vm(content, args.vm)
    guest = vm.guest
    print(
        f"vm={vm.name} power={vm.runtime.powerState} "
        f"tools={guest.toolsRunningStatus} ip={guest.ipAddress or 'N/D'}"
    )
    if vm.runtime.powerState != vim.VirtualMachinePowerState.poweredOn:
        raise RuntimeError("VM is not powered on; refusing to change power state")
    if guest.toolsRunningStatus != "guestToolsRunning":
        raise RuntimeError("VMware Tools is not running in the guest")
    guest_password = getpass.getpass("Guest password: ")
    auth = vim.vm.guest.NamePasswordAuthentication(
        username=args.guest_user,
        password=guest_password,
        interactiveSession=False,
    )
    if args.action == "inspect":
        code, output = _run(
            content,
            vm,
            auth,
            "hostname; id; pwd; "
            "systemctl is-active dtlab-dashboard.service dtlab-collector.timer "
            "dtlab-host-ot-ingress.service nginx 2>&1 || true",
            args.host,
            30,
        )
        print(output, end="")
        return code
    if args.action == "run":
        code, output = _run(content, vm, auth, args.command, args.host, args.timeout)
        print(output, end="")
        return code
    if args.action == "upload":
        _upload(
            content,
            vm,
            auth,
            args.local_path,
            args.guest_path,
            args.host,
        )
        print(f"uploaded={args.local_path.resolve()} guest_path={args.guest_path}")
        return 0
    raise AssertionError(args.action)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
