"""Read-only VMware ESXi inventory collector with certificate pinning."""

from __future__ import annotations

import hashlib
import hmac
import socket
import ssl
from datetime import UTC, datetime
from typing import Any

from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim

from dtlab.collector.config import EsxiConfig
from dtlab.collector.credentials import load_esxi_password


class EsxiCollectionError(RuntimeError):
    """ESXi collection failed before a trustworthy inventory was produced."""


def certificate_sha256(host: str, port: int, *, timeout: float = 10) -> str:
    context = ssl._create_unverified_context()
    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as raw,
            context.wrap_socket(raw, server_hostname=host) as wrapped,
        ):
            certificate = wrapped.getpeercert(binary_form=True)
    except OSError as exc:
        raise EsxiCollectionError("Connessione TLS ESXi non riuscita.") from exc
    return hashlib.sha256(certificate).hexdigest()


def _snapshot_names(nodes: Any) -> list[str]:
    names: list[str] = []
    for node in nodes or []:
        names.append(str(node.name))
        names.extend(_snapshot_names(node.childSnapshotList))
    return names


def _serialize_vm(vm: Any) -> dict[str, Any]:
    config = vm.config
    guest = vm.guest
    summary = vm.summary
    interfaces: list[dict[str, Any]] = []
    disks: list[dict[str, Any]] = []
    for device in config.hardware.device:
        if isinstance(device, vim.vm.device.VirtualEthernetCard):
            backing = getattr(device, "backing", None)
            interfaces.append(
                {
                    "label": device.deviceInfo.label,
                    "mac_address": device.macAddress,
                    "connected": bool(device.connectable.connected),
                    "start_connected": bool(device.connectable.startConnected),
                    "network": getattr(backing, "deviceName", None),
                    "backing_type": type(backing).__name__ if backing else None,
                }
            )
        elif isinstance(device, vim.vm.device.VirtualDisk):
            disks.append(
                {
                    "label": device.deviceInfo.label,
                    "capacity_gb": round(device.capacityInKB / 1024 / 1024, 3),
                }
            )
    guest_networks = [
        {
            "network": network.network,
            "mac_address": network.macAddress,
            "ip_addresses": list(network.ipAddress or []),
        }
        for network in guest.net or []
    ]
    return {
        "name": vm.name,
        "moid": vm._moId,
        "power_state": str(summary.runtime.powerState),
        "guest_full_name": config.guestFullName,
        "guest_id": config.guestId,
        "tools_status": str(summary.guest.toolsStatus),
        "hostname": guest.hostName,
        "primary_ip": guest.ipAddress,
        "cpu": config.hardware.numCPU,
        "memory_mb": config.hardware.memoryMB,
        "networks": interfaces,
        "guest_networks": guest_networks,
        "disks": disks,
        "snapshots": _snapshot_names(vm.snapshot.rootSnapshotList) if vm.snapshot else [],
    }


def _inherited(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    return {"value": value.value, "inherited": value.inherited}


def _serialize_host(host: Any) -> dict[str, Any]:
    network = host.config.network
    return {
        "name": host.name,
        "vendor": host.hardware.systemInfo.vendor,
        "model": host.hardware.systemInfo.model,
        "product": host.config.product.fullName,
        "connection_state": str(host.runtime.connectionState),
        "maintenance_mode": host.runtime.inMaintenanceMode,
        "vswitches": [
            {
                "name": switch.name,
                "mtu": switch.mtu,
                "ports": switch.numPorts,
                "uplinks": list(switch.pnic or []),
            }
            for switch in network.vswitch
        ],
        "portgroups": [
            {
                "name": portgroup.spec.name,
                "vswitch": portgroup.spec.vswitchName,
                "vlan_id": portgroup.spec.vlanId,
                "promiscuous_mode": _inherited(
                    portgroup.spec.policy.security.allowPromiscuous
                ),
                "mac_changes": _inherited(portgroup.spec.policy.security.macChanges),
                "forged_transmits": _inherited(
                    portgroup.spec.policy.security.forgedTransmits
                ),
            }
            for portgroup in network.portgroup
        ],
    }


def collect_esxi_inventory(
    config: EsxiConfig,
    *,
    password_provider=load_esxi_password,
    now: datetime | None = None,
) -> dict[str, Any]:
    actual_fingerprint = certificate_sha256(config.host, config.port)
    if not hmac.compare_digest(actual_fingerprint, config.tls_sha256):
        raise EsxiCollectionError("Fingerprint TLS ESXi diverso da quello autorizzato.")
    try:
        password = password_provider(config.username)
    except Exception as exc:
        raise EsxiCollectionError("Credenziale ESXi non disponibile nel vault.") from exc

    ssl_context = ssl._create_unverified_context()
    thumbprint = ":".join(
        config.tls_sha256[index : index + 2]
        for index in range(0, len(config.tls_sha256), 2)
    )
    try:
        service_instance = SmartConnect(
            host=config.host,
            user=config.username,
            pwd=password,
            port=config.port,
            sslContext=ssl_context,
            thumbprint=thumbprint,
            connectionPoolTimeout=60,
        )
    except Exception as exc:
        raise EsxiCollectionError("Autenticazione o connessione ESXi non riuscita.") from exc
    finally:
        password = ""

    try:
        content = service_instance.RetrieveContent()
        vm_view = content.viewManager.CreateContainerView(
            content.rootFolder,
            [vim.VirtualMachine],
            True,
        )
        try:
            virtual_machines = [_serialize_vm(vm) for vm in vm_view.view]
        finally:
            vm_view.Destroy()

        host_view = content.viewManager.CreateContainerView(
            content.rootFolder,
            [vim.HostSystem],
            True,
        )
        try:
            hosts = [_serialize_host(host) for host in host_view.view]
        except Exception:
            hosts = []
        finally:
            host_view.Destroy()
    except Exception as exc:
        raise EsxiCollectionError("Lettura inventario ESXi non riuscita.") from exc
    finally:
        Disconnect(service_instance)

    collected_at = now or datetime.now(UTC)
    if collected_at.tzinfo is None:
        raise EsxiCollectionError("now deve includere il fuso orario.")
    return {
        "collected_at": collected_at.astimezone(UTC).isoformat(),
        "esxi_host": config.host,
        "certificate_sha256": actual_fingerprint,
        "vm_count": len(virtual_machines),
        "virtual_machines": sorted(
            virtual_machines,
            key=lambda item: item["name"].lower(),
        ),
        "hosts": hosts,
    }
