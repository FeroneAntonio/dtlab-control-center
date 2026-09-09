# -*- coding: utf-8 -*-
"""Audited Twisted/Pymodbus 2.5.3 TCP server hook for the BeerFactory PLC."""

from __future__ import absolute_import

import logging
import threading

from dtlab_plc_audit.runtime import runtime_from_file


_LOGGER = logging.getLogger(__name__)


def _is_main_thread():
    """Match Pymodbus 2.5.3 signal-handler behavior on Python 2 and 3."""

    main_thread = getattr(threading, "main_thread", None)
    if main_thread is not None:
        return threading.current_thread() == main_thread()
    return isinstance(threading.current_thread(), threading._MainThread)

try:
    from pymodbus.constants import Defaults
    from pymodbus.device import ModbusDeviceIdentification
    from pymodbus.exceptions import NoSuchSlaveException
    from pymodbus.pdu import ModbusExceptions as merror
    from pymodbus.server.asynchronous import ModbusServerFactory, ModbusTcpProtocol
    from pymodbus.transaction import ModbusSocketFramer
except ImportError:
    Defaults = None
    ModbusDeviceIdentification = None
    NoSuchSlaveException = None
    merror = None
    ModbusServerFactory = None
    ModbusTcpProtocol = object
    ModbusSocketFramer = None


class AuditedModbusTcpProtocol(ModbusTcpProtocol):
    """Pymodbus protocol that records write requests after server execution."""

    def _peer(self):
        try:
            return self.transport.getPeer()
        except Exception:
            return None

    def _local(self):
        try:
            return self.transport.getHost()
        except Exception:
            return None

    def _audit(self, request, response, outcome_state):
        try:
            self.factory.audit_runtime.observe(
                request,
                response,
                self._peer(),
                self._local(),
                outcome_state=outcome_state,
            )
        except Exception as exc:
            self.factory.audit_runtime.report_failure("event_emit_failed", exc)

    def _execute(self, request):
        """Mirror Pymodbus 2.5.3 execution and add passive post-execution audit."""

        outcome_state = "processed"
        try:
            context = self.factory.store[request.unit_id]
            response = request.execute(context)
            try:
                if response.isError():
                    outcome_state = "rejected"
            except (AttributeError, TypeError):
                pass
        except NoSuchSlaveException:
            outcome_state = "rejected"
            if self.factory.ignore_missing_slaves:
                self._audit(request, None, outcome_state)
                return
            response = request.doException(merror.GatewayNoResponse)
        except Exception:
            outcome_state = "rejected"
            _LOGGER.exception("Datastore unable to fulfill audited Modbus request")
            response = request.doException(merror.SlaveFailure)

        response.transaction_id = request.transaction_id
        response.unit_id = request.unit_id
        self._audit(request, response, outcome_state)
        self._send(response)

    def connectionLost(self, reason):
        peer = self._peer()
        try:
            if peer is not None:
                self.factory.audit_runtime.flush_peer(peer)
        except Exception as exc:
            self.factory.audit_runtime.report_failure("peer_flush_failed", exc)
        return ModbusTcpProtocol.connectionLost(self, reason)


def StartAuditedTcpServer(
    context,
    audit_config,
    identity=None,
    address=None,
    console=False,
    defer_reactor_run=False,
    custom_functions=None,
    **kwargs
):
    """Start a Pymodbus 2.5.3 server with an isolated endpoint audit runtime.

    This intentionally resembles Pymodbus 2.5.3 ``StartTcpServer`` and does not
    monkey-patch the installed package.  Monitoring failures are logged and made
    visible through ``health_path`` but never alter the Modbus response.
    """

    if ModbusServerFactory is None:
        raise RuntimeError("Pymodbus 2.5.3 e Twisted non sono disponibili.")
    from twisted.internet import reactor
    from twisted.internet.task import LoopingCall

    custom_functions = custom_functions or []
    address = address or ("", Defaults.Port)
    framer = kwargs.pop("framer", ModbusSocketFramer)
    audit_runtime = runtime_from_file(audit_config)
    factory = ModbusServerFactory(context, framer, identity, **kwargs)
    factory.protocol = AuditedModbusTcpProtocol
    factory.audit_runtime = audit_runtime
    for custom_function in custom_functions:
        factory.decoder.register(custom_function)

    flush_loop = LoopingCall(audit_runtime.flush_expired)
    flush_loop.start(1.0, now=False)
    reactor.addSystemEventTrigger("before", "shutdown", audit_runtime.flush_all)
    _LOGGER.info("Starting audited Modbus TCP server on %s:%s", address[0], address[1])
    reactor.listenTCP(address[1], factory, interface=address[0])
    if not defer_reactor_run:
        reactor.run(installSignalHandlers=_is_main_thread())
    return factory


__all__ = ["AuditedModbusTcpProtocol", "StartAuditedTcpServer"]
