import errno
import json
import unittest
from unittest.mock import patch
from recon.output import render_json
from recon.scanner import scan


class TcpAttemptTests(unittest.IsolatedAsyncioTestCase):
    async def test_both_engines_distinguish_connection_outcomes(self):
        def simulate_probe(port, on_connected):
            if port == 22:
                raise ConnectionRefusedError("connection refused")
            if port == 80:
                raise TimeoutError("connection timed out")
            if port == 443:
                raise OSError(errno.ENETUNREACH, "network unreachable")

            on_connected(1.25)
            raise ConnectionResetError("peer reset during banner exchange")

        async def async_probe(
            target, address, port, timeout, banner_timeout, *, on_connected):
            return simulate_probe(port, on_connected)

        def socket_probe(
            address, target, port, timeout, banner_timeout, *, on_connected):
            return simulate_probe(port, on_connected)

        for engine in ("async", "socket"):
            with self.subTest(engine=engine):
                with (
                    patch("recon.scanner._async_probe", side_effect=async_probe),
                    patch("recon.scanner.socket_probe", side_effect=socket_probe),):
                    report = await scan(
                        ["127.0.0.1"], ports=(22, 80, 443, 8443), engine=engine,)

                host = report.hosts[0]
                self.assertEqual(
                    [(attempt.port, attempt.outcome) for attempt in host.tcp_attempts],
                    [(22, "refused"), (80, "timeout"), (443, "error"), (8443, "open")],)
                self.assertEqual([finding.port for finding in host.open_ports], [8443])
                self.assertEqual(host.open_ports[0].latency_ms, 1.25)
                self.assertIsNone(host.open_ports[0].banner)
                saved_host = json.loads(render_json(report))["hosts"][0]
                self.assertEqual(saved_host["tcp_attempts"][-1]["outcome"], "open")