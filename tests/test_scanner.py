import json
import socket
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from recon.cli import main, parse_ports
from recon.output import render_json
from recon.protocols import socket_probe, web_url
from recon.scanner import TargetError, expand_targets, scan


class TargetTests(unittest.TestCase):
    def test_expands_cidr_hosts(self):
        self.assertEqual(expand_targets(["192.0.2.0/30"]), ("192.0.2.1", "192.0.2.2"))

    def test_rejects_cidr_beyond_limit(self):
        with self.assertRaises(TargetError):
            expand_targets(["192.0.2.0/24"], max_hosts=10)

    def test_parses_ports_and_ranges(self):
        self.assertEqual(parse_ports("443,22,8000-8002"), (22, 443, 8000, 8001, 8002))

    def test_builds_web_urls(self):
        cases = {
            80: "http://lab.example",
            443: "https://lab.example",
            8080: "http://lab.example:8080",
            8443: "https://lab.example:8443",
        }
        for port, expected in cases.items():
            with self.subTest(port=port):
                self.assertEqual(web_url("lab.example", port), expected)

        self.assertIsNone(web_url("lab.example", 22))

    @patch("recon.cli.asyncio.run", side_effect=KeyboardInterrupt)
    def test_sigint_returns_shell_interrupt_code(self, run):
        self.assertEqual(main(["127.0.0.1"]), 130)
        run.assert_called_once()
        run.call_args.args[0].close()


class AsyncScannerTests(unittest.IsolatedAsyncioTestCase):
    async def test_async_engine_records_open_port(self):
        reader = MagicMock()
        reader.read = AsyncMock(return_value=b"SSH-2.0-test\r\n")
        writer = MagicMock()
        writer.drain = AsyncMock()
        writer.wait_closed = AsyncMock()

        with patch("recon.scanner.asyncio.open_connection", new=AsyncMock(return_value=(reader, writer))):
            report = await scan(["192.0.2.1"], ports=(22,), timeout=0.1, banner_timeout=0.1)

        finding = report.hosts[0].open_ports[0]
        self.assertEqual(finding.port, 22)
        self.assertEqual(finding.service, "SSH")
        self.assertEqual(finding.banner, "SSH-2.0-test")
        writer.close.assert_called_once()

    async def test_json_output_is_structured(self):
        with patch("recon.scanner.asyncio.open_connection", new=AsyncMock(side_effect=ConnectionRefusedError)):
            report = await scan(["192.0.2.1"], ports=(22,))
        data = json.loads(render_json(report))
        self.assertEqual(data["engine"], "async")
        self.assertEqual(data["hosts"][0]["target"], "192.0.2.1")
        self.assertEqual(data["hosts"][0]["open_ports"], [])


class SocketEngineTests(unittest.TestCase):
    @patch("recon.protocols.socket.socket")
    def test_socket_engine_calls_connect(self, socket_factory):
        sock = socket_factory.return_value.__enter__.return_value
        sock.recv.return_value = b"SSH-2.0-test\r\n"
        latency, banner = socket_probe("192.0.2.1", "lab.example", 22, 0.1, 0.1)
        socket_factory.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect.assert_called_once_with(("192.0.2.1", 22))
        self.assertGreaterEqual(latency, 0)
        self.assertEqual(banner, "SSH-2.0-test")


if __name__ == "__main__":
    unittest.main()
