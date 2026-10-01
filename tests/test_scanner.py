import json
import socket
import unittest
from unittest.mock import AsyncMock, MagicMock, call, patch

from recon.cli import main, parse_ports
from recon.output import render_json, render_table, render_text
from recon.protocols import socket_probe, web_url
from recon.scanner import TargetError, expand_targets, scan
from recon.web import WebFinding, assess_security_headers, inspect_url

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

    async def test_http_inspection_reaches_scan_and_renderers(self):
        reader = MagicMock()
        reader.read = AsyncMock(return_value=b"HTTP/1.0 200 OK\r\n\r\n")
        writer = MagicMock()
        writer.drain = AsyncMock()
        writer.wait_closed = AsyncMock()
        web = WebFinding(
            status=200,
            final_url="http://192.0.2.1:8080/",
            title="Lab Dashboard",
            server="nginx",
            content_type="text/html",
            powered_by=None,
            response_size=512,
            response_time_ms=25.0,
            redirects=0,
        )

        with (
            patch(
                "recon.scanner.asyncio.open_connection",
                new=AsyncMock(return_value=(reader, writer)),
            ),
            patch("recon.scanner.inspect_url", return_value=web) as inspect,
        ):
            report = await scan(
                ["192.0.2.1"],
                ports=(8080,),
                inspect_http=True,
            )

        finding = report.hosts[0].open_ports[0]
        self.assertEqual(finding.web, web)
        inspect.assert_called_once_with("http://192.0.2.1:8080", 5.0)
        self.assertIn("http: 200 | title: Lab Dashboard", render_text(report))
        self.assertIn("HTTP", render_table(report))
        self.assertIn("200", render_table(report))

class WebInspectionTests(unittest.TestCase):
    @patch("recon.web.requests.get")
    def test_inspect_url_returns_structured_evidence(self, get):
        response = MagicMock()
        response.status_code = 200
        response.url = "https://lab.example/dashboard"
        response.text = "<html><title>Lab Dashboard</title></html>"
        response.content = response.text.encode()
        response.headers = {
            "Server": "nginx",
            "Content-Type": "text/html",
            "X-Powered-By": "PHP",
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
        }
        response.elapsed.total_seconds.return_value = 0.125
        response.history = [MagicMock()]
        robots = MagicMock()
        robots.status_code = 200
        robots.text = "User-agent: *\nDisallow: /admin\nDisallow: /backups # private\n"
        get.side_effect = [response, robots]

        finding = inspect_url("http://lab.example", timeout=2.0)

        self.assertEqual(
            get.call_args_list,
            [
                call(
                    "http://lab.example",
                    timeout=2.0,
                    headers={"User-Agent": "recon-helper/0.3"},
                ),
                call(
                    "https://lab.example/robots.txt",
                    timeout=2.0,
                    headers={"User-Agent": "recon-helper/0.3"},
                ),
            ],
        )
        self.assertEqual(finding.status, 200)
        self.assertEqual(finding.final_url, "https://lab.example/dashboard")
        self.assertEqual(finding.title, "Lab Dashboard")
        self.assertEqual(finding.server, "nginx")
        self.assertEqual(finding.powered_by, "PHP")
        self.assertEqual(finding.redirects, 1)
        self.assertEqual(finding.response_time_ms, 125.0)
        self.assertEqual(finding.robots.disallowed_paths, ("/admin", "/backups"))
        headers = {header.name: header for header in finding.security_headers}
        self.assertTrue(headers["Strict-Transport-Security"].present)
        self.assertFalse(headers["X-Frame-Options"].present)

    def test_hsts_is_not_applicable_to_plain_http(self):
        findings = assess_security_headers({}, "http://lab.example")
        hsts = next(
            finding
            for finding in findings
            if finding.name == "Strict-Transport-Security"
        )
        self.assertFalse(hsts.applicable)
        self.assertFalse(hsts.present)

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
