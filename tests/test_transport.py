import asyncio
import errno
import io
import json
import ssl
import unittest
from unittest.mock import AsyncMock, MagicMock, patch
from recon.cli import main
from recon.output import render
from recon.scanner import scan
from recon.tls import TLSFinding, inspect_tls
from recon.udp import UdpFinding, probe_udp, scan_udp

class StartTlsTests(unittest.TestCase):
    def inspect(self, reply, *, cert_error=None):
        connection = MagicMock()
        connection.getsockname.return_value = ("192.0.2.10", 40000)
        connection.recv.side_effect = [bytes([byte]) for byte in reply]
        context = MagicMock()
        wrapped = context.wrap_socket.return_value.__enter__.return_value
        wrapped.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        wrapped.version.return_value = "TLSv1.3"
        wrapped.getpeercert.return_value = {"subjectAltName": (("DNS", "mail.example"),)}
        wrapped.getpeercert.side_effect = [
            wrapped.getpeercert.return_value,
            b"abc",]
        if cert_error:
            context.wrap_socket.side_effect = cert_error
        with patch("recon.tls.socket.create_connection") as connect, patch(
            "recon.tls.ssl.create_default_context", return_value=context,):
            connect.return_value.__enter__.return_value = connection
            result = inspect_tls("mail.example", "192.0.2.4", 587, smtp_starttls=True)
            connect.assert_called_once_with(("192.0.2.4", 587), timeout=3.0)
        return result, connection, context

    def test_negotiates_upgrade_and_verifies_original_identity(self):
        result, connection, context = self.inspect(
            b"220 mail.example\r\n250-mail.example\r\n250-STARTTLS\r\n250 SIZE 1024\r\n220 Ready\r\n")
        self.assertEqual([call.args[0] for call in connection.sendall.call_args_list],
                         [b"EHLO [192.0.2.10]\r\n", b"STARTTLS\r\n"])
        context.wrap_socket.assert_called_once_with(connection, server_hostname="mail.example")
        self.assertTrue(result.certificate_verified)
        self.assertEqual(result.san_hostnames, ("mail.example",))
        self.assertEqual(result.mode, "smtp-starttls")

    def test_missing_extension_or_refused_upgrade_never_starts_tls(self):
        for capabilities, error, commands in [
            (b"250-mail.example\r\n250 SIZE 10\r\n", "did not advertise", 1),
            (b"250-mail.example\r\n250 STARTTLS\r\n454 Unavailable\r\n", "returned 454", 2),]:
            with self.subTest(error=error):
                result, connection, context = self.inspect(b"220 mail.example\r\n" + capabilities)
                self.assertIn(error, result.error)
                self.assertFalse(result.certificate_verified)
                self.assertEqual(connection.sendall.call_count, commands)
                context.wrap_socket.assert_not_called()

    def test_certificate_failure_remains_unverified(self):
        error = ssl.SSLCertVerificationError("self-signed certificate")
        error.verify_code = 18
        result, _, _ = self.inspect(
            b"220 mail.example\r\n250-mail.example\r\n250 STARTTLS\r\n220 Ready\r\n",
            cert_error=error,)
        self.assertFalse(result.certificate_verified)
        self.assertEqual(result.verification_code, 18)

class TransportScannerTests(unittest.IsolatedAsyncioTestCase):
    async def test_starttls_only_runs_on_selected_open_ports(self):
        async def tcp_probe(target, address, port, *args, **kwargs):
            if port == 25:
                raise ConnectionRefusedError
            return (1, None)
        with patch("recon.scanner._async_probe", side_effect=tcp_probe), patch(
            "recon.scanner.inspect_tls", return_value=TLSFinding(mode="smtp-starttls"),
        ) as inspect:
            report = await scan(["127.0.0.1"], ports=(22, 25, 587),
                                smtp_starttls_ports=(25, 587))
        inspect.assert_called_once_with("127.0.0.1", "127.0.0.1", 587, 3.0, smtp_starttls=True)
        self.assertIn("SMTP STARTTLS", render(report, "text"))
        with self.assertRaisesRegex(ValueError, "must not overlap"):
            await scan(["127.0.0.1"], inspect_tls_enabled=True, smtp_starttls_ports=(443,))

    async def test_udp_labels_reply_refusal_silence_and_socket_error_separately(self):
        variants = [
            (b"", None, "open"),
            (None, ConnectionRefusedError(errno.ECONNREFUSED, "refused"), "closed"),
            (None, TimeoutError(), "open|filtered"),
            (None, OSError(errno.ENETUNREACH, "unreachable"), "error"),]
        for response, error, expected in variants:
            with self.subTest(status=expected):
                loop = MagicMock(sock_connect=AsyncMock(), sock_sendall=AsyncMock(),
                                 sock_recv=AsyncMock(return_value=response, side_effect=error))
                with patch("recon.udp.socket.socket") as socket_factory, patch(
                    "recon.udp.asyncio.get_running_loop", return_value=loop,):
                    result = await probe_udp("127.0.0.1", 53, 0.2)
                self.assertEqual(result.status, expected)
                if expected == "open":
                    self.assertEqual(result.response_bytes, 0)
                self.assertTrue(loop.sock_sendall.await_args.args[1].endswith(b"\x00\x00\x02\x00\x01"))
                socket_factory.return_value.__exit__.assert_called_once()

    async def test_udp_partial_report_retains_only_finished_probes(self):
        blocked = asyncio.Event()

        async def probe(address, port, timeout):
            if port == 53:
                return UdpFinding(port, "open", "DNS", "reply", 10)
            blocked.set()
            await asyncio.Event().wait()
        with patch("recon.udp.probe_udp", side_effect=probe):
            job = asyncio.create_task(scan_udp(["127.0.0.1"], ports=(53, 123, 161),
                                              concurrency=1, preserve_on_cancel=True))
            await asyncio.wait_for(blocked.wait(), 1)
            job.cancel()
            report = await job
        self.assertTrue(report.interrupted)
        self.assertFalse(report.hosts[0].complete)
        self.assertEqual([item.port for item in report.hosts[0].results], [53])
        self.assertIn("1/3 UDP checks", render(report, "text"))
        self.assertIn("PARTIAL UDP REPORT", render(report, "table"))
        self.assertEqual(json.loads(render(report, "json"))["protocol"], "udp")

class TransportCliTests(unittest.TestCase):
    def test_udp_requires_ports_and_rejects_tls(self):
        for args in (["--udp"], ["--udp", "--ports", "53", "--tls"]):
            with self.subTest(args=args), patch("sys.stderr", new_callable=io.StringIO):
                self.assertEqual(main(["127.0.0.1", *args]), 2)

    def test_udp_dispatch_never_calls_tcp(self):
        with patch("recon.cli.scan", new_callable=AsyncMock) as tcp, patch(
            "recon.cli.scan_udp", new_callable=AsyncMock,
        ) as udp, patch("recon.cli.render", return_value=""), patch("sys.stdout", new_callable=io.StringIO):
            udp.return_value.interrupted = False
            self.assertEqual(main(["127.0.0.1", "--udp", "--ports", "53", "--probe-rate", "2"]), 0)
        tcp.assert_not_called()
        self.assertEqual(udp.await_args.kwargs["ports"], (53,))
        self.assertEqual(udp.await_args.kwargs["probe_rate"], 2)
