import ssl
import unittest
import json
from recon.output import render_json, render_table, render_text
from unittest.mock import MagicMock, patch, AsyncMock
from recon.tls import inspect_tls, TLSFinding
from recon.scanner import scan

class TLSInspectionTests(unittest.TestCase):
    def test_records_verified_tls_version_and_cipher(self):
        connection = MagicMock()
        tls_connection = MagicMock()
        tls_connection.version.return_value = "TLSv1.3"
        tls_connection.cipher.return_value = (
            "TLS_AES_256_GCM_SHA384",
            "TLSv1.3",
            256,
        )
        tls_connection.getpeercert.return_value = {
            "subject": (
                (("commonName", "lab.example"),),
            ),
            "issuer": (
                (("commonName", "Example Lab CA"),),
            ),
            "subjectAltName": (
                ("DNS", "lab.example"),
                ("DNS", "www.lab.example"),
                ("IP Address", "192.0.2.1"),
            ),
            "notBefore": "Oct  1 00:00:00 2026 GMT",
            "notAfter": "Oct  1 00:00:00 2027 GMT",
        }
        with (
            patch("recon.tls.socket.create_connection") as connect,
            patch("recon.tls.ssl.create_default_context") as create_context,
        ):
            connect.return_value.__enter__.return_value = connection
            context = create_context.return_value
            context.wrap_socket.return_value.__enter__.return_value = (
                tls_connection
            )
            finding = inspect_tls(
                "lab.example",
                "192.0.2.1",
                443,
                timeout=2.0,
            )
        connect.assert_called_once_with(
            ("192.0.2.1", 443),
            timeout=2.0,
        )
        context.wrap_socket.assert_called_once_with(
            connection,
            server_hostname="lab.example",
        )
        self.assertEqual(finding.version, "TLSv1.3")
        self.assertEqual(finding.cipher, "TLS_AES_256_GCM_SHA384")
        self.assertTrue(finding.certificate_verified)
        self.assertIsNone(finding.error)
        self.assertEqual(finding.subject, "commonName=lab.example")
        self.assertEqual(finding.issuer, "commonName=Example Lab CA")
        self.assertEqual(
            finding.san_hostnames,
            ("lab.example", "www.lab.example"),
        )
        self.assertEqual(
            finding.valid_from,
            "Oct  1 00:00:00 2026 GMT",
        )
        self.assertEqual(
            finding.valid_until,
            "Oct  1 00:00:00 2027 GMT",
        )

    def test_records_certificate_verification_failure(self):
        with (
            patch("recon.tls.socket.create_connection"),
            patch("recon.tls.ssl.create_default_context") as create_context,
        ):
            create_context.return_value.wrap_socket.side_effect = (
                ssl.SSLCertVerificationError(
                    1,
                    "self-signed certificate",
                )
            )
            finding = inspect_tls("lab.example", "192.0.2.1", 443)
        self.assertFalse(finding.certificate_verified)
        self.assertIsNone(finding.version)
        self.assertIn(
            "certificate verification failed",
            finding.error or "",
        )

    def test_records_connection_failure(self):
        with (
            patch("recon.tls.ssl.create_default_context"),
            patch(
                "recon.tls.socket.create_connection",
                side_effect=TimeoutError("connection timed out"),
            ),
        ):
            finding = inspect_tls("lab.example", "192.0.2.1", 443)
        self.assertFalse(finding.certificate_verified)
        self.assertIn("TLS connection failed", finding.error or "")
        self.assertIn("connection timed out", finding.error or "")

    def test_rejects_nonpositive_timeout_before_connecting(self):
        for timeout in (0, -1):
            with self.subTest(timeout=timeout):
                with patch(
                    "recon.tls.socket.create_connection"
                ) as connect:
                    with self.assertRaises(ValueError):
                        inspect_tls(
                            "lab.example",
                            "192.0.2.1",
                            443,
                            timeout=timeout,
                        )
                connect.assert_not_called()

class TLSScannerTests(unittest.IsolatedAsyncioTestCase):
    async def test_tls_inspection_is_opt_in(self):
        expected = TLSFinding(
            version="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384",
            certificate_verified=True,
        )
        for enabled in (False, True):
            with self.subTest(enabled=enabled):
                with (
                    patch(
                        "recon.scanner._async_probe",
                        new_callable=AsyncMock,
                        return_value=(1.0, None),
                    ),
                    patch(
                        "recon.scanner.inspect_tls",
                        return_value=expected,
                    ) as inspect,
                ):
                    report = await scan(
                        ["127.0.0.1"],
                        ports=(443,),
                        inspect_tls_enabled=enabled,
                        tls_timeout=2.0,
                    )
                finding = report.hosts[0].open_ports[0]
                if enabled:
                    inspect.assert_called_once_with("127.0.0.1", "127.0.0.1", 443, 2.0, )
                    self.assertEqual(finding.tls, expected)
                else:
                    inspect.assert_not_called()
                    self.assertIsNone(finding.tls)

    async def test_outputs_include_tls_details(self):
        expected = TLSFinding(
            version="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384",
            certificate_verified=True,
            subject="commonName=lab.example",
            issuer="commonName=Example Lab CA",
            san_hostnames=("lab.example",),
            valid_from="Oct  1 00:00:00 2026 GMT",
            valid_until="Oct  1 00:00:00 2027 GMT",
        )
        with (
            patch(
                "recon.scanner._async_probe",
                new_callable=AsyncMock,
                return_value=(1.0, None),
            ),
            patch("recon.scanner.inspect_tls", return_value=expected),
        ):
            report = await scan(
                ["127.0.0.1"],
                ports=(443,),
                inspect_tls_enabled=True,
            )
        text = render_text(report)
        self.assertIn("TLS: TLSv1.3", text)
        self.assertIn("cipher: TLS_AES_256_GCM_SHA384", text)
        self.assertIn("certificate: verified", text)
        self.assertIn("subject: commonName=lab.example", text)
        self.assertIn("issuer: commonName=Example Lab CA", text)
        self.assertIn("SAN DNS names: lab.example", text)
        self.assertIn("valid from: Oct  1 00:00:00 2026 GMT", text)
        self.assertIn("valid until: Oct  1 00:00:00 2027 GMT", text)
        table = render_table(report)
        self.assertIn("TLS", table.splitlines()[0].split())
        self.assertIn("TLSv1.3", table.splitlines()[2].split())
        data = json.loads(render_json(report))
        tls = data["hosts"][0]["open_ports"][0]["tls"]
        self.assertEqual(tls["version"], "TLSv1.3")
        self.assertTrue(tls["certificate_verified"])
        self.assertEqual(tls["san_hostnames"], ["lab.example"])

    async def test_tls_failure_preserves_open_port(self):
        failed_tls = TLSFinding(
            error="certificate verification failed: self-signed certificate"
        )
        with (
            patch(
                "recon.scanner._async_probe",
                new_callable=AsyncMock,
                return_value=(1.0, None),
            ),
            patch(
                "recon.scanner.inspect_tls",
                return_value=failed_tls,
            ) as inspect,
        ):
            report = await scan(
                ["127.0.0.1"],
                ports=(443,),
                inspect_tls_enabled=True,
            )
        inspect.assert_called_once()
        self.assertEqual(len(report.hosts[0].open_ports), 1)
        finding = report.hosts[0].open_ports[0]
        self.assertEqual(finding.port, 443)
        self.assertEqual(finding.tls, failed_tls)
        self.assertFalse(finding.tls.certificate_verified)
        self.assertIn("TLS inspection failed:", render_text(report))
        self.assertIn(
            "error",
            render_table(report).splitlines()[2].split(),
        )
        data = json.loads(render_json(report))
        tls = data["hosts"][0]["open_ports"][0]["tls"]
        self.assertEqual(tls["error"], failed_tls.error)
        self.assertFalse(tls["certificate_verified"])


