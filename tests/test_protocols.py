import unittest
import json
from unittest.mock import AsyncMock, patch
from recon.scanner import scan
from recon.protocols import detect_banner_service
from recon.output import render_json, render_table, render_text

class BannerDetectionTests(unittest.TestCase):
    def test_recognises_ssh_identification(self):
        self.assertEqual(
            detect_banner_service("SSH-2.0-OpenSSH_9.6"),
            "SSH",
        )

    def test_recognises_ssh_after_greeting(self):
        self.assertEqual(
            detect_banner_service(
                "Welcome to the lab | SSH-2.0-OpenSSH_9.6"
            ),
            "SSH",
        )

    def test_leaves_unsupported_or_missing_banners_unidentified(self):
        banners = (
            None,
            "",
            "220 Service ready",
            "HTTP/1.1 200 OK",
            "SSH-2.0-",
            "Welcome to my SSH server",
        )
        for banner in banners:
            with self.subTest(banner=banner):
                self.assertIsNone(detect_banner_service(banner))

    def test_recognises_explicit_ftp_greetings(self):
        banners = (
            "220 Welcome to the FTP service",
            "220 ftp server ready",
            "220-Welcome to the FTP service | 220 Ready",
        )
        for banner in banners:
            with self.subTest(banner=banner):
                self.assertEqual(
                    detect_banner_service(banner),
                    "FTP",
                )

    def test_leaves_ambiguous_or_unrelated_greetings_unidentified(self):
        banners = (
            "220 Service ready",
            "220 mail.example ESMTP ready",
            "220 SFTP service ready",
            "Welcome to the FTP service",
            "500 FTP service unavailable",
        )
        for banner in banners:
            with self.subTest(banner=banner):
                self.assertIsNone(detect_banner_service(banner))

class ServiceDetectionTests(unittest.IsolatedAsyncioTestCase):
    async def test_detection_depends_on_banner_not_port(self):
        cases = (
            (2222, "SSH-2.0-OpenSSH_9.6", "SSH"),
            (22, None, None),
            (2121, "220 Welcome to the FTP service", "FTP"),
            (21, "220 Service ready", None),
            (21, "220 mail.example ESMTP ready", None),
        )
        for port, banner, expected in cases:
            with self.subTest(port=port):
                with patch(
                    "recon.scanner._async_probe",
                    new_callable=AsyncMock,
                    return_value=(1.0, banner),
                ) as probe:
                    report = await scan(
                        ["127.0.0.1"],
                        ports=(port,),
                    )
                probe.assert_awaited_once()
                finding = report.hosts[0].open_ports[0]
                self.assertEqual(finding.detected_service, expected)
                self.assertEqual(finding.banner, banner)
                if port == 22:
                    self.assertEqual(finding.service, "SSH")
                if expected is not None:
                    self.assertIn(
                        f"banner identifies: {expected}",
                        render_text(report),
                    )
                    row = render_table(report).splitlines()[2].split()
                    self.assertEqual(row[4], expected)
                    data = json.loads(render_json(report))
                    self.assertEqual(
                        data["hosts"][0]["open_ports"][0]["detected_service"],
                        expected,
                    )

    async def test_outputs_separate_hint_from_detection(self):
        with patch(
            "recon.scanner._async_probe",
            new_callable=AsyncMock,
            return_value=(1.0, None),
        ):
            report = await scan(["127.0.0.1"], ports=(22,))
        text = render_text(report)
        self.assertIn("hint: SSH", text)
        self.assertNotIn("banner identifies:", text)
        table = render_table(report)
        headings = table.splitlines()[0].split()
        self.assertEqual(headings[3:5], ["HINT", "DETECTED"])
        row = table.splitlines()[2].split()
        self.assertEqual(row[3:5], ["SSH", "-"])
        data = json.loads(render_json(report))
        finding = data["hosts"][0]["open_ports"][0]
        self.assertEqual(finding["service"], "SSH")
        self.assertIsNone(finding["detected_service"])

