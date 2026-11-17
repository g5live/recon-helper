import io
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from recon.cli import main

class CompareCliTests(unittest.TestCase):
    def test_compares_nmap_and_recon_files_without_scanning(self):
        with TemporaryDirectory() as directory:
            baseline = Path(directory) / "baseline.xml"

            retest = Path(directory) / "retest.json"
            baseline.write_text("""<nmaprun>
              <host>
                <address addr="192.0.2.10" addrtype="ipv4"/>
                <ports>
                  <port protocol="tcp" portid="443">
                    <state state="open" reason="syn-ack"/>
                  </port>
                  <port protocol="tcp" portid="8443">
                    <state state="open" reason="syn-ack"/>
                  </port>
                </ports>
              </host>
            </nmaprun>""", encoding="utf-8")

            retest.write_text(json.dumps({
                "ports": [443, 8443],
                "interrupted": True,
                "hosts": [{
                    "target": "lab.example",
                    "address": "192.0.2.10",
                    "open_ports": [],
                    "tcp_attempts": [{
                        "port": 443,
                        "outcome": "refused",
                        "evidence": "TCP connection refused",}],}],
            }), encoding="utf-8")

            with (
                patch("recon.cli.scan") as tcp_scan,
                patch("recon.cli.scan_udp") as udp_scan,
                patch("sys.stdout", new_callable=io.StringIO) as output,):
                exit_code = main(["compare", str(baseline), str(retest)])

        self.assertEqual(exit_code, 0)
        tcp_scan.assert_not_called()
        udp_scan.assert_not_called()
        text = output.getvalue()
        self.assertIn("443/tcp: open -> refused (outcome-changed)", text)
        self.assertIn("8443/tcp: open -> not observed (baseline-only)", text)
        self.assertIn("Retest was interrupted", text)

    def test_missing_file_returns_an_input_error(self):
        with TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.xml"
            with patch("sys.stderr", new_callable=io.StringIO) as error:
                exit_code = main(["compare", str(missing), str(missing)])

        self.assertEqual(exit_code, 2)
        self.assertIn("Cannot compare scans:", error.getvalue())
        self.assertIn("missing.xml", error.getvalue())

    def test_summary_distinguishes_tls_change_from_missing_observations(self):
        def report(ports, fingerprint, interrupted=False):
            return {
                "ports": ports,
                "interrupted": interrupted,
                "hosts": [{
                    "target": "lab.example",
                    "address": "192.0.2.10",
                    "open_ports": [{
                        "port": 443,
                        "tls": {
                            "mode": "direct",
                            "certificate_verified": True,
                            "certificate_sha256": fingerprint,},}],}],}
        with TemporaryDirectory() as directory:
            baseline = Path(directory) / "baseline.json"
            retest = Path(directory) / "retest.json"
            original = report([443, 8443, 9443], "a" * 64)
            original["hosts"][0]["open_ports"].extend([
                {"port": 8443},
                {"port": 9443},])
            baseline.write_text(json.dumps(original), encoding="utf-8")
            retest.write_text(
                json.dumps(report([443, 9443], "b" * 64, interrupted=True)),
                encoding="utf-8",)
            with patch("sys.stdout", new_callable=io.StringIO) as output:
                exit_code = main(["compare", str(baseline), str(retest), "--summary"])
        self.assertEqual(exit_code, 0)
        text = output.getvalue()
        self.assertIn("# Retest summary", text)
        self.assertIn("`443/tcp`: the TLS certificate changed. " "The retest certificate verified successfully.",text,)
        self.assertIn("`8443/tcp`: status not reassessed. " "The port was outside the retest’s recorded port selection.",text,)
        self.assertIn("`9443/tcp`: status not reassessed. No retest observation was recorded.",text,)
        self.assertIn("its observations are partial", text)