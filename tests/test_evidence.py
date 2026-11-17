import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from recon.evidence import load_nmap_xml, load_recon_json

class ReconEvidenceTests(unittest.TestCase):
    def load_report(self, host_fields, **report_fields):
        data = {
            "ports": [443, 8443],
            "hosts": [{
                "target": "lab.example",
                "address": "192.0.2.10",
                **host_fields,}],
            **report_fields,}
        with TemporaryDirectory() as directory:
            path = Path(directory) / "scan.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            return load_recon_json(path)

    def test_partial_tcp_report_preserves_attempts_and_tls(self):
        tls = {"certificate_verified": True, "version": "TLSv1.3"}
        report = self.load_report(
            {
                "open_ports": [{"port": 443, "tls": tls}],
                "tcp_attempts": [
                    {"port": 443, "outcome": "open", "evidence": "Connected"},
                    {"port": 22, "outcome": "timeout", "evidence": "Timed out"},],},
            ports=[22, 443, 8443],
            interrupted=True,)
        self.assertEqual(report.requested_ports, (22, 443, 8443))
        self.assertTrue(report.interrupted)
        self.assertEqual(
            [(item.port, item.outcome) for item in report.observations],
            [(22, "timeout"), (443, "open")],)
        self.assertEqual(report.observations[1].tls, tls)

    def test_older_tcp_report_does_not_guess_from_checked_ports(self):
        report = self.load_report({
            "open_ports": [{"port": 443}],
            "checked_ports": [443, 8443],})
        self.assertEqual(
            [(item.port, item.outcome) for item in report.observations],
            [(443, "open")],)

    def test_udp_silence_stays_open_or_filtered(self):
        report = self.load_report(
            {"results": [{
                "port": 53,
                "status": "open|filtered",
                "evidence": "No reply before timeout",}]},
            protocol="udp",
            ports=[53],)
        observation, = report.observations
        self.assertEqual(observation.protocol, "udp")
        self.assertEqual(observation.outcome, "open|filtered")
        self.assertEqual(observation.evidence, "No reply before timeout")

class NmapEvidenceTests(unittest.TestCase):
    def test_imports_explicit_tcp_and_udp_ports_separately(self):
        xml = """<nmaprun start="0">
          <host>
            <address addr="192.0.2.10" addrtype="ipv4"/>
            <ports>
              <extraports state="closed" count="997"/>
              <port protocol="tcp" portid="53">
                <state state="open" reason="syn-ack"/>
                <service name="domain" method="probed"/>
              </port>
              <port protocol="udp" portid="53">
                <state state="open|filtered" reason="no-response"/>
                <service name="domain" method="table"/>
              </port>
            </ports>
          </host>
          <runstats><finished exit="success"/></runstats>
        </nmaprun>"""

        with TemporaryDirectory() as directory:
            path = Path(directory) / "scan.xml"
            path.write_text(xml, encoding="utf-8")
            report = load_nmap_xml(path)
        self.assertEqual(report.source, "nmap")
        self.assertEqual(report.started_at, "1970-01-01T00:00:00+00:00")
        self.assertIs(report.interrupted, False)
        self.assertEqual(
            [(item.address, item.protocol, item.port, item.outcome,item.evidence, item.service_method)
                for item in report.observations],
            [("192.0.2.10", "tcp", 53, "open", "syn-ack", "probed"),
             ("192.0.2.10", "udp", 53, "open|filtered", "no-response", "table"),],)