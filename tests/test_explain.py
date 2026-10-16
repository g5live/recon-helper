import unittest
from recon.explain import explain_finding
from recon.scanner import PortFinding, HostScan, ScanReport
from recon.tls import TLSFinding
from recon.web import WebFinding
from recon.output import render_text

class ExplanationTests(unittest.TestCase):
    def test_port_hint_does_not_become_protocol_identification(self):
        explanation = explain_finding(PortFinding(22, 'SSH', 1))
        self.assertIn('has not been confirmed', explanation.uncertainty)
        self.assertNotIn('advertised SSH', explanation.meaning)

    def test_ssh_evidence_works_on_an_unusual_port(self):
        explanation = explain_finding(
            PortFinding(2222, 'unknown', 1, detected_service='SSH'))
        self.assertIn('advertised SSH', explanation.meaning)
        self.assertIn('does not establish patch status', explanation.uncertainty)

    def test_tls_failure_is_not_called_verified_or_vulnerable(self):
        explanation = explain_finding(PortFinding(
            443, 'HTTPS', 1, tls=TLSFinding(error='certificate verification failed')))
        self.assertIn("TLS inspection did not finish successfully",explanation.meaning,)
        self.assertIn('TLS error', explanation.next_check)

    def test_verified_tls_has_a_limited_claim(self):
        explanation = explain_finding(PortFinding(
            443, 'HTTPS', 1, tls=TLSFinding(certificate_verified=True)))
        self.assertIn('target-identity', explanation.meaning)
        self.assertIn('does not establish', explanation.uncertainty)

    def test_certificate_failure_guidance(self):
        cases = (
            (10, "has expired"),
            (9, "not valid yet"),
            (62, "does not match"),
            (64, "does not match"),
            (18, "self-signed"),
            (19, "self-signed"),
            (20, "trusted certificate chain"),
            (21, "trusted certificate chain"),
            (999, "did not pass verification"),)
        for code, expected in cases:
            with self.subTest(code=code):
                finding = PortFinding(443, "HTTPS", 1, tls=TLSFinding(
                        error="certificate verification failed",
                        verification_code=code,),)
                explanation = explain_finding(finding)
                self.assertIn(expected, explanation.meaning)
                self.assertTrue(explanation.uncertainty)
                self.assertTrue(explanation.next_check)

    def test_report_shows_both_http_and_tls_guidance(self):
        web = WebFinding(
            status=200,
            final_url="https://lab.example/",
            title="Lab page",
            server=None,
            content_type="text/html",
            powered_by=None,
            response_size=100,
            response_time_ms=5,
            redirects=0,)
        finding = PortFinding(
            port=443,
            service="HTTPS",
            latency_ms=1,
            web=web,
            tls=TLSFinding(
                error="certificate verification failed",
                verification_code=10,),)
        report = ScanReport(
            requested_targets=("lab.example",),
            engine="async",
            ports=(443,),
            started_at="2026-10-16T12:00:00+00:00",
            duration_ms=10,
            hosts=(
                HostScan(
                    target="lab.example",
                    address="192.0.2.1",
                    open_ports=(finding,),),),)
        explained = render_text(report, explain=True)
        self.assertIn("What this means: An HTTP response was recorded", explained,)
        self.assertIn(
            "What this means: Certificate verification failed "
            "because the certificate has expired.", explained,)
        self.assertEqual(explained.count("What this means:"), 2)
        compact = render_text(report)
        self.assertNotIn("What this means:", compact)