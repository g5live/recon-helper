import unittest
from recon.compare import compare_scans
from recon.evidence import PortObservation, SavedScan

def saved_scan(source, *observations):
    return SavedScan(source, None, (), (), False, observations)

class CompareScanTests(unittest.TestCase):
    def test_matches_by_ip_and_keeps_tcp_and_udp_separate(self):
        address = "192.0.2.10"
        baseline = saved_scan(
            "nmap",
            PortObservation(address, address, "tcp", 53, "open"),
            PortObservation(address, address, "udp", 53, "open|filtered"),
            PortObservation(address, address, "tcp", 8443, "open"),)
        retest = saved_scan(
            "recon-helper",
            PortObservation("lab.example", address, "tcp", 53, "refused"),
            PortObservation("lab.example", address, "udp", 53, "open|filtered"),
            PortObservation("lab.example", address, "tcp", 9443, "open"),)
        deltas = {delta.endpoint: delta for delta in compare_scans(baseline, retest)}
        self.assertEqual(
            {key: delta.kind for key, delta in deltas.items()},
            {
                (address, "tcp", 53): "outcome-changed",
                (address, "udp", 53): "same-outcome",
                (address, "tcp", 8443): "baseline-only",
                (address, "tcp", 9443): "retest-only",},)
        self.assertIsNone(deltas[(address, "tcp", 8443)].after)
        self.assertIsNone(deltas[(address, "tcp", 9443)].before)

    def test_matches_equivalent_ipv6_spellings(self):
        baseline = saved_scan(
            "nmap",
            PortObservation("lab", "2001:0db8:0:0:0:0:0:1", "tcp", 443, "open"),)
        retest = saved_scan(
            "recon-helper",
            PortObservation("lab", "2001:db8::1", "tcp", 443, "open"),)
        delta, = compare_scans(baseline, retest)
        self.assertEqual(delta.endpoint, ("2001:db8::1", "tcp", 443))
        self.assertEqual(delta.kind, "same-outcome")

    def test_rejects_ambiguous_duplicate_endpoints(self):
        address = "192.0.2.10"
        baseline = saved_scan(
            "recon-helper",
            PortObservation("a.example", address, "tcp", 443, "open"),
            PortObservation("b.example", address, "tcp", 443, "open"),)
        with self.assertRaisesRegex(ValueError, "Multiple observations"):
            compare_scans(baseline, saved_scan("nmap"))

    def tls_scan(self, target, fingerprint, *, mode="direct", verified=True):
        return saved_scan(
            "recon-helper",
            PortObservation(
                target, "192.0.2.10", "tcp", 443, "open",
                tls={
                    "mode": mode,
                    "certificate_verified": verified,
                    "certificate_sha256": fingerprint,},),)

    def test_reports_certificate_change_while_port_stays_open(self):
        baseline = self.tls_scan("lab.example", "a" * 64)
        retest = self.tls_scan("lab.example", "b" * 64)
        delta, = compare_scans(baseline, retest)
        self.assertEqual(delta.kind, "same-outcome")
        self.assertEqual(delta.tls_changes, ("certificate fingerprint changed",))

    def test_withholds_certificate_claim_when_evidence_does_not_match(self):
        baseline = self.tls_scan("lab.example", "a" * 64)
        cases = [
            ("different hostname", self.tls_scan("other.example", "b" * 64), ()),
            ("different TLS mode", self.tls_scan(
                "lab.example", "b" * 64, mode="smtp-starttls",
            ), ()),
            ("missing fingerprint", self.tls_scan("lab.example", None), ()),
            ("verification failure", self.tls_scan(
                "lab.example", None, verified=False,
            ), ("verification result changed",)),]
        for label, retest, expected in cases:
            with self.subTest(label=label):
                delta, = compare_scans(baseline, retest)
                self.assertEqual(delta.tls_changes, expected)