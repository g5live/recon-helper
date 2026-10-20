import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from recon.cli import main

class TLSPortCliTests(unittest.TestCase):
    def test_passes_custom_tls_ports_to_scanner(self):
        report = SimpleNamespace(interrupted=False)
        with (
            patch(
                "recon.cli.scan",
                new_callable=AsyncMock,
                return_value=report,
            ) as scan_mock,
            patch("recon.cli.render", return_value=""),
            patch("sys.stdout"),):
            exit_code = main([
                "127.0.0.1",
                "--ports", "9443",
                "--tls",
                "--tls-ports", "9443,443,9443",])
        self.assertEqual(exit_code, 0)
        scan_mock.assert_awaited_once()
        options = scan_mock.await_args.kwargs
        self.assertEqual(options["ports"], (9443,))
        self.assertEqual(options["tls_ports"], (443, 9443))
        self.assertTrue(options["inspect_tls_enabled"])