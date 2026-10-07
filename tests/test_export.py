import json
import tempfile
import unittest
import io
from unittest.mock import AsyncMock, patch
from recon.cli import main
from pathlib import Path
from recon.output import write_report, render
from recon.scanner import ScanReport

class ExportTests(unittest.TestCase):
    def setUp(self):
        self.report = ScanReport(
            requested_targets=("127.0.0.1",),
            engine="async",
            ports=(22,),
            started_at="2026-10-07T18:00:00+00:00",
            duration_ms=1.0,
            hosts=(),
        )

    def test_writes_json_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "results.json"
            write_report(self.report, path, "json")
            content = path.read_text(encoding="utf-8")
            data = json.loads(content)
            self.assertEqual(data["requested_targets"], ["127.0.0.1"])
            self.assertEqual(data["ports"], [22])
            self.assertEqual(data["engine"], "async")
            self.assertTrue(content.endswith("\n"))

    def test_refuses_to_overwrite_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "results.json"
            path.write_text("keep this content", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                write_report(self.report, path, "json")
            self.assertEqual(
                path.read_text(encoding="utf-8"),
                "keep this content",
            )

    def test_cli_exports_requested_format(self):
        cases = (
            ("-oJ", "json"),
            ("-oT", "text"),
        )
        for option, output_format in cases:
            with self.subTest(option=option):
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "results.txt"
                    with (
                        patch(
                            "recon.cli.scan",
                            new_callable=AsyncMock,
                            return_value=self.report,
                        ),
                        patch(
                            "sys.stdout",
                            new_callable=io.StringIO,
                        ) as terminal,
                    ):
                        exit_code = main([
                            "127.0.0.1",
                            "--format", "table",
                            option, str(path),
                        ])
                    self.assertEqual(exit_code, 0)
                    self.assertEqual(
                        path.read_text(encoding="utf-8"),
                        render(self.report, output_format) + "\n",
                    )
                    self.assertEqual(
                        terminal.getvalue(),
                        render(self.report, "table") + "\n",
                    )

    def test_cli_export_failure_preserves_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "results.json"
            path.write_text("keep this content", encoding="utf-8")
            with (
                patch(
                    "recon.cli.scan",
                    new_callable=AsyncMock,
                    return_value=self.report,
                ),
                patch(
                    "sys.stdout",
                    new_callable=io.StringIO,
                ) as terminal,
                patch(
                    "sys.stderr",
                    new_callable=io.StringIO,
                ) as errors,
            ):
                exit_code = main([
                    "127.0.0.1",
                    "-oJ", str(path),
                ])
            self.assertEqual(exit_code, 1)
            self.assertEqual(
                path.read_text(encoding="utf-8"),
                "keep this content",
            )
            self.assertEqual(
                terminal.getvalue(),
                render(self.report, "text") + "\n",
            )
            self.assertIn("could not save report", errors.getvalue())

