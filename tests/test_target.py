import io
import tempfile
import unittest
from unittest.mock import AsyncMock, patch
from recon.cli import main, read_target_file
from pathlib import Path
from recon.scanner import TargetError, expand_targets

class TargetFileTests(unittest.TestCase):
    def test_reads_targets_and_skips_blank_lines_and_comments(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "targets.txt"
            path.write_text(
                "# Local practice targets\n"
                "\n"
                "  127.0.0.1  \n"
                "localhost\n"
                "127.0.0.0/30\n",
                encoding="utf-8",
            )
            targets = read_target_file(path)
            self.assertEqual(
                targets,
                ["127.0.0.1", "localhost", "127.0.0.0/30"],
            )
    def test_combines_cli_and_file_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "targets.txt"
            path.write_text("127.0.0.1\n", encoding="utf-8")
            with (
                patch("recon.cli.scan", new_callable=AsyncMock) as scan,
                patch("recon.cli.render", return_value="test report"),
                patch("sys.stdout", new_callable=io.StringIO),
            ):
                exit_code = main([
                    "localhost",
                    "-iL", str(path),
                    "--ports", "22",
                ])
            self.assertEqual(exit_code, 0)
            scan.assert_awaited_once()
            self.assertEqual(
                scan.call_args.args[0],
                ["localhost", "127.0.0.1"],
            )
            self.assertEqual(scan.call_args.kwargs["ports"], (22,))

    def test_missing_file_returns_error_without_scanning(self):
            with tempfile.TemporaryDirectory() as directory:
                missing_path = Path(directory) / "missing.txt"
                with (
                    patch("recon.cli.scan", new_callable=AsyncMock) as scan,
                    patch("builtins.input") as prompt,
                    patch("sys.stderr", new_callable=io.StringIO) as errors,
                ):
                    exit_code = main(["-iL", str(missing_path)])
                self.assertEqual(exit_code, 2)
                scan.assert_not_called()
                prompt.assert_not_called()
                self.assertIn("cannot read target file", errors.getvalue())

    def test_empty_file_returns_error_without_scanning(self):
        for contents in ("", "# No targets yet\n\n"):
            with self.subTest(contents=contents):
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "targets.txt"
                    path.write_text(contents, encoding="utf-8")
                    with (
                        patch("recon.cli.scan", new_callable=AsyncMock) as scan,
                        patch("builtins.input") as prompt,
                        patch("sys.stderr", new_callable=io.StringIO) as errors,
                    ):
                        exit_code = main(["-iL", str(path)])
                    self.assertEqual(exit_code, 2)
                    scan.assert_not_called()
                    prompt.assert_not_called()
                    self.assertIn(
                        "no usable targets supplied",
                        errors.getvalue(),
                    )

    def test_large_cidr_stops_at_host_limit(self):
        with self.assertRaises(TargetError):
            expand_targets(
                ["2001:db8::/64"],
                max_hosts=2,
            )

    def test_deduplicates_overlapping_targets(self):
        targets = expand_targets(
            ["192.0.2.1", "192.0.2.0/30", "192.0.2.2"],
            max_hosts=2,
        )
        self.assertEqual(
            targets,
            ("192.0.2.1", "192.0.2.2"),
        )

    def test_host_limit_applies_across_combined_targets(self):
        with self.assertRaises(TargetError):
            expand_targets(
                ["192.0.2.1", "192.0.2.0/30", "192.0.2.3"],
                max_hosts=2,
            )