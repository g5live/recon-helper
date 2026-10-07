import io
import unittest
from unittest.mock import patch, AsyncMock
from recon.cli import main

class InteractiveTests(unittest.TestCase):
    def test_guided_targets_ports(self):
        with patch('builtins.input',side_effect=['','127.0.0.1 localhost','bad','22,80']), patch('recon.cli.scan',new_callable=AsyncMock) as scan, patch('recon.cli.render',return_value='report'),patch('sys.stdout',new_callable=io.StringIO):
            self.assertEqual(main([]),0)
            self.assertEqual(scan.call_args.args[0],['127.0.0.1','localhost'])
            self.assertEqual(scan.call_args.kwargs['ports'],(22,80))
    def test_exit_eof_and_interrupt(self):
        for event,code in [('q',0),(EOFError(),0),(KeyboardInterrupt(),130)]:
            with patch('builtins.input',side_effect=[event]),patch('recon.cli.scan') as scan:
                self.assertEqual(main([]),code)
                scan.assert_not_called()
