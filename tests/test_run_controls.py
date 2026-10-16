import argparse
import asyncio
import io
import json
import math
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch
from recon.cli import main, parse_ports
from recon.output import render_json, render_table, render_text, write_report
from recon.scanner import ProbePacer, ScanReport, HostScan, PortFinding, scan

class PacingTests(unittest.IsolatedAsyncioTestCase):
    async def test_spacing_does_not_accumulate_burst_credits(self):
        now=[0.0]
        loop=MagicMock();loop.time.side_effect=lambda:now[0]
        async def sleep(delay):now[0]+=delay
        pacer=ProbePacer(2)
        with patch('recon.scanner.asyncio.get_running_loop',return_value=loop), patch('recon.scanner.asyncio.sleep',side_effect=sleep) as wait:
            await pacer.wait()
            await pacer.wait()
            now[0]=10.0
            await pacer.wait()
            await pacer.wait()
        self.assertEqual([call.args[0] for call in wait.call_args_list],[0.5,0.5])

    async def test_one_pacer_is_shared_across_hosts_and_both_engines(self):
        for engine in ('async','socket'):
            with patch('recon.scanner.ProbePacer.wait',new_callable=AsyncMock) as wait, patch('recon.scanner._async_probe',new=AsyncMock(side_effect=ConnectionRefusedError)), patch('recon.scanner.socket_probe',side_effect=ConnectionRefusedError):
                report=await scan(['192.0.2.1','192.0.2.2'],ports=(22,80),engine=engine,probe_rate=2)
                self.assertEqual(wait.await_count,4)
                self.assertEqual(report.probe_rate,2)
                self.assertTrue(all(host.complete for host in report.hosts))
                self.assertTrue(all(host.checked_ports==(22,80) for host in report.hosts))

    async def test_invalid_rates_and_timeouts_never_connect(self):
        with patch('recon.scanner._async_probe',new_callable=AsyncMock) as probe:
            for rate in (0,-1,float('nan'),float('inf'),-float('inf')):
                with self.subTest(rate=rate), self.assertRaises(ValueError):
                    await scan(['192.0.2.1'],probe_rate=rate)
            for name in ('timeout','banner_timeout','http_timeout','tls_timeout'):
                with self.subTest(timeout=name), self.assertRaises(ValueError):
                    await scan(['192.0.2.1'],**{name:float('nan')})
            probe.assert_not_called()

class InterruptionTests(unittest.IsolatedAsyncioTestCase):
    async def test_partial_port_and_unstarted_host_are_not_negative_findings(self):
        blocked=asyncio.Event()
        async def probe(target,address,port,*args,**kwargs):
            if target=='192.0.2.1' and port==22:return 1.2,'SSH-2.0-test'
            blocked.set();await asyncio.Event().wait()
        with patch('recon.scanner._async_probe',side_effect=probe):
            task=asyncio.create_task(scan(['192.0.2.1','192.0.2.2'],ports=(22,80),concurrency=1,preserve_on_cancel=True))
            await blocked.wait();task.cancel();report=await task
        self.assertTrue(report.interrupted)
        self.assertEqual(report.hosts[0].open_ports[0].port,22)
        self.assertEqual(report.hosts[0].checked_ports,(22,))
        self.assertFalse(report.hosts[0].complete)
        self.assertFalse(report.hosts[1].complete)
        text=render_text(report);table=render_table(report)
        self.assertIn('partial report',text)
        self.assertIn('unfinished checks remain',text)
        self.assertIn('PARTIAL REPORT',table)
        self.assertNotIn('No selected TCP ports responded.',table)
        data=json.loads(render_json(report))
        self.assertTrue(data['interrupted'])
        self.assertFalse(data['hosts'][1]['complete'])

    async def test_cancel_during_banner_keeps_observed_open_connection(self):
        reading=asyncio.Event()
        async def read(size):reading.set();await asyncio.Event().wait()
        reader=MagicMock();reader.read=read
        writer=MagicMock();writer.wait_closed=AsyncMock();writer.drain=AsyncMock()
        with patch('recon.scanner.asyncio.open_connection',new=AsyncMock(return_value=(reader,writer))):
            task=asyncio.create_task(scan(['192.0.2.1'],ports=(22,),preserve_on_cancel=True))
            await reading.wait();task.cancel();report=await task
        finding=report.hosts[0].open_ports[0]
        self.assertEqual(finding.port,22)
        self.assertFalse(finding.inspection_complete)
        self.assertIn('inspection incomplete',render_text(report))
        writer.close.assert_called_once()

    async def test_cancel_during_http_keeps_port_and_banner(self):
        started=asyncio.Event()
        async def inspect(*args,**kwargs):started.set();await asyncio.Event().wait()
        with patch('recon.scanner._async_probe',new=AsyncMock(return_value=(1.0,'HTTP/1.0 200 OK'))), patch('recon.scanner.asyncio.to_thread',side_effect=inspect):
            task=asyncio.create_task(scan(['192.0.2.1'],ports=(80,),inspect_http=True,preserve_on_cancel=True))
            await started.wait();task.cancel();report=await task
        self.assertEqual(report.hosts[0].open_ports[0].banner,'HTTP/1.0 200 OK')
        self.assertFalse(report.hosts[0].open_ports[0].inspection_complete)
        self.assertIn('pending',render_table(report))

    async def test_library_cancellation_propagates_unless_preservation_requested(self):
        started=asyncio.Event()
        async def probe(*args,**kwargs):started.set();await asyncio.Event().wait()
        with patch('recon.scanner._async_probe',side_effect=probe):
            task=asyncio.create_task(scan(['192.0.2.1'],ports=(22,)))
            await started.wait();task.cancel()
            with self.assertRaises(asyncio.CancelledError):await task

class ControlCliTests(unittest.TestCase):
    def report(self):
        return ScanReport(('192.0.2.1',),'async',(22,80),'2026-10-16T00:00:00+00:00',1,
            (HostScan('192.0.2.1','192.0.2.1',(PortFinding(22,'SSH',1),),checked_ports=(22,),complete=False),),interrupted=True)

    def test_interrupted_report_exports_and_returns_130(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'partial.json'
            with patch('recon.cli.scan',new=AsyncMock(return_value=self.report())),patch('sys.stdout',new_callable=io.StringIO) as output:
                code=main(['192.0.2.1','--probe-rate','2','-oJ',str(path)])
            self.assertEqual(code,130)
            self.assertTrue(json.loads(path.read_text())['interrupted'])
            self.assertIn('partial report',output.getvalue())

    def test_table_export_and_existing_file_protection(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'table.txt'
            with patch('recon.cli.scan',new=AsyncMock(return_value=self.report())),patch('sys.stdout',new_callable=io.StringIO):
                code=main(['192.0.2.1','-oA',str(path)])
            self.assertEqual(code,130)
            self.assertEqual(path.read_text(),render_table(self.report())+'\n')
            with self.assertRaises(FileExistsError):write_report(self.report(),path,'table')

    def test_out_of_range_ranges_are_rejected_before_expansion(self):
        for value in ('1-999999999999999','0-80','65535-65536','80-22'):
            with self.subTest(value=value),self.assertRaises(argparse.ArgumentTypeError):parse_ports(value)

    @unittest.skipUnless(sys.platform!='win32','POSIX signal regression')
    def test_actual_sigint_preserves_output_in_a_subprocess_without_network(self):
        script='''
import asyncio,signal,sys
from unittest.mock import patch
from recon.cli import main
async def probe(target,address,port,*args,**kwargs):
    if port==22:return 1.0,'SSH-2.0-test'
    asyncio.get_running_loop().call_soon(signal.raise_signal,signal.SIGINT)
    await asyncio.Event().wait()
with patch('recon.scanner._async_probe',side_effect=probe):
    raise SystemExit(main(['192.0.2.1','--ports','22,80','-oJ',sys.argv[1]]))
'''
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'interrupt.json'
            result=subprocess.run([sys.executable,'-c',script,str(path)],capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,130,result.stderr)
            data=json.loads(path.read_text())
            self.assertTrue(data['interrupted'])
            self.assertEqual(data['hosts'][0]['open_ports'][0]['port'],22)
            self.assertIn('partial report',result.stdout)
