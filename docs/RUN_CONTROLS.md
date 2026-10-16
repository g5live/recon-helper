# Run controls and partial reports

## Pace checks

```bash
python recon.py 127.0.0.1 --ports 22,80,443 --probe-rate 2 --concurrency 5 --format table -oA scan-table.txt
```

Concurrency is how many operations can be in flight. Probe rate spaces the dispatch of new TCP probes across all hosts, including the socket engine. At two per second, dispatches are at least half a second apart; idle time does not earn a burst of extra probes. Without this option, concurrency remains the only dispatch constraint.

This is a dispatch limit, not a packet or total-request limit. Socket threads can start later than dispatch. Optional HTTP inspection (including redirects and robots.txt), TLS inspection and DNS queries are outside the pacing limit. Positive finite values are required for rate and timeouts.

## Stop and keep evidence

Press Ctrl+C once during a scan. The CLI cancels remaining work, prints a partial report, attempts the requested file export and exits with code 130. Existing export files are protected, including during interruption. An export failure is logged; an interrupted run still returns 130.

An open TCP connection is recorded before reading its banner. Captured banners and completed HTTP findings are retained before later inspection starts. Work still running when the snapshot is taken may have no result. Thread-based socket/HTTP/TLS calls cannot be forcibly cancelled and can delay shutdown until their configured timeouts; timeouts are per operation, not a deadline for the whole run. A second Ctrl+C can force shutdown before export.

JSON adds these fields without removing the previous evidence fields:

| Field | Meaning |
|---|---|
| `interrupted` | Cancellation stopped the scan; this is a partial report |
| `probe_rate` | Requested TCP dispatch limit, or null when unset |
| `hosts[].checked_ports` | TCP attempts that produced an open observation or a terminal connection error/timeout; this does not assert that a port is closed |
| `hosts[].complete` | Host processing reached its terminal state; inspect `error` for resolution failures and each finding for inspection status |
| `hosts[].open_ports[].inspection_complete` | The probe and requested enrichment finished or recorded their handled failures; this is not a guarantee that inspection succeeded |

Text explains unfinished host work. The table marks unfinished open-port inspection as `pending` and includes unresolved/incomplete hosts even if no open port was observed. No observation yet means unknown, not closed. Check `error`, HTTP and TLS details separately for failed inspections.

The Python `scan()` API propagates cancellation by default. Set `preserve_on_cancel=True` only when the caller intends to consume a partial report. The CLI enables it.

## Save a view

`--format` selects terminal output independently of the file option. Choose one of `-oJ`/`--output-json`, `-oT`/`--output-text`, or `-oA`/`--output-table`. Here `-oA` means one table file, not all formats. Parent directories must exist; files are created exclusively and never overwritten.

## Verification

The regression suite uses mocked connections. It covers both engine dispatch paths, rate spacing, invalid numeric inputs, cancellation during banner/HTTP work, ordinary API cancellation, incomplete-host output, table export protection and an actual POSIX SIGINT delivered to a subprocess with mocked probes.
