#!/usr/bin/env python3
"""Phase 2 local ICMP metadata sensor. No API calls or packet-file output."""
import argparse
from collections import Counter
import csv
from datetime import datetime, timezone
import ipaddress
import json
import math
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import uuid

WINDOW_SECONDS = 60
THRESHOLD = 40
FIELDS = ('frame.number', 'frame.time_epoch', 'ip.src', 'ip.dst', 'ip.proto', 'icmp.type')


def ipv4(value):
    return str(ipaddress.IPv4Address(value))


def analyze(rows, destination, allowed_sources, destination_host=None, interface=None):
    """Count only observed, unique IPv4 ICMP echo-request frames in one window."""
    destination = ipv4(destination)
    allowed = {ipv4(s) for s in allowed_sources}
    counts = Counter()
    last_frame = 0
    stamps = []
    for row in rows:
        if set(row) != set(FIELDS) or any(row[k] is None for k in FIELDS):
            raise ValueError('Unexpected or incomplete metadata columns')
        frame = int(row['frame.number'])
        stamp = float(row['frame.time_epoch'])
        if frame <= last_frame or not math.isfinite(stamp) or stamp < 0:
            raise ValueError('Duplicate/out-of-order frame or invalid timestamp')
        last_frame = frame
        source, target = ipv4(row['ip.src']), ipv4(row['ip.dst'])
        if source not in allowed or target != destination or row['ip.proto'] != '1' or row['icmp.type'] != '8':
            raise ValueError('Metadata does not match the authorized capture scope')
        stamps.append(stamp)
        counts[source] += 1
    if stamps and max(stamps) - min(stamps) > WINDOW_SECONDS + 0.01:
        raise ValueError('Metadata exceeds one observation window')
    alerts = []
    for source, count in sorted(counts.items()):
        if count <= THRESHOLD:
            continue
        alerts.append({
            'alert_id': 'SOC-' + uuid.uuid4().hex.upper(),
            'alert_type': 'Network Volume Threshold Exceeded',
            'indicator_type': 'ip', 'indicator_value': source, 'source_ip': source,
            'source_host': destination_host if source == destination else None,
            'destination_host': destination_host, 'destination_ip': destination,
            'protocol': 'ICMP', 'detection_threshold': THRESHOLD,
            'evidence': {
                'packet_count': count, 'time_window_seconds': WINDOW_SECONDS,
                'data_source': 'metadata.csv', 'capture_interface': interface,
                'counting_rule': 'One observed IPv4 ICMP echo-request frame to the local destination; replies excluded',
                'interpretation': 'Volume threshold crossing only; malicious intent and service impact are unknown'
            }
        })
    return dict(sorted(counts.items())), alerts


def write_json(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write('\n')


def local_ipv4s(interface):
    if not interface or interface.startswith('-') or interface == 'any':
        raise ValueError('Select one actual local interface, never any')
    result = subprocess.run(['ip', '-j', '-4', 'addr', 'show', 'dev', interface],
                            check=True, capture_output=True, text=True, timeout=5)
    return {ipv4(a['local']) for link in json.loads(result.stdout)
            for a in link.get('addr_info', []) if a.get('family') == 'inet'}


def capture(args):
    if sys.platform != 'linux':
        raise RuntimeError('Live capture is permitted only inside the verified Ubuntu-New Linux VM')
    if os.geteuid() == 0:
        raise RuntimeError('Run Python as the ordinary lab user; grant capture access only to dumpcap')
    destination = ipv4(args.destination_ip)
    sources = sorted({ipv4(s) for s in args.source_ip})
    if destination not in local_ipv4s(args.interface):
        raise ValueError('Destination must be assigned to the selected local interface')
    if args.interface == 'lo' and (destination != '127.0.0.1' or sources != ['127.0.0.1']):
        raise ValueError('Phase 2 loopback scope must be exactly 127.0.0.1')
    os.umask(0o077)
    root = Path(args.output).resolve()
    root.mkdir(mode=0o700)  # Refuse existing run directories; never overwrite.
    source_filter = ' or '.join('src host ' + s for s in sources)
    capture_filter = f'ip and icmp and icmp[icmptype] = icmp-echo and dst host {destination} and ({source_filter})'
    command = ['tshark', '-n', '-p', '-i', args.interface, '-s', '64',
               '-f', capture_filter, '-a', f'duration:{WINDOW_SECONDS}',
               '-T', 'fields', '-E', 'header=y', '-E', 'separator=,',
               '-E', 'quote=d', '-E', 'occurrence=f']
    for field in FIELDS:
        command.extend(['-e', field])
    write_json(root / 'capture-config.json', {
        'mode': 'live_capture', 'interface': args.interface,
        'destination_ip': destination, 'allowed_source_ips': sources,
        'observation_window_seconds': WINDOW_SECONDS, 'detection_threshold': THRESHOLD,
        'threshold_operator': '>', 'capture_filter': capture_filter,
        'promiscuous': False, 'raw_packet_files_saved': False,
        'snaplen_bytes': 64, 'command': command,
        'started_at_utc': datetime.now(timezone.utc).isoformat(),
        'purpose': args.purpose
    })
    start = time.monotonic()
    try:
        with (root / 'metadata.csv').open('x', encoding='utf-8', newline='') as output, \
             (root / 'tshark.stderr.log').open('x', encoding='utf-8') as error:
            print('Capture starting: 60 seconds; wait for tshark capture startup before generating benign traffic.', flush=True)
            subprocess.run(command, stdout=output, stderr=error, timeout=WINDOW_SECONDS + 15, check=True)
        elapsed = time.monotonic() - start
        if elapsed < WINDOW_SECONDS - 0.25:
            raise RuntimeError('Capture stopped before the complete observation window')
        with (root / 'metadata.csv').open(encoding='utf-8', newline='') as stream:
            reader = csv.DictReader(stream)
            if tuple(reader.fieldnames or ()) != FIELDS:
                raise ValueError('Unexpected or missing tshark header')
            counts, alerts = analyze(reader, destination, sources, socket.gethostname(), args.interface)
        for alert in alerts:
            write_json(root / (alert['alert_id'] + '.json'), alert)
        summary = {
            'status': 'completed', 'mode': 'live_capture',
            'packet_count_by_source': counts, 'observed_echo_requests': sum(counts.values()),
            'alert_count': len(alerts), 'observation_window_seconds': WINDOW_SECONDS,
            'process_elapsed_seconds': round(elapsed, 3),
            'detection_threshold': THRESHOLD, 'purpose': args.purpose,
            'capture_loss_status': 'Not established; review tshark.stderr.log. Counts describe observed frames only.',
            'completed_at_utc': datetime.now(timezone.utc).isoformat()
        }
        write_json(root / 'summary.json', summary)
        print(json.dumps(summary, indent=2))
    except Exception as exc:
        write_json(root / 'failure.json', {'status': 'failed', 'error': str(exc),
                                        'interpretation': 'No successful observation established; do not use partial metadata as a complete window'})
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--interface', required=True)
    parser.add_argument('--destination-ip', required=True)
    parser.add_argument('--source-ip', action='append', required=True)
    parser.add_argument('--output', required=True, help='New directory; its parent must already exist')
    parser.add_argument('--purpose', required=True, help='Operator-recorded reason; this is not proof of benign intent')
    args = parser.parse_args()
    try:
        capture(args)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print('Capture failed: ' + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())