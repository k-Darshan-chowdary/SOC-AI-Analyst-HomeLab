"""Offline logic tests; synthetic metadata is never labeled a live capture."""
import csv
import io
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from soc_capture import analyze, FIELDS


def rows(n, source='127.0.0.1', start=1):
    return [dict(zip(FIELDS, map(str, (i, 1800000000 + (i-start)*0.5, source, '127.0.0.1', 1, 8)))) for i in range(start, start+n)]


class SensorTests(unittest.TestCase):
    def check_count(self, n):
        counts, alerts = analyze(rows(n), '127.0.0.1', ['127.0.0.1'], 'observed-lab-host', 'lo')
        self.assertEqual(sum(counts.values()), n)
        self.assertEqual(len(alerts), int(n > 40))
        return alerts

    def test_empty(self): self.check_count(0)
    def test_below(self): self.check_count(39)
    def test_equal(self): self.check_count(40)
    def test_above_and_schema(self):
        a = self.check_count(41)[0]
        self.assertEqual(a['evidence']['packet_count'], 41)
        self.assertEqual(a['evidence']['time_window_seconds'], 60)
        self.assertEqual(a['detection_threshold'], 40)
        self.assertEqual(a['source_ip'], '127.0.0.1')
        for key in ['alert_id','alert_type','indicator_type','indicator_value','source_host','destination_host','destination_ip','protocol']:
            self.assertIn(key, a)
        json.dumps(a, allow_nan=False)

    def test_all_sources_and_unknown_host(self):
        data = rows(41, '192.0.2.1') + rows(41, '192.0.2.2', 42)
        counts, alerts = analyze(data, '127.0.0.1', ['192.0.2.1','192.0.2.2'], 'local-host', 'lo')
        self.assertEqual(len(alerts), 2)
        self.assertEqual(sum(counts.values()), 82)
        self.assertTrue(all(a['source_host'] is None for a in alerts))

    def test_replies_rejected(self):
        data = rows(1); data[0]['icmp.type'] = '0'
        with self.assertRaises(ValueError): analyze(data, '127.0.0.1', ['127.0.0.1'])
    def test_unapproved_source_rejected(self):
        with self.assertRaises(ValueError): analyze(rows(1,'192.0.2.1'), '127.0.0.1', ['127.0.0.1'])
    def test_wrong_destination_rejected(self):
        data = rows(1); data[0]['ip.dst'] = '192.0.2.9'
        with self.assertRaises(ValueError): analyze(data, '127.0.0.1', ['127.0.0.1'])
    def test_duplicate_frame_rejected(self):
        data = rows(1) * 2
        with self.assertRaises(ValueError): analyze(data, '127.0.0.1', ['127.0.0.1'])
    def test_missing_metadata_rejected(self):
        data = rows(1); del data[0]['ip.proto']
        with self.assertRaises(ValueError): analyze(data, '127.0.0.1', ['127.0.0.1'])
    def test_nonfinite_time_rejected(self):
        data = rows(1); data[0]['frame.time_epoch'] = 'nan'
        with self.assertRaises(ValueError): analyze(data, '127.0.0.1', ['127.0.0.1'])
    def test_multiple_windows_rejected(self):
        data = rows(2); data[1]['frame.time_epoch'] = '1800000061'
        with self.assertRaises(ValueError): analyze(data, '127.0.0.1', ['127.0.0.1'])
    def test_real_csv_format(self):
        data = rows(41); buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=FIELDS, quoting=csv.QUOTE_ALL)
        writer.writeheader(); writer.writerows(data); buffer.seek(0)
        counts, alerts = analyze(csv.DictReader(buffer), '127.0.0.1', ['127.0.0.1'])
        self.assertEqual(alerts[0]['source_host'], None)
        self.assertEqual(counts['127.0.0.1'], 41)


if __name__ == '__main__': unittest.main(verbosity=2)