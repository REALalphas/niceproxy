import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('benchmark_park', Path(__file__).parents[1] / 'benchmark-park.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class BenchmarkEvidenceTest(unittest.TestCase):
    def row(self):
        return {'exitCode': 0, 'errors': 0, 'succeeded': 100,
                'conntrackBefore': {'count': 10, 'max': 262144},
                'conntrackAfter': {'count': 11, 'max': 262144},
                'ruleStatsAfter': [{'status': 'healthy', 'stats': {'errors': 0, 'rejects': 0}},
                                   {'status': 'healthy', 'stats': {'errors': 0, 'rejects': 0}}]}

    def test_success_requires_proxy_and_host_evidence(self):
        module.validate_result(self.row())

    def test_successful_clients_cannot_hide_proxy_errors_or_rejects(self):
        for counter in ('errors', 'rejects'):
            row = self.row()
            row['ruleStatsAfter'][0]['stats'][counter] = 1
            with self.subTest(counter=counter), self.assertRaisesRegex(AssertionError, 'counters'):
                module.validate_result(row)

    def test_unavailable_conntrack_cannot_pass(self):
        for field in ('conntrackBefore', 'conntrackAfter'):
            row = self.row()
            row[field] = None
            with self.subTest(field=field), self.assertRaisesRegex(AssertionError, 'conntrack'):
                module.validate_result(row)

    def test_missing_stats_or_unhealthy_rule_cannot_pass(self):
        cases = []
        row = self.row(); row['statsReadError'] = 'timeout'; cases.append(row)
        row = self.row(); row['ruleStatsAfter'] = None; cases.append(row)
        row = self.row(); row['ruleStatsAfter'][0]['status'] = 'error'; cases.append(row)
        for row in cases:
            with self.assertRaises(AssertionError):
                module.validate_result(row)


    def test_http_requires_exact_full_body_byte_count(self):
        for protocol in ('http', 'https'):
            row = self.row()
            row.update(protocol=protocol, receivedBytes=100 * len(module.HTTP_BODY.encode()))
            module.validate_result(row)
            for size in (None, 0, 100 * len('bench-backend '), row['receivedBytes'] + 1):
                with self.subTest(protocol=protocol, size=size):
                    invalid = {**row, 'receivedBytes': size}
                    with self.assertRaisesRegex(AssertionError, 'byte count'):
                        module.validate_result(invalid)

    def target_rows(self, rates=(110, 120), concurrency=16):
        return [{**self.row(), 'case': 'tcp_256_reused', 'variant': 'proxy',
                 'repeat': i + 1, 'concurrency': concurrency, 'requestsPerSecond': rate}
                for i, rate in enumerate(rates)]

    def assess(self, rows, levels=(16,)):
        return module.assess_targets(rows, {'tcp_256_reused': 100}, levels, 2)['tcp_256_reused']

    def test_target_requires_all_repeats_not_average_or_max(self):
        self.assertTrue(self.assess(self.target_rows((100, 120)))['passed'])
        self.assertFalse(self.assess(self.target_rows((90, 200)))['passed'])

    def test_missing_cases_repeats_and_duplicate_repeats_cannot_pass(self):
        for rows in ([], self.target_rows()[:1], self.target_rows()[:1] * 2):
            with self.subTest(rows=rows):
                self.assertFalse(self.assess(rows)['passed'])

    def test_direct_runs_do_not_fill_missing_proxy_repeats(self):
        rows = self.target_rows()
        rows[1]['variant'] = 'direct'
        self.assertFalse(self.assess(rows)['passed'])

    def test_target_requires_zero_errors_and_functional_evidence(self):
        for field, value in (('errors', 1), ('errors', None), ('exitCode', 1),
                             ('conntrackAfter', None), ('requestsPerSecond', float('nan'))):
            rows = self.target_rows()
            rows[1][field] = value
            with self.subTest(field=field):
                self.assertFalse(self.assess(rows)['passed'])

    def test_repeats_cannot_be_pooled_across_concurrency_levels(self):
        rows = self.target_rows()
        rows[1]['concurrency'] = 32
        self.assertFalse(self.assess(rows, (16, 32))['passed'])

    def test_each_qualifying_level_needs_complete_repeats(self):
        rows = self.target_rows((90, 200)) + self.target_rows((100, 110), 32)
        assessment = self.assess(rows, (16, 32, 64))
        self.assertTrue(assessment['passed'])
        self.assertFalse(assessment['concurrency']['16']['passed'])
        self.assertTrue(assessment['concurrency']['32']['passed'])
        self.assertFalse(assessment['concurrency']['64']['complete'])


if __name__ == '__main__':
    unittest.main()
