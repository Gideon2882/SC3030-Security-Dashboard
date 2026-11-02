import unittest
from pathlib import Path
from validator import POLICIES, EXPANDED_POLICIES, validate

ROOT = Path(__file__).resolve().parents[1]
def sample(name):
    return (ROOT / 'samples' / name).read_text(encoding='utf-8')

class ExpandedPolicyTests(unittest.TestCase):
    def test_suite_size_and_ids(self):
        self.assertEqual(len(POLICIES), 4)
        self.assertEqual(len(EXPANDED_POLICIES), 8)
        self.assertEqual(len({p.identifier for p in EXPANDED_POLICIES}), 8)

    def test_original_test_outcomes_unchanged(self):
        self.assertEqual(validate(sample('01_unsafe_missing_deny.txt'))['passed'], 3)
        self.assertEqual(validate(sample('02_corrected.txt'))['passed'], 4)
        self.assertEqual(validate(sample('03_overblocked_dns.txt'))['passed'], 3)

    def test_corrected_sample_expanded_all_pass(self):
        r=validate(sample('02_corrected.txt'), EXPANDED_POLICIES)
        self.assertTrue(r['valid_for_model'])
        self.assertEqual((r['passed'],r['security_passed'],r['safety_passed']), (8,5,3))

    def test_unsafe_sample_expanded(self):
        r=validate(sample('01_unsafe_missing_deny.txt'), EXPANDED_POLICIES)
        self.assertEqual(r['passed'], 5)
        self.assertEqual({x['ID'] for x in r['results'] if x['Status']=='FAIL'}, {'SEC-01','SEC-03','SEC-05'})

    def test_overblocked_sample_expanded(self):
        r=validate(sample('03_overblocked_dns.txt'), EXPANDED_POLICIES)
        self.assertEqual(r['passed'], 6)
        self.assertEqual({x['ID'] for x in r['results'] if x['Status']=='FAIL'}, {'OPS-01','OPS-03'})

    def test_actual_8_requirement_outputs(self):
        for filename in ['A_basic_8_requirements.txt', 'B_guided_8_requirements.txt']:
            with self.subTest(filename=filename):
                config = (ROOT / 'experiment_configs' / filename).read_text(encoding='utf-8')
                result = validate(config, EXPANDED_POLICIES)
                self.assertTrue(result['valid_for_model'])
                self.assertEqual((result['passed'],result['security_passed'],result['safety_passed']), (8,5,3))

    def test_acl_order_blocks_dns_in_expanded(self):
        cfg = sample('03_overblocked_dns.txt')
        result = validate(cfg, EXPANDED_POLICIES)
        failures = {x['ID'] for x in result['results'] if x['Status'] == 'FAIL'}
        self.assertIn('OPS-01', failures)
        self.assertIn('OPS-03', failures)

if __name__ == '__main__': unittest.main()
