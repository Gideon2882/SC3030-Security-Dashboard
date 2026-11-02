import unittest
from pathlib import Path
from validator import POLICIES, EXPANDED_POLICIES, validate

ROOT = Path(__file__).resolve().parents[1]

class FourExperimentReproductionTests(unittest.TestCase):
    def test_four_saved_configs_reproduce_scores(self):
        cases = [
            ('A_original_4_requirements.txt', 4, 5, {'SEC-03', 'SEC-04', 'SEC-05'}),
            ('B_original_4_requirements.txt', 4, 5, {'SEC-03', 'SEC-04', 'SEC-05'}),
            ('A_basic_8_requirements.txt', 4, 8, set()),
            ('B_guided_8_requirements.txt', 4, 8, set()),
        ]
        for name, expected_four, expected_eight, expected_failures in cases:
            with self.subTest(name=name):
                text = (ROOT / 'experiment_configs' / name).read_text(encoding='utf-8')
                first = validate(text, POLICIES)
                second = validate(text, EXPANDED_POLICIES)
                self.assertTrue(first['valid_for_model'])
                self.assertTrue(second['valid_for_model'])
                self.assertEqual(first['passed'], expected_four)
                self.assertEqual(second['passed'], expected_eight)
                self.assertEqual({x['ID'] for x in second['results'] if x['Status']=='FAIL'}, expected_failures)
                self.assertEqual(second['safety_passed'], 3)

if __name__ == '__main__':
    unittest.main()
