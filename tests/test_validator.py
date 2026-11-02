import unittest
from pathlib import Path
from validator import POLICIES, _parse_ace, validate

ROOT = Path(__file__).resolve().parents[1]


def sample(name):
    return (ROOT / 'samples' / name).read_text(encoding='utf-8')


class ACLValidationTests(unittest.TestCase):
    def test_unsafe_config_fails_guest_ssh_to_server(self):
        report = validate(sample('01_unsafe_missing_deny.txt'))
        self.assertTrue(report['valid_for_model'])
        self.assertEqual(report['passed'], 3)
        self.assertEqual([r['ID'] for r in report['results'] if r['Status']=='FAIL'], ['SEC-01'])

    def test_corrected_passes_all_checks(self):
        report = validate(sample('02_corrected.txt'))
        self.assertTrue(report['valid_for_model'])
        self.assertEqual(report['passed'], len(POLICIES))

    def test_overblock_breaks_legitimate_dns(self):
        report = validate(sample('03_overblocked_dns.txt'))
        self.assertTrue(report['valid_for_model'])
        self.assertEqual(report['passed'], 3)
        self.assertEqual([r['ID'] for r in report['results'] if r['Status']=='FAIL'], ['OPS-01'])

    def test_missing_acl_attachment_does_not_enforce_security(self):
        config = sample('02_corrected.txt').replace(' ip access-group GUEST_IN in', '')
        report = validate(config)
        self.assertEqual([r['ID'] for r in report['results'] if r['Status']=='FAIL'], ['SEC-01', 'SEC-02'])

    def test_undefined_acl_reference_stops_evaluation(self):
        config = sample('02_corrected.txt').replace('ip access-group GUEST_IN in', 'ip access-group MISSING in')
        report = validate(config)
        self.assertFalse(report['valid_for_model'])
        self.assertEqual(report['results'], [])

    def test_unsupported_acl_syntax_stops_evaluation(self):
        config = sample('02_corrected.txt').replace('permit udp 192.168.20.0 0.0.0.255 host 10.0.0.10 eq 53',
                                                       'permit udp 192.168.20.0 0.0.0.255 host 10.0.0.10 eq dns')
        report = validate(config)
        self.assertFalse(report['valid_for_model'])
        self.assertTrue(report['errors'])

    def test_sequence_numbered_ace(self):
        ace = _parse_ace('10 permit udp any host 10.0.0.10 eq 53')
        self.assertEqual(ace.destination_port, 53)

    def test_outbound_acl_supported(self):
        config = sample('02_corrected.txt')
        config = config.replace(' ip address 10.0.0.1 255.255.255.0',
                                ' ip address 10.0.0.1 255.255.255.0\n ip access-group SERVER_OUT out')
        config += '\nip access-list extended SERVER_OUT\n deny tcp host 192.168.10.10 host 10.0.0.10 eq 443\n permit ip any any\n!\n'
        report = validate(config)
        self.assertEqual([r['ID'] for r in report['results'] if r['Status']=='FAIL'], ['OPS-02'])

    def test_config_mutation_changes_evidence(self):
        safe = sample('02_corrected.txt')
        unsafe = safe.replace(' deny ip 192.168.20.0 0.0.0.255 host 10.0.0.10\n', '')
        a, b = validate(safe), validate(unsafe)
        self.assertEqual(a['passed'], 4)
        self.assertEqual(b['passed'], 3)


if __name__ == '__main__':
    unittest.main()
