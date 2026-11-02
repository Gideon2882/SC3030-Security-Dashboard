"""Small, transparent static checker for a deliberately limited Cisco IOS ACL subset.

This is NOT a Cisco parser, Batfish replacement, network emulator, or a safety proof.
It models ordered extended IPv4 ACL entries on directly-connected interfaces.
"""
from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from typing import Optional
import re


@dataclass(frozen=True)
class ACE:
    action: str
    protocol: str
    source: IPv4Network
    destination: IPv4Network
    destination_port: Optional[int]
    original: str


@dataclass
class Interface:
    name: str
    ipv4: Optional[IPv4Interface] = None
    incoming_acl: Optional[str] = None
    outgoing_acl: Optional[str] = None


@dataclass
class ParsedConfig:
    interfaces: dict[str, Interface]
    acls: dict[str, list[ACE]]
    errors: list[str]


@dataclass(frozen=True)
class PolicyTest:
    identifier: str
    group: str
    name: str
    source: str
    destination: str
    protocol: str
    destination_port: int
    expected: str


POLICIES = [
    PolicyTest('SEC-01', 'Security', 'Guest must not SSH to server', '192.168.20.10', '10.0.0.10', 'tcp', 22, 'DENY'),
    PolicyTest('SEC-02', 'Security', 'Guest must not SSH to staff PC', '192.168.20.10', '192.168.10.10', 'tcp', 22, 'DENY'),
    PolicyTest('OPS-01', 'Operational safety', 'Guest must access DNS service', '192.168.20.10', '10.0.0.10', 'udp', 53, 'ALLOW'),
    PolicyTest('OPS-02', 'Operational safety', 'Staff must access HTTPS server', '192.168.10.10', '10.0.0.10', 'tcp', 443, 'ALLOW'),
]


# Original policies: unchanged, for reproducibility of the earlier four-check results.
# Expanded policies: new, stronger requirements defined BEFORE new A/B runs.
EXPANDED_POLICIES = [
    POLICIES[0],
    POLICIES[1],
    PolicyTest('SEC-03', 'Security', 'Other guest host must not SSH to server',
               '192.168.20.11', '10.0.0.10', 'tcp', 22, 'DENY'),
    PolicyTest('SEC-04', 'Security', 'Other guest host must not SSH to staff PC',
               '192.168.20.11', '192.168.10.10', 'tcp', 22, 'DENY'),
    PolicyTest('SEC-05', 'Security', 'Guest must not access server HTTPS',
               '192.168.20.10', '10.0.0.10', 'tcp', 443, 'DENY'),
    POLICIES[2],
    POLICIES[3],
    PolicyTest('OPS-03', 'Operational safety', 'Other guest host must access DNS service',
               '192.168.20.11', '10.0.0.10', 'udp', 53, 'ALLOW'),
]


def _mask_to_network(ip: str, wildcard: str) -> IPv4Network:
    wildcard_int = int(IPv4Address(wildcard))
    subnet_mask_int = (~wildcard_int) & 0xFFFFFFFF
    subnet_mask = str(IPv4Address(subnet_mask_int))
    # ipaddress rejects noncontiguous masks. We intentionally do not support those.
    return IPv4Network(f'{ip}/{subnet_mask}', strict=False)


def _address(tokens: list[str], pos: int) -> tuple[IPv4Network, int]:
    if pos >= len(tokens):
        raise ValueError('Missing ACL address')
    t = tokens[pos].lower()
    if t == 'any':
        return IPv4Network('0.0.0.0/0'), pos + 1
    if t == 'host':
        if pos + 1 >= len(tokens):
            raise ValueError('Missing IP after host')
        return IPv4Network(f'{IPv4Address(tokens[pos + 1])}/32'), pos + 2
    if pos + 1 >= len(tokens):
        raise ValueError('Expected address and wildcard mask')
    return _mask_to_network(tokens[pos], tokens[pos + 1]), pos + 2


def _parse_ace(line: str) -> ACE:
    tokens = line.strip().split()
    if tokens and tokens[0].isdigit():
        tokens.pop(0)
    if len(tokens) < 4:
        raise ValueError('Incomplete ACL entry')
    action = tokens[0].lower()
    protocol = tokens[1].lower()
    if action not in ('permit', 'deny'):
        raise ValueError('Expected permit or deny')
    if protocol not in ('ip', 'tcp', 'udp', 'icmp'):
        raise ValueError(f'Unsupported protocol: {protocol}')
    src, idx = _address(tokens, 2)
    dst, idx = _address(tokens, idx)
    port = None
    if idx < len(tokens) and tokens[idx].lower() == 'eq':
        if protocol not in ('tcp', 'udp'):
            raise ValueError('eq is supported only for TCP/UDP')
        if idx + 1 >= len(tokens):
            raise ValueError('Missing destination port')
        if not tokens[idx + 1].isdigit():
            raise ValueError('Destination port must be numeric, e.g. eq 53')
        port = int(tokens[idx + 1])
        if port < 1 or port > 65535:
            raise ValueError('Destination port out of range')
        idx += 2
    if idx < len(tokens) and tokens[idx].lower() == 'log':
        idx += 1
    if idx != len(tokens):
        raise ValueError(f'Unsupported ACL syntax near: {" ".join(tokens[idx:])}')
    return ACE(action, protocol, src, dst, port, line.strip())


def parse_configuration(text: str) -> ParsedConfig:
    interfaces: dict[str, Interface] = {}
    acls: dict[str, list[ACE]] = {}
    errors: list[str] = []
    mode: Optional[str] = None
    current: Optional[str] = None
    for line_no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith('!'):
            mode = None if line.startswith('!') else mode
            continue
        if line.lower() == 'exit':
            mode = None
            current = None
            continue
        m = re.fullmatch(r'interface\s+(\S+)', line, re.I)
        if m:
            mode, current = 'interface', m.group(1)
            if current in interfaces:
                errors.append(f'Line {line_no}: repeated interface definition: {current}')
            else:
                interfaces[current] = Interface(current)
            continue
        m = re.fullmatch(r'ip access-list extended\s+(\S+)', line, re.I)
        if m:
            mode, current = 'acl', m.group(1)
            if current in acls:
                errors.append(f'Line {line_no}: repeated ACL definition: {current}')
            else:
                acls[current] = []
            continue
        if mode == 'interface' and current:
            iface = interfaces[current]
            m = re.fullmatch(r'ip address\s+(\S+)\s+(\S+)', line, re.I)
            if m:
                try:
                    iface.ipv4 = IPv4Interface(f'{m.group(1)}/{m.group(2)}')
                except ValueError as ex:
                    errors.append(f'Line {line_no}: invalid interface address ({ex})')
                continue
            m = re.fullmatch(r'ip access-group\s+(\S+)\s+(in|out)', line, re.I)
            if m:
                acl, direction = m.group(1), m.group(2).lower()
                if direction == 'in':
                    iface.incoming_acl = acl
                else:
                    iface.outgoing_acl = acl
                continue
            # Other interface directives (description, shutdown, etc.) are NOT interpreted.
            continue
        if mode == 'acl' and current:
            if line.lower().startswith('remark ') or re.fullmatch(r'\d+\s+remark\s+.*', line, re.I):
                continue
            try:
                acls[current].append(_parse_ace(line))
            except ValueError as ex:
                errors.append(f'Line {line_no}, ACL {current}: {ex}')
            continue
        # Ignore hostname, version, service, other global config: not analyzed.
    if not interfaces:
        errors.append('No interface definitions found.')
    for iface in interfaces.values():
        if iface.ipv4 is None:
            errors.append(f'Interface {iface.name} has no valid IPv4 address.')
        for name in (iface.incoming_acl, iface.outgoing_acl):
            if name and name not in acls:
                errors.append(f'Interface {iface.name} references undefined ACL: {name}')
    nets = [(i.name, i.ipv4.network) for i in interfaces.values() if i.ipv4]
    for i, (name1, net1) in enumerate(nets):
        for name2, net2 in nets[i + 1:]:
            if net1.overlaps(net2):
                errors.append(f'Connected networks overlap: {name1} {net1} and {name2} {net2}')
    return ParsedConfig(interfaces, acls, errors)


def _iface_for_ip(cfg: ParsedConfig, address: IPv4Address) -> Optional[Interface]:
    for iface in cfg.interfaces.values():
        if iface.ipv4 and address in iface.ipv4.network:
            return iface
    return None


def _apply_acl(cfg: ParsedConfig, name: str, test: PolicyTest) -> tuple[bool, str]:
    source, destination = IPv4Address(test.source), IPv4Address(test.destination)
    for rule in cfg.acls[name]:
        if source not in rule.source or destination not in rule.destination:
            continue
        if rule.protocol != 'ip' and rule.protocol != test.protocol:
            continue
        if rule.destination_port is not None and rule.destination_port != test.destination_port:
            continue
        return rule.action == 'permit', f'ACL {name}: {rule.original}'
    return False, f'ACL {name}: implicit deny (no matching ACE)'


def evaluate_test(cfg: ParsedConfig, test: PolicyTest) -> dict[str, str | bool]:
    src = _iface_for_ip(cfg, IPv4Address(test.source))
    dst = _iface_for_ip(cfg, IPv4Address(test.destination))
    if src is None or dst is None:
        return {'observed': 'NOT EVALUATED', 'passed': False,
                'evidence': 'One or both test endpoints are outside configured connected networks.'}
    if src.incoming_acl:
        allowed, trace = _apply_acl(cfg, src.incoming_acl, test)
        if not allowed:
            return {'observed': 'DENY', 'passed': test.expected == 'DENY', 'evidence': trace}
        traces = [trace]
    else:
        traces = [f'{src.name}: no inbound ACL']
    if dst.outgoing_acl:
        allowed, trace = _apply_acl(cfg, dst.outgoing_acl, test)
        traces.append(trace)
        if not allowed:
            return {'observed': 'DENY', 'passed': test.expected == 'DENY', 'evidence': '; '.join(traces)}
    else:
        traces.append(f'{dst.name}: no outbound ACL')
    return {'observed': 'ALLOW', 'passed': test.expected == 'ALLOW', 'evidence': '; '.join(traces)}


def validate(text: str, policies: list[PolicyTest] | None = None) -> dict:
    """Evaluate a chosen *predefined* set of flow policies; default remains original 4."""
    if policies is None:
        policies = POLICIES
    cfg = parse_configuration(text)
    if cfg.errors:
        return {'valid_for_model': False, 'errors': cfg.errors, 'results': [], 'passed': 0,
                'total': len(policies), 'security_passed': 0, 'safety_passed': 0,
                'config': cfg}
    results = []
    for test in policies:
        outcome = evaluate_test(cfg, test)
        results.append({
            'ID': test.identifier, 'Category': test.group, 'Policy': test.name,
            'Source': test.source, 'Destination': test.destination,
            'Protocol': f'{test.protocol.upper()}/{test.destination_port}',
            'Expected': test.expected, 'Observed': outcome['observed'],
            'Status': 'PASS' if outcome['passed'] else 'FAIL',
            'Evidence': outcome['evidence'],
        })
    return {
        'valid_for_model': True, 'errors': [], 'results': results,
        'passed': sum(x['Status'] == 'PASS' for x in results),
        'total': len(results),
        'security_passed': sum(x['Status'] == 'PASS' for x in results if x['Category'] == 'Security'),
        'safety_passed': sum(x['Status'] == 'PASS' for x in results if x['Category'] == 'Operational safety'),
        'config': cfg,
    }
