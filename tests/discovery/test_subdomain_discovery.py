from pathlib import Path

from dnsrecon.subdomain_discovery import (
    DiscoveryConfig,
    DNSRecord,
    RecursiveSubdomainDiscoverer,
    load_wordlists,
    normalize_root,
)


class MappingResolver:
    def __init__(self, records=None, wildcard=None):
        self.records = records or {}
        self.wildcard = wildcard
        self.calls = []

    def __call__(self, fqdn, record_types):
        self.calls.append((fqdn, record_types))
        if fqdn in self.records:
            return self.records[fqdn]
        if self.wildcard and fqdn.endswith('.example'):
            return self.wildcard
        return []


def make_config(tmp_path: Path, **overrides) -> DiscoveryConfig:
    values = {
        'roots': ('example',),
        'labels': ('a',),
        'record_types': ('A', 'AAAA', 'CNAME', 'NS'),
        'output_dir': tmp_path,
        'max_depth': 4,
        'workers': 2,
        'rate': 0,
        'max_resolutions': 100,
        'max_children_per_parent': 10,
        'wildcard_probes': 2,
        'timeout': 1,
    }
    values.update(overrides)
    return DiscoveryConfig(**values)


def test_normalize_root_removes_boundary_dots():
    assert normalize_root('.NTT.') == 'ntt'
    assert normalize_root('.ntt.co.jp') == 'ntt.co.jp'


def test_load_wordlists_deduplicates_and_keeps_single_labels(tmp_path):
    first = tmp_path / 'first.txt'
    second = tmp_path / 'second.txt'
    first.write_text('www\nAPI\n# comment\nfoo.bar\n')
    second.write_text('api\nmail\ninvalid label\n')

    assert load_wordlists([first, second]) == ('api', 'mail', 'www')


def test_recursive_discovery_reaches_relative_depth_four(tmp_path):
    records = {
        'a.example': [DNSRecord('A', '192.0.2.1')],
        'a.a.example': [DNSRecord('A', '192.0.2.2')],
        'a.a.a.example': [DNSRecord('A', '192.0.2.3')],
        'a.a.a.a.example': [DNSRecord('A', '192.0.2.4')],
    }
    resolver = MappingResolver(records=records)
    discoverer = RecursiveSubdomainDiscoverer(make_config(tmp_path), resolver=resolver)

    summary = discoverer.run()

    assert summary['status'] == 'complete'
    assert summary['findings'] == 4
    assert summary['completed_parents'] == 4
    csv_text = (tmp_path / 'results.csv').read_text()
    assert 'a.a.a.a.example' in csv_text


def test_wildcard_only_answers_are_not_discoveries(tmp_path):
    wildcard = [DNSRecord('A', '192.0.2.99')]
    resolver = MappingResolver(wildcard=wildcard)
    config = make_config(tmp_path, labels=('www', 'mail'))
    discoverer = RecursiveSubdomainDiscoverer(config, resolver=resolver)

    summary = discoverer.run()

    assert summary['findings'] == 0
    assert summary['wildcard_parents'] == 1
    assert summary['completed_parents'] == 1


def test_budget_stops_before_partial_parent_and_can_resume(tmp_path):
    resolver = MappingResolver(records={'a.example': [DNSRecord('A', '192.0.2.1')]})
    first_run = RecursiveSubdomainDiscoverer(make_config(tmp_path, max_depth=1, max_resolutions=2), resolver=resolver)

    first_summary = first_run.run()

    assert first_summary['status'] == 'budget_exhausted'
    assert first_summary['resolution_count'] == 0
    assert first_summary['pending_parents'] == 1
    assert resolver.calls == []

    second_run = RecursiveSubdomainDiscoverer(make_config(tmp_path, max_depth=1, max_resolutions=3), resolver=resolver)
    second_summary = second_run.run(resume=True)

    assert second_summary['status'] == 'complete'
    assert second_summary['findings'] == 1
