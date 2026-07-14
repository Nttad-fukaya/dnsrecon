"""Bounded, recursive subdomain discovery built on DNSRecon's dependencies and wordlists."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import logging
import re
import secrets
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol

import dns.exception
import dns.resolver

LOGGER = logging.getLogger(__name__)
DEFAULT_ROOTS = ('ntt', 'ntt.co.jp')
DEFAULT_RECORD_TYPES = ('A', 'AAAA', 'CNAME', 'NS')
SUPPORTED_RECORD_TYPES = frozenset({'A', 'AAAA', 'CNAME', 'NS', 'MX', 'TXT'})
LABEL_PATTERN = re.compile(r'^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$', re.IGNORECASE)
STATE_VERSION = 1


@dataclass(frozen=True, order=True)
class DNSRecord:
    rtype: str
    value: str


class NameResolver(Protocol):
    def __call__(self, fqdn: str, record_types: tuple[str, ...]) -> list[DNSRecord]: ...


@dataclass(frozen=True)
class ParentTask:
    root: str
    parent: str
    depth: int


@dataclass(frozen=True)
class DiscoveryConfig:
    roots: tuple[str, ...]
    labels: tuple[str, ...]
    record_types: tuple[str, ...]
    output_dir: Path
    max_depth: int = 4
    workers: int = 20
    rate: float = 5.0
    max_resolutions: int = 100_000
    max_children_per_parent: int = 500
    wildcard_probes: int = 3
    timeout: float = 3.0
    nameservers: tuple[str, ...] = ()

    def validate(self) -> None:
        if not self.roots:
            raise ValueError('At least one root domain is required')
        if not self.labels:
            raise ValueError('At least one valid dictionary label is required')
        if not 1 <= self.max_depth <= 10:
            raise ValueError('max_depth must be between 1 and 10')
        if not 1 <= self.workers <= 100:
            raise ValueError('workers must be between 1 and 100')
        if self.rate < 0:
            raise ValueError('rate must be zero or greater')
        if self.max_resolutions < 1:
            raise ValueError('max_resolutions must be positive')
        if self.max_children_per_parent < 1:
            raise ValueError('max_children_per_parent must be positive')
        if not 2 <= self.wildcard_probes <= 10:
            raise ValueError('wildcard_probes must be between 2 and 10')
        if self.timeout <= 0:
            raise ValueError('timeout must be positive')
        unsupported = set(self.record_types) - SUPPORTED_RECORD_TYPES
        if unsupported:
            raise ValueError(f'Unsupported record types: {sorted(unsupported)}')

    def fingerprint(self) -> str:
        stable_config = {
            'roots': self.roots,
            'labels': self.labels,
            'record_types': self.record_types,
            'max_depth': self.max_depth,
            'max_children_per_parent': self.max_children_per_parent,
            'wildcard_probes': self.wildcard_probes,
            'nameservers': self.nameservers,
        }
        payload = json.dumps(stable_config, ensure_ascii=True, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(payload.encode()).hexdigest()


class DnspythonResolver:
    """Create one resolver per worker thread and return normalized DNS records."""

    def __init__(self, timeout: float, nameservers: tuple[str, ...] = ()) -> None:
        self.timeout = timeout
        self.nameservers = nameservers
        self._local = threading.local()

    def _get_resolver(self) -> dns.resolver.Resolver:
        resolver = getattr(self._local, 'resolver', None)
        if resolver is None:
            resolver = dns.resolver.Resolver(configure=not self.nameservers)
            if self.nameservers:
                resolver.nameservers = list(self.nameservers)
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            self._local.resolver = resolver
        return resolver

    def __call__(self, fqdn: str, record_types: tuple[str, ...]) -> list[DNSRecord]:
        resolver = self._get_resolver()
        records: set[DNSRecord] = set()
        for record_type in record_types:
            try:
                answer = resolver.resolve(fqdn, record_type, search=False, raise_on_no_answer=False)
            except (dns.exception.DNSException, OSError):
                continue
            if answer.rrset is None:
                continue
            for rdata in answer:
                records.add(DNSRecord(record_type, rdata.to_text().rstrip('.')))
        return sorted(records)


class RateLimiter:
    """Limit candidate-name resolutions; each resolution can issue several DNS questions."""

    def __init__(self, rate: float) -> None:
        self.interval = 0.0 if rate == 0 else 1.0 / rate
        self.next_time = 0.0
        self.lock = threading.Lock()

    def wait(self) -> None:
        if self.interval == 0:
            return
        with self.lock:
            now = time.monotonic()
            delay = self.next_time - now
            if delay > 0:
                time.sleep(delay)
                now = time.monotonic()
            self.next_time = max(now, self.next_time) + self.interval


class RecursiveSubdomainDiscoverer:
    def __init__(self, config: DiscoveryConfig, resolver: NameResolver | None = None) -> None:
        config.validate()
        self.config = config
        self.resolver = resolver or DnspythonResolver(config.timeout, config.nameservers)
        self.rate_limiter = RateLimiter(config.rate)
        self.state_path = config.output_dir / 'state.json'
        self.events_path = config.output_dir / 'results.jsonl'
        self.csv_path = config.output_dir / 'results.csv'
        self.summary_path = config.output_dir / 'summary.json'

    def plan(self) -> dict[str, object]:
        label_count = len(self.config.labels)
        theoretical_candidates = len(self.config.roots) * sum(label_count**depth for depth in range(1, self.config.max_depth + 1))
        first_level_resolutions = len(self.config.roots) * (label_count + self.config.wildcard_probes)
        return {
            'roots': list(self.config.roots),
            'dictionary_labels': label_count,
            'max_depth': self.config.max_depth,
            'record_types': list(self.config.record_types),
            'first_level_resolutions': first_level_resolutions,
            'dns_questions_per_resolution': len(self.config.record_types),
            'theoretical_candidates_without_pruning': theoretical_candidates,
            'max_resolutions': self.config.max_resolutions,
            'rate_resolutions_per_second': self.config.rate,
            'max_children_per_parent': self.config.max_children_per_parent,
            'output_dir': str(self.config.output_dir),
        }

    def run(self, resume: bool = False) -> dict[str, object]:
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
        self.events_path.touch(exist_ok=True)
        state = self._load_or_create_state(resume)
        pending = deque(ParentTask(**task) for task in state['pending'])
        completed = set(state['completed'])

        status = 'complete'
        while pending:
            task = pending[0]
            required_resolutions = len(self.config.labels) + self.config.wildcard_probes
            if state['resolution_count'] + required_resolutions > self.config.max_resolutions:
                status = 'budget_exhausted'
                break

            pending.popleft()
            children, wildcard_records = self._scan_parent(task)
            state['resolution_count'] += required_resolutions
            if wildcard_records:
                state['wildcards'][task.parent] = [asdict(record) for record in wildcard_records]

            new_children = []
            for fqdn, records in children:
                if fqdn not in state['findings']:
                    finding = {
                        'name': fqdn,
                        'root': task.root,
                        'parent': task.parent,
                        'depth': task.depth,
                        'records': [asdict(record) for record in records],
                    }
                    state['findings'][fqdn] = finding
                    self._append_event(finding)
                new_children.append(fqdn)

            if task.depth < self.config.max_depth:
                if len(new_children) <= self.config.max_children_per_parent:
                    known_tasks = completed | {self._task_key(existing) for existing in pending}
                    for child in new_children:
                        child_task = ParentTask(root=task.root, parent=child, depth=task.depth + 1)
                        if self._task_key(child_task) not in known_tasks:
                            pending.append(child_task)
                            known_tasks.add(self._task_key(child_task))
                else:
                    state['suppressed_recursion'].append(
                        {
                            'parent': task.parent,
                            'depth': task.depth,
                            'children': len(new_children),
                            'limit': self.config.max_children_per_parent,
                        }
                    )
                    LOGGER.warning(
                        'Suppressing recursion below %s: %d children exceed the limit of %d',
                        task.parent,
                        len(new_children),
                        self.config.max_children_per_parent,
                    )

            completed.add(self._task_key(task))
            state['completed'] = sorted(completed)
            state['pending'] = [asdict(item) for item in pending]
            self._write_state(state)
            self._write_reports(state, status='running' if pending else 'complete')

        state['pending'] = [asdict(item) for item in pending]
        self._write_state(state)
        return self._write_reports(state, status=status)

    def _scan_parent(self, task: ParentTask) -> tuple[list[tuple[str, list[DNSRecord]]], list[DNSRecord]]:
        wildcard_records = self._detect_wildcard(task.parent)
        wildcard_signature = set(wildcard_records)
        candidates = [f'{label}.{task.parent}' for label in self.config.labels]
        LOGGER.info('Scanning %s at relative depth %d (%d candidates)', task.parent, task.depth, len(candidates))

        children = []
        with ThreadPoolExecutor(max_workers=self.config.workers) as executor:
            for fqdn, records in zip(candidates, executor.map(self._resolve_name, candidates), strict=True):
                if not records:
                    continue
                if self._is_wildcard_only(records, wildcard_signature):
                    continue
                children.append((fqdn, records))
        return children, wildcard_records

    def _detect_wildcard(self, parent: str) -> list[DNSRecord]:
        probe_results = []
        for _ in range(self.config.wildcard_probes):
            probe = f'zz-{secrets.token_hex(8)}.{parent}'
            records = self._resolve_name(probe)
            if records:
                probe_results.append(records)
        if len(probe_results) < 2:
            return []
        return sorted({record for records in probe_results for record in records})

    def _resolve_name(self, fqdn: str) -> list[DNSRecord]:
        self.rate_limiter.wait()
        try:
            return self.resolver(fqdn, self.config.record_types)
        except Exception as error:
            LOGGER.warning('Resolution failed for %s: %s', fqdn, error)
            return []

    @staticmethod
    def _is_wildcard_only(records: list[DNSRecord], wildcard_signature: set[DNSRecord]) -> bool:
        if not wildcard_signature:
            return False
        if any(record.rtype in {'NS', 'MX'} for record in records):
            return False
        return set(records).issubset(wildcard_signature)

    def _load_or_create_state(self, resume: bool) -> dict[str, object]:
        if self.state_path.exists():
            if not resume:
                raise FileExistsError(f'{self.state_path} already exists; use --resume or choose another output directory')
            state = json.loads(self.state_path.read_text())
            if state.get('version') != STATE_VERSION:
                raise ValueError('Unsupported checkpoint version')
            if state.get('fingerprint') != self.config.fingerprint():
                raise ValueError('Checkpoint configuration does not match the current roots, dictionary, or scan settings')
            return state

        return {
            'version': STATE_VERSION,
            'fingerprint': self.config.fingerprint(),
            'pending': [asdict(ParentTask(root=root, parent=root, depth=1)) for root in self.config.roots],
            'completed': [],
            'resolution_count': 0,
            'findings': {},
            'wildcards': {},
            'suppressed_recursion': [],
        }

    @staticmethod
    def _task_key(task: ParentTask) -> str:
        return f'{task.root}|{task.parent}|{task.depth}'

    def _append_event(self, finding: dict[str, object]) -> None:
        with self.events_path.open('a') as output:
            output.write(json.dumps(finding, ensure_ascii=False, sort_keys=True) + '\n')

    def _write_state(self, state: dict[str, object]) -> None:
        self._atomic_json_write(self.state_path, state)

    def _write_reports(self, state: dict[str, object], status: str) -> dict[str, object]:
        findings = list(state['findings'].values())
        rows = []
        for finding in sorted(findings, key=lambda item: (item['root'], item['depth'], item['name'])):
            for record in finding['records']:
                rows.append(
                    {
                        'name': finding['name'],
                        'root': finding['root'],
                        'parent': finding['parent'],
                        'depth': finding['depth'],
                        'type': record['rtype'],
                        'value': record['value'],
                    }
                )
        with self.csv_path.open('w', newline='') as output:
            writer = csv.DictWriter(output, fieldnames=['name', 'root', 'parent', 'depth', 'type', 'value'])
            writer.writeheader()
            writer.writerows(rows)

        summary = {
            'status': status,
            'roots': list(self.config.roots),
            'max_depth': self.config.max_depth,
            'resolution_count': state['resolution_count'],
            'max_resolutions': self.config.max_resolutions,
            'findings': len(findings),
            'record_rows': len(rows),
            'pending_parents': len(state['pending']),
            'completed_parents': len(state['completed']),
            'wildcard_parents': len(state['wildcards']),
            'suppressed_recursion': state['suppressed_recursion'],
            'results_csv': str(self.csv_path),
            'results_jsonl': str(self.events_path),
            'checkpoint': str(self.state_path),
        }
        self._atomic_json_write(self.summary_path, summary)
        return summary

    @staticmethod
    def _atomic_json_write(path: Path, data: dict[str, object]) -> None:
        temporary = path.with_suffix(path.suffix + '.tmp')
        temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + '\n')
        temporary.replace(path)


def normalize_root(value: str) -> str:
    root = value.strip().strip('.').lower()
    if not root:
        raise ValueError('Root domain cannot be empty')
    labels = root.split('.')
    if any(not LABEL_PATTERN.fullmatch(label) for label in labels):
        raise ValueError(f'Invalid root domain: {value}')
    if len(root) > 253:
        raise ValueError(f'Root domain is too long: {value}')
    return root


def load_wordlists(paths: list[Path]) -> tuple[str, ...]:
    labels = set()
    for path in paths:
        if not path.is_file():
            raise FileNotFoundError(f'Wordlist not found: {path}')
        for raw_line in path.read_text(errors='replace').splitlines():
            label = raw_line.strip().lower()
            if not label or label.startswith('#'):
                continue
            if '.' in label or not LABEL_PATTERN.fullmatch(label):
                continue
            labels.add(label)
    return tuple(sorted(labels))


def parse_record_types(value: str) -> tuple[str, ...]:
    record_types = tuple(dict.fromkeys(part.strip().upper() for part in value.split(',') if part.strip()))
    unsupported = set(record_types) - SUPPORTED_RECORD_TYPES
    if not record_types or unsupported:
        raise argparse.ArgumentTypeError(f'Record types must be a comma-separated subset of {sorted(SUPPORTED_RECORD_TYPES)}')
    return record_types


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='Bounded recursive subdomain discovery for DNSRecon')
    parser.add_argument('--root', action='append', help='Root domain; repeat for multiple roots. Defaults to ntt and ntt.co.jp')
    parser.add_argument('--wordlist', action='append', type=Path, help='Single-label dictionary; repeat to merge dictionaries')
    parser.add_argument('--record-types', type=parse_record_types, default=DEFAULT_RECORD_TYPES)
    parser.add_argument('--max-depth', type=int, default=4, help='Relative depth below each root')
    parser.add_argument('--workers', type=int, default=20)
    parser.add_argument(
        '--rate', type=float, default=5.0, help='Candidate resolutions per second; each uses several DNS questions'
    )
    parser.add_argument('--max-resolutions', type=int, default=100_000)
    parser.add_argument('--max-children-per-parent', type=int, default=500)
    parser.add_argument('--wildcard-probes', type=int, default=3)
    parser.add_argument('--timeout', type=float, default=3.0)
    parser.add_argument('--nameserver', action='append', default=[])
    parser.add_argument('--output-dir', type=Path, default=Path('output/ntt-subdomains'))
    parser.add_argument('--execute', action='store_true', help='Perform DNS queries. Without this option only a plan is printed')
    parser.add_argument('--resume', action='store_true', help='Resume from output-dir/state.json')
    parser.add_argument('--verbose', action='store_true')
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

    try:
        roots = tuple(dict.fromkeys(normalize_root(root) for root in (args.root or DEFAULT_ROOTS)))
        default_wordlist = Path(__file__).with_name('data') / 'namelist.txt'
        labels = load_wordlists(args.wordlist or [default_wordlist])
        config = DiscoveryConfig(
            roots=roots,
            labels=labels,
            record_types=args.record_types,
            output_dir=args.output_dir,
            max_depth=args.max_depth,
            workers=args.workers,
            rate=args.rate,
            max_resolutions=args.max_resolutions,
            max_children_per_parent=args.max_children_per_parent,
            wildcard_probes=args.wildcard_probes,
            timeout=args.timeout,
            nameservers=tuple(args.nameserver),
        )
        discoverer = RecursiveSubdomainDiscoverer(config)
        if not args.execute:
            print(json.dumps(discoverer.plan(), ensure_ascii=False, indent=2))
            return 0
        summary = discoverer.run(resume=args.resume)
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0
    except (FileExistsError, FileNotFoundError, ValueError) as error:
        parser.error(str(error))
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
