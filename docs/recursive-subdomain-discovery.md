# Recursive subdomain discovery

`dnsrecon-recursive` performs bounded dictionary discovery below one or more DNS roots. Its default roots are `ntt` and
`ntt.co.jp`, and its default dictionary is `dnsrecon/data/namelist.txt`.

The depth is relative to each root:

- depth 1: `www.ntt`
- depth 2: `dev.www.ntt`
- depth 3: `api.dev.www.ntt`
- depth 4: `internal.api.dev.www.ntt`

Only names that resolve at the current depth become parents for the next depth. This is still not a mathematical guarantee of
complete coverage: a name absent from the dictionary cannot be found, and an existing deep name whose intermediate parent does
not resolve cannot be reached by recursive brute force.

## Plan without DNS queries

Running without `--execute` prints the roots, dictionary size, first-level workload, and safety limits. It performs no DNS queries.

```bash
uv run dnsrecon-recursive
```

## Execute the bounded scan

Use this only for an authorized scope. The default rate is five candidate names per second. Each candidate can issue four DNS
questions (`A`, `AAAA`, `CNAME`, and `NS`).

```bash
uv run dnsrecon-recursive \
  --execute \
  --root ntt \
  --root ntt.co.jp \
  --max-depth 4 \
  --rate 5 \
  --workers 20 \
  --max-resolutions 100000 \
  --output-dir output/ntt-subdomains
```

The program checks each parent with random labels before scanning it. Repeated matching answers are treated as wildcard DNS and
filtered unless the candidate also has an `NS` or `MX` record.

The safety controls are:

- `--rate`: candidate-name resolutions per second; the DNS question rate can be up to the number of configured record types.
- `--max-resolutions`: cumulative candidate and wildcard-probe budget.
- `--max-children-per-parent`: record all children but suppress further recursion when a parent returns an implausibly large set.
- `--max-depth`: relative traversal depth, default 4.

## Resume

The checkpoint is written after every completed parent. Increase `--max-resolutions` and resume when the first budget is exhausted.
Roots, dictionaries, record types, depth, wildcard settings, and nameservers must match the checkpoint.

```bash
uv run dnsrecon-recursive \
  --execute \
  --resume \
  --max-resolutions 250000 \
  --output-dir output/ntt-subdomains
```

## Output

- `results.csv`: one row per DNS record.
- `results.jsonl`: append-only discovery events.
- `summary.json`: current counts and completion status.
- `state.json`: resumable checkpoint.

For broader coverage, repeat `--wordlist` to merge dictionaries. Multi-label entries such as `www.dev` are intentionally skipped
so that each traversal step always represents exactly one DNS label.
