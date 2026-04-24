# Adversarial benchmarks

Reproduces the numbers in [`RESULTS-v4.19.0.md`](./RESULTS-v4.19.0.md).

## Pipeline

### 1. In-distribution delta (jailbreak_llms / Giskard / Compass CTF)

```bash
# Uses corpora already checked into tests/adversarial/datasets/
npx tsx tests/adversarial/v419-delta-benchmark.ts
# -> v419-delta-results.json
```

### 2. WildChat-1M FPR (out-of-distribution)

```bash
# Fetch shard 0 of WildChat-1M (allenai, ODC-BY, 230 MB)
mkdir -p /tmp/wildchat
curl -L -o /tmp/wildchat/train-00000.parquet \
    "https://huggingface.co/datasets/allenai/WildChat-1M/resolve/main/data/train-00000-of-00014.parquet"

# Sample 10K non-toxic first-user-turns (seed=42)
pip install 'pyarrow==21.0.0'
python3 tests/adversarial/extract_wildchat.py
# -> /tmp/wildchat/sample10k.jsonl

# Measure FPR under Pipeline A and Pipeline B
npx tsx tests/adversarial/wildchat-fpr.ts
# -> wildchat-fpr-results.json

# Dump all blocked prompts for label-noise analysis
npx tsx tests/adversarial/wildchat-block-dump.ts
# -> /tmp/wildchat/pipelineA-blocks.jsonl, pipelineB-blocks.jsonl

# Classify with canonical heuristic + select 50-sample for hand adjudication
python3 tests/adversarial/classify_wildchat_blocks.py
# -> /tmp/wildchat/classified-blocks-{A,B}.jsonl, hand-label-sample.jsonl
```

Hand labels for the 50-sample (single annotator, project maintainer) are committed at [`hand-labels.json`](./hand-labels.json). Adjudication rubric + limitations are in that file's `meta` block.

## Corpus notes

- `datasets/jailbreak_llms/` — Shen et al. 2024 (CCS'24) — December 25, 2023 snapshot. 16 months old at the run date.
- `datasets/prompt-injections/` — Giskard open-source scanner (release date unknown).
- `datasets/prompt_injection_research/` — Compass CTF (release date unknown).
- `WildChat-1M` — Allen AI 2024 release, ODC-BY. Non-toxic / non-redacted conversations filtered upstream. Pre-filter does NOT remove prompt-injection attempts, only moderation-flagged content.

## Honesty constraints

See [`../../CLAUDE.md`](../../CLAUDE.md) for the project's honesty rules. In particular:
- Never claim detection percentages without measurement.
- Never claim improvement without a baseline measurement.
- Distinguish curated test suites from real-world data.
- Flag data older than 12 months.

If you re-run these benchmarks with modified regex patterns, update `RESULTS-v4.19.0.md` with the new numbers. Do not silently bake stale numbers into the README.
