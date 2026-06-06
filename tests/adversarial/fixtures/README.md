# WildChat FPR fixture

`wildchat-sample10k.jsonl` — a deterministic 10,000-prompt sample of real
ChatGPT first-user-turns used to measure the Sanitizer+Encoder false-positive
rate (Pipeline A).

- **Source:** [`allenai/WildChat-1M`](https://huggingface.co/datasets/allenai/WildChat-1M),
  shard 0 (`train-00000-of-00014.parquet`).
- **License:** ODC-BY (attribution required — this notice satisfies it).
- **Selection:** non-toxic, non-redacted, user-role first turns; `seed=42`;
  simple random; `5 <= len(content) <= 100000`. Reproduce with
  `tests/adversarial/extract_wildchat.py`.
- **Tracked via Git LFS** (see `.gitattributes`). Excluded from the published
  npm package (`files` allowlist ships only `dist/` + docs), so consumers never
  download it.

This is real-world consumer traffic, **not** a curated test suite. The curated
benign-context probe lives in `tests/benign-context.test.ts`.
