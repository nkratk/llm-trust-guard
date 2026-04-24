"""Extract 10K random non-toxic, non-redacted, first-user-turn prompts from WildChat-1M shard 0.

Usage:
    pip install pyarrow  # version pinned to 21.0.0 for reproducibility
    # Download shard 0 (230 MB):
    curl -L -o /tmp/wildchat/train-00000.parquet \\
        "https://huggingface.co/datasets/allenai/WildChat-1M/resolve/main/data/train-00000-of-00014.parquet"
    python3 tests/adversarial/extract_wildchat.py

Output: /tmp/wildchat/sample10k.jsonl (one JSON per line: content, language, conv_hash).

Reproducibility: seed=42, simple random over non-toxic/non-redacted conversations
with a user-role first turn. Re-running produces the same 10K rows given the same
parquet input. If Allen AI re-shards or edits WildChat-1M, the sample will diverge —
pin the exact parquet shard URL for long-term reproducibility.
"""
import pyarrow.parquet as pq
import random
import json
from collections import Counter
from pathlib import Path

SEED = 42
TARGET = 10_000
IN_PATH = Path("/tmp/wildchat/train-00000.parquet")
OUT_PATH = Path("/tmp/wildchat/sample10k.jsonl")

if not IN_PATH.exists():
    raise SystemExit(
        f"Missing input parquet at {IN_PATH}. Download first:\n"
        f"  curl -L -o {IN_PATH} \\\n"
        f"    https://huggingface.co/datasets/allenai/WildChat-1M/resolve/main/data/train-00000-of-00014.parquet"
    )

t = pq.read_table(str(IN_PATH))
d = t.to_pydict()
print(f"Loaded {t.num_rows} conversations from {IN_PATH}")

candidates = []
for i in range(t.num_rows):
    if d["toxic"][i] or d["redacted"][i]:
        continue
    convo = d["conversation"][i]
    if not convo:
        continue
    first = convo[0]
    if first.get("role") != "user":
        continue
    content = (first.get("content", "") or "").strip()
    if len(content) < 5 or len(content) > 100_000:
        continue
    candidates.append({
        "content": content,
        "language": d["language"][i] or "unknown",
        "conv_hash": d["conversation_hash"][i],
    })

print(f"Clean candidates: {len(candidates)}")

random.seed(SEED)
random.shuffle(candidates)
sample = candidates[:TARGET]

langs = Counter(c["language"] for c in sample)
print("Top 10 languages in sample:")
for lang, count in langs.most_common(10):
    print(f"  {lang}: {count}")

OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
with OUT_PATH.open("w") as f:
    for c in sample:
        f.write(json.dumps(c, ensure_ascii=False) + "\n")
print(f"\nWrote {len(sample)} prompts to {OUT_PATH}")
