#!/usr/bin/env python3
from __future__ import annotations

import json
import pathlib
import sys
import time
import urllib.request

from p2c.evaluation.tier_second_coder import (
    SYSTEM,
    author_binary,
    build_prompt,
    parse_label,
    score_binary,
)
from p2c.mapping.catalog import load_default_index

ROOT = pathlib.Path(__file__).resolve().parent.parent
OVERLAY = ROOT / "taxonomy" / "release" / "sort_overlay.json"
ARTIFACT = ROOT / "evaluation" / "tier_second_coder.json"
CKPT = pathlib.Path(
    "evaluation/checkpoints/tier_second_coder_ckpt.json"
)

MODEL = "qwen2.5:7b"
MODEL_DIGEST = "845dbda0ea48ed749caafd9e6037047aa19acfcfd82e704d7ca97d631a0b697e"
HOST = "http://127.0.0.1:11434"
SEED = 1337
NUM_CTX = 4096
CALL_TIMEOUT = 300.0


def _overlay_rows() -> list[dict]:
    return json.loads(OVERLAY.read_text(encoding="utf-8"))["controls"]


def _generate(prompt: str) -> str:
    body = {
        "model": MODEL,
        "system": SYSTEM,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.0,
            "seed": SEED,
            "num_predict": 8,
            "num_ctx": NUM_CTX,
            "keep_alive": "30m",
        },
    }
    req = urllib.request.Request(
        f"{HOST}/api/generate",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=CALL_TIMEOUT) as resp:
        return str(json.loads(resp.read()).get("response", ""))


def _load_ckpt() -> dict:
    if CKPT.is_file():
        return json.loads(CKPT.read_text(encoding="utf-8"))
    return {"labels": {}, "raw": {}}


def _save_ckpt(ckpt: dict) -> None:
    CKPT.parent.mkdir(parents=True, exist_ok=True)
    CKPT.write_text(json.dumps(ckpt, indent=2), encoding="utf-8")


def run(max_rows: int | None) -> None:
    index = load_default_index()
    rows = _overlay_rows()
    ckpt = _load_ckpt()
    done = 0
    for row in rows:
        cid = row["id"]
        if cid in ckpt["labels"]:
            continue
        if max_rows is not None and done >= max_rows:
            break
        entry = index.require(cid)
        t0 = time.time()
        try:
            resp = _generate(build_prompt(entry))
        except Exception as exc:
            print(f"  err {cid}: {str(exc)[:80]}", flush=True)
            break
        label = parse_label(resp)
        ckpt["labels"][cid] = label
        ckpt["raw"][cid] = resp.strip()[:40]
        _save_ckpt(ckpt)
        done += 1
        print(f"  {cid:10s} -> {label!s:6s}  {time.time() - t0:5.1f}s", flush=True)
    total = len(ckpt["labels"])
    print(f"{total}/{len(rows)} rows classified" + ("" if total == len(rows) else "; run again"), flush=True)
    if total == len(rows):
        print("all rows done; run `score` next", flush=True)


def score() -> None:
    rows = _overlay_rows()
    ckpt = _load_ckpt()
    labels = ckpt.get("labels", {})
    if len(labels) != len(rows):
        raise SystemExit(f"incomplete ({len(labels)}/{len(rows)}); run `run` first")
    paired = [(row["id"], author_binary(row["tier"]), labels[row["id"]]) for row in rows]
    result = score_binary(paired)
    kind_by_id = {row["id"]: row["kind"] for row in rows}
    dis_ids = {d["id"] for d in result.disagreements}
    breakdown = {
        "author_scan_model_answer": result.confusion["scan_answer"],
        "author_answer_model_scan": result.confusion["answer_scan"],
        "umbrella_main": sum(1 for cid in dis_ids if kind_by_id[cid] == "main"),
        "leaf": sum(1 for cid in dis_ids if kind_by_id[cid] != "main"),
    }
    n_agree = result.confusion["scan_scan"] + result.confusion["answer_answer"]
    artifact = {
        "model": MODEL,
        "model_digest": MODEL_DIGEST,
        "task": "independent second reading of the primary observation boundary: scan-provable "
        "(author Tier 1) vs must-answer (author Tier 2/3)",
        "boundary": "binary",
        "n_rows": result.n_rows,
        "n_scored": result.n_scored,
        "n_unparseable": result.n_unparseable,
        "n_agree": n_agree,
        "agreement_rate": round(result.agreement_rate, 4),
        "cohen_kappa": round(result.cohen_kappa, 4),
        "n_scan_author": result.n_scan_author,
        "n_scan_model": result.n_scan_model,
        "confusion": result.confusion,
        "disagreement_set": result.disagreements,
        "n_disagreements": len(result.disagreements),
        "disagreement_breakdown": breakdown,
        "note": "Weak stability signal, NOT validation and NOT a substitute for the expert panel. "
        "One representative open-weight model (qwen2.5:7b, the paper's baseline ladder model) reads "
        "each control's own public text and picks scan-provable vs must-answer. This is the coarse "
        "observation boundary, a much coarser judgment than the fine 31-check to subcontrol mapping "
        "the baselines fail at (best micro F1 0.60), so agreement here says nothing about that fine "
        "mapping. The durable output is the published disagreement set, which surfaces the "
        "contestable rows. Opt-in, not part of `make reproduce`; qwen2.5:14b would not load in a "
        "foreground budget on this 4-core GPU-less host. No NCA control text is in this artifact.",
        "provenance": {
            "seed": SEED,
            "temperature": 0.0,
            "num_ctx": NUM_CTX,
            "n_rows": len(rows),
            "host": "CPU-only, 4 cores (arm64)",
            "run_date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
    }
    ARTIFACT.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    print(f"agreement={artifact['agreement_rate']:.4f}  kappa={artifact['cohen_kappa']:.4f}")
    print(f"scan: author={result.n_scan_author} model={result.n_scan_model}  confusion={result.confusion}")
    print(f"disagreements={artifact['n_disagreements']} (unparseable {result.n_unparseable})")
    print(f"artifact -> {ARTIFACT}")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "run"
    if cmd == "run":
        cap = None
        if "--max" in sys.argv:
            cap = int(sys.argv[sys.argv.index("--max") + 1])
        run(cap)
    elif cmd == "score":
        score()
    else:
        raise SystemExit(f"unknown command {cmd}")
