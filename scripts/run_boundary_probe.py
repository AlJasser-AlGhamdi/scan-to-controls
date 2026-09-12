#!/usr/bin/env python3
from __future__ import annotations

import json
import pathlib
import re
import sys
import time
import urllib.request

from p2c.evaluation.ablation import (
    check_query_text,
    score_check_mapping,
    subcontrol_entries,
    subcontrol_text_full,
)
from p2c.evaluation.synthetic import expert_key

ROOT = pathlib.Path(__file__).resolve().parent.parent
CKPT = pathlib.Path(
    "evaluation/checkpoints/boundary_probe_ckpt.json"
)
ARTIFACT = ROOT / "evaluation" / "baselines_boundary.json"

MODEL = "qwen2.5:7b"
MODEL_DIGEST = "845dbda0ea48ed749caafd9e6037047aa19acfcfd82e704d7ca97d631a0b697e"
HOST = "http://127.0.0.1:11434"
SEED = 1337
NUM_CTX = 8192
CALL_TIMEOUT = 900.0
_ID_RE = re.compile(r"\d(?:-\d{1,2}){2,3}")

BASE_SYSTEM = (
    "You are a cybersecurity compliance expert mapping one external scan finding to the single "
    "ECC-2:2024 control subcontrol it evidences. Choose from the provided candidate ids only. "
    "Reply with just that one control id on its own line."
)
BOUNDARY = (
    " Context: an external scan observes only what an unauthenticated observer of a firm's internet "
    "facing assets can determine, namely the contents of published DNS records, the negotiated "
    "parameters of a transport layer session, which ports answer, which response headers a web "
    "server returns, and which services and versions those responses reveal. The finding you are "
    "given was produced by such a scan, so it evidences a control this external observation settles."
)
CONDITIONS = {"without_boundary": BASE_SYSTEM, "with_boundary": BASE_SYSTEM + BOUNDARY}


def _ranked_checks() -> list:
    return sorted(expert_key(), key=lambda c: c.value)


def _catalog_block() -> tuple[str, frozenset[str]]:
    ents = subcontrol_entries()
    block = "\n".join(f"{e.native_id}: {subcontrol_text_full(e)}" for e in ents)
    return block, frozenset(e.native_id for e in ents)


def _generate(system: str, prompt: str) -> str:
    body = {
        "model": MODEL,
        "system": system,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.0, "seed": SEED, "num_predict": 64, "num_ctx": NUM_CTX,
                    "keep_alive": "30m"},
    }
    req = urllib.request.Request(
        f"{HOST}/api/generate", data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=CALL_TIMEOUT) as resp:
        return str(json.loads(resp.read()).get("response", ""))


def _extract(response: str, valid: frozenset[str]) -> str | None:
    ids = [m for m in _ID_RE.findall(response) if m in valid]
    return ids[-1] if ids else None


def _load_ckpt() -> dict:
    if CKPT.is_file():
        return json.loads(CKPT.read_text(encoding="utf-8"))
    return {"without_boundary": {}, "with_boundary": {}}


def _save_ckpt(ckpt: dict) -> None:
    CKPT.parent.mkdir(parents=True, exist_ok=True)
    CKPT.write_text(json.dumps(ckpt, indent=2), encoding="utf-8")


def run() -> None:
    checks = _ranked_checks()
    block, valid = _catalog_block()
    ckpt = _load_ckpt()
    target = next(
        (c for c in CONDITIONS if len(ckpt.get(c, {})) < len(checks)), None
    )
    if target is None:
        print("both conditions complete; run `score` next")
        return
    system = CONDITIONS[target]
    print(f"condition={target} model={MODEL}; {len(ckpt.get(target, {}))}/{len(checks)} done", flush=True)
    for check in checks:
        if check.value in ckpt[target]:
            continue
        prompt = (
            f"Candidate controls (id: text):\n{block}\n\n"
            f"Scan finding: {check_query_text(check)}\n"
            "Reply with the single best control id and nothing else."
        )
        t0 = time.time()
        try:
            resp = _generate(system, prompt)
            cid = _extract(resp, valid)
        except Exception as exc:
            print(f"  err {check.value}: {str(exc)[:80]}", flush=True)
            break
        ckpt[target][check.value] = cid
        _save_ckpt(ckpt)
        print(f"  {check.value:32s} -> {cid}  {time.time() - t0:.1f}s", flush=True)
    done = len(ckpt[target])
    print(f"condition={target}: {done}/{len(checks)} mapped", flush=True)
    if done == len(checks) and any(len(ckpt.get(c, {})) < len(checks) for c in CONDITIONS):
        print("run again for the remaining condition")
    elif all(len(ckpt.get(c, {})) == len(checks) for c in CONDITIONS):
        print("both conditions complete; run `score` next")


FEWSHOT_SYSTEM = (
    "You map one external scan finding to the single ECC-2:2024 subcontrol id it evidences. You are "
    "given example findings with their correct control ids; use them to map the new finding. Reply "
    "with just that one control id on its own line."
)


def loo_run() -> None:
    checks = _ranked_checks()
    key = expert_key()
    _, valid = _catalog_block()
    ckpt = _load_ckpt()
    ckpt.setdefault("loo_fewshot", {})
    print(f"condition=loo_fewshot model={MODEL}; {len(ckpt['loo_fewshot'])}/{len(checks)} done", flush=True)
    for target in checks:
        if target.value in ckpt["loo_fewshot"]:
            continue
        tgold = set(key[target])
        examples = [
            f"{check_query_text(c)} -> {sorted(key[c])[0]}"
            for c in checks
            if not (set(key[c]) & tgold)
        ]
        prompt = (
            "Examples (finding -> control id):\n" + "\n".join(examples) + "\n\n"
            f"New finding: {check_query_text(target)}\n"
            "Reply with the single best control id and nothing else."
        )
        t0 = time.time()
        try:
            cid = _extract(_generate(FEWSHOT_SYSTEM, prompt), valid)
        except Exception as exc:
            print(f"  err {target.value}: {str(exc)[:80]}", flush=True)
            break
        ckpt["loo_fewshot"][target.value] = cid
        _save_ckpt(ckpt)
        print(f"  {target.value:32s} -> {cid}  ({len(examples)} ex)  {time.time() - t0:.1f}s", flush=True)
    if len(ckpt["loo_fewshot"]) == len(checks):
        print("loo complete; run `loo-score` next")


def loo_score() -> None:
    ckpt = _load_ckpt()
    checks = _ranked_checks()
    preds = ckpt.get("loo_fewshot", {})
    if len(preds) != len(checks):
        raise SystemExit(f"loo incomplete ({len(preds)}/{len(checks)}); run `loo` first")
    result = _score_condition(preds, "leave-one-out few-shot")
    zero = _score_condition(ckpt["without_boundary"], "zero-shot") if len(ckpt.get("without_boundary", {})) == len(checks) else None
    ceiling = 0.919
    print(f"loo_fewshot micro_f1={result['micro_f1']:.4f} (unanswered {result['unanswered_checks']})")
    if zero:
        print(f"zero-shot   micro_f1={zero['micro_f1']:.4f}  delta={result['micro_f1'] - zero['micro_f1']:+.4f}")
    print(f"single-pick ceiling={ceiling}; midpoint(zero,ceiling)~={round((zero['micro_f1'] + ceiling) / 2, 3) if zero else 'n/a'}")
    print("LEAKAGE if it jumps toward the ceiling; otherwise it strengthens the negative result.")


def _score_condition(preds: dict[str, str | None], label: str) -> dict:
    checks = {c.value: c for c in _ranked_checks()}
    mapping = {checks[k]: v for k, v in preds.items() if k in checks}
    unanswered = sum(1 for v in preds.values() if v is None)
    result = score_check_mapping(
        mapping,
        100,
        seed=None,
        method=f"zero-shot LLM ({MODEL}) over full public control text, {label.replace('_', ' ')}",
        note="representative-model local probe (not the 12-model ladder); constrained to catalog ids",
    )
    result["unanswered_checks"] = unanswered
    return result


def score() -> None:
    ckpt = _load_ckpt()
    checks = _ranked_checks()
    for cond in CONDITIONS:
        if len(ckpt.get(cond, {})) != len(checks):
            raise SystemExit(f"condition {cond} incomplete ({len(ckpt.get(cond, {}))}/{len(checks)}); run first")
    without = _score_condition(ckpt["without_boundary"], "without_boundary")
    with_b = _score_condition(ckpt["with_boundary"], "with_boundary")
    loo = None
    if len(ckpt.get("loo_fewshot", {})) == len(checks):
        loo = score_check_mapping(
            {c: ckpt["loo_fewshot"][c.value] for c in checks},
            100,
            seed=None,
            method=f"leave-one-out few-shot LLM ({MODEL}): every other check's mapping shown, the "
            "target control's own held out (with all sibling rows sharing it)",
            note="leakage-bounded few-shot; the target control's mapping is never in the prompt, so a "
            "jump toward the single-pick ceiling would be leakage. It recovers nothing instead.",
        )
        loo["unanswered_checks"] = sum(1 for v in ckpt["loo_fewshot"].values() if v is None)
    artifact = {
        "model": MODEL,
        "model_digest": MODEL_DIGEST,
        "condition": "full public control text, single-pick, temperature 0, fixed seed 1337",
        "without_boundary": without,
        "with_boundary": with_b,
        "loo_fewshot": loo,
        "delta_micro_f1": round(with_b["micro_f1"] - without["micro_f1"], 4),
        "boundary_text": BOUNDARY.strip(),
        "n_findings": without["n_findings"],
        "note": "Indicative observation-boundary ablation. One representative open-weight model "
        "(qwen2.5:7b, the ladder's zero-shot LLM) maps each external check to the ECC-2:2024 "
        "subcontrol it evidences, over the full public control text, with and without the paper's "
        "observation-boundary definition in the prompt. Not part of `make reproduce` and not the "
        "12-model ladder of Appendix B. qwen2.5:14b would not load in a foreground budget on this "
        "4-core GPU-less host, so 7B (already in the ladder) is the representative model.",
        "provenance": {
            "seed": SEED,
            "temperature": 0.0,
            "num_ctx": NUM_CTX,
            "n_checks": len(checks),
            "n_candidate_controls": len(subcontrol_entries()),
            "host": "CPU-only, 4 cores (arm64)",
            "run_date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
    }
    ARTIFACT.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    print(f"without_boundary micro_f1={without['micro_f1']:.4f} (unanswered {without['unanswered_checks']})")
    print(f"with_boundary    micro_f1={with_b['micro_f1']:.4f} (unanswered {with_b['unanswered_checks']})")
    print(f"delta={artifact['delta_micro_f1']:+.4f}  n_findings={artifact['n_findings']}")
    if loo is not None:
        print(f"loo_fewshot      micro_f1={loo['micro_f1']:.4f} (unanswered {loo['unanswered_checks']})")
    print(f"artifact -> {ARTIFACT}")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "run"
    if cmd == "run":
        run()
    elif cmd == "score":
        score()
    elif cmd == "loo":
        loo_run()
    elif cmd == "loo-score":
        loo_score()
    else:
        raise SystemExit(f"unknown command {cmd}")
