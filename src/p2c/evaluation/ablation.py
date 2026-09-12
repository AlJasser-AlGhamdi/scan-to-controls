from __future__ import annotations

import re
from collections import Counter
from collections.abc import Mapping
from typing import Any

from p2c.evaluation import metrics as M
from p2c.evaluation.synthetic import expert_key, generate_cases
from p2c.mapping.catalog import ControlEntry, load_default_index
from p2c.scanning.catalog import CATALOG, CheckId

_STOP = frozenset(
    {
        "the",
        "of",
        "and",
        "to",
        "a",
        "an",
        "in",
        "for",
        "with",
        "by",
        "on",
        "is",
        "are",
        "use",
        "using",
        "absent",
        "missing",
        "no",
        "not",
        "enabled",
        "disabled",
        "or",
        "over",
        "external",
        "entity",
        "its",
        "into",
        "that",
        "this",
        "these",
    }
)
_MIN_TOKEN_LEN = 3
_STATEMENT_CHARS = 160


def _tokens(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z]+", text.lower()) if w not in _STOP and len(w) >= _MIN_TOKEN_LEN}


def subcontrol_entries() -> list[ControlEntry]:
    index = load_default_index()
    return sorted((e for e in index.entries.values() if e.is_subcontrol), key=lambda e: e.native_id)


def subcontrol_text(entry: ControlEntry) -> str:
    return f"{entry.title} {entry.statement_en[:_STATEMENT_CHARS]}"


def subcontrol_text_full(entry: ControlEntry) -> str:
    return f"{entry.title}. {entry.statement_en}"


def check_query_text(check: CheckId) -> str:
    return CATALOG[check].title


def _naive_map(check: CheckId, subcontrols: list[tuple[str, set[str]]]) -> str | None:
    want = _tokens(CATALOG[check].title)
    best_id: str | None = None
    best_score = -1
    for cid, toks in subcontrols:
        score = len(want & toks)
        if score > best_score:
            best_score = score
            best_id = cid
    return best_id


def keyword_fulltext_baseline(n: int = 100, *, seed: int | None = None) -> dict[str, Any]:
    subcontrols = [(e.native_id, _tokens(subcontrol_text_full(e))) for e in subcontrol_entries()]
    naive = {check: _naive_map(check, subcontrols) for check in expert_key()}
    return score_check_mapping(
        naive,
        n,
        seed=seed,
        method="naive keyword title overlap over the full public control text",
        note="candidate is the complete public control statement, untruncated; still far below the "
        "curated cross-walk, so the mapping is not lexically recoverable even from full regulatory text",
    )


def score_check_mapping(
    predicted: Mapping[CheckId, str | frozenset[str] | None],
    n: int,
    *,
    seed: int | None,
    method: str,
    note: str,
) -> dict[str, Any]:
    key = expert_key()
    freq = Counter(inj.check for c in generate_cases(n, seed=seed) for inj in c.injected)
    pairs: list[tuple[set[str], set[str]]] = []
    for check, count in freq.items():
        gold = set(key.get(check, frozenset()))
        if not gold:
            continue
        raw = predicted.get(check)
        if raw is None:
            pred: set[str] = set()
        elif isinstance(raw, str):
            pred = {raw}
        else:
            pred = set(raw)
        pairs.extend((pred, gold) for _ in range(count))
    micro = M.micro_prf(pairs)
    return {
        "method": method,
        "micro_precision": micro.precision,
        "micro_recall": micro.recall,
        "micro_f1": micro.f1,
        "curated_f1": 1.0,
        "n_findings": len(pairs),
        "note": note,
    }


def naive_keyword_baseline(n: int = 100, *, seed: int | None = None) -> dict[str, Any]:
    subcontrols = [(e.native_id, _tokens(subcontrol_text(e))) for e in subcontrol_entries()]
    naive = {check: _naive_map(check, subcontrols) for check in expert_key()}
    return score_check_mapping(
        naive,
        n,
        seed=seed,
        method="naive keyword title overlap over the full catalog",
        note="scanner findings and regulatory control text share little vocabulary, so the "
        "finding-to-control mapping is not lexically recoverable and needs the curated cross-walk",
    )


def observable_subcontrol_entries() -> list[ControlEntry]:
    return [e for e in subcontrol_entries() if e.tier == 1]


def _naive_map_set(check: CheckId, subcontrols: list[tuple[str, set[str]]], k: int) -> frozenset[str]:
    want = _tokens(CATALOG[check].title)
    ranked = sorted(((len(want & toks), cid) for cid, toks in subcontrols), key=lambda t: (-t[0], t[1]))
    return frozenset(cid for overlap, cid in ranked[:k] if overlap > 0)


def naive_keyword_observable_baseline(
    n: int = 100, *, seed: int | None = None, full_text: bool = False
) -> dict[str, Any]:
    text_fn = subcontrol_text_full if full_text else subcontrol_text
    subcontrols = [(e.native_id, _tokens(text_fn(e))) for e in observable_subcontrol_entries()]
    naive = {check: _naive_map(check, subcontrols) for check in expert_key()}
    scope = "full public control text" if full_text else "title"
    return score_check_mapping(
        naive,
        n,
        seed=seed,
        method=f"naive keyword over the {scope}, observable candidate set",
        note="candidates restricted to the taxonomy's externally observable controls, the fair set a "
        "real external mapper would search; still far below the curated cross-walk",
    )


def naive_keyword_multilabel_baseline(n: int = 100, *, seed: int | None = None, k: int = 2) -> dict[str, Any]:
    subcontrols = [(e.native_id, _tokens(subcontrol_text_full(e))) for e in subcontrol_entries()]
    multi = {check: _naive_map_set(check, subcontrols, k) for check in expert_key()}
    return score_check_mapping(
        multi,
        n,
        seed=seed,
        method=f"naive keyword multi-label (top {k}) over the full public control text",
        note="allowed to predict the top controls per check, removing the single-pick cap; still far "
        "below the curated cross-walk, so the cap does not explain the gap",
    )


_DEFINITIONAL_ARTIFACTS: dict[str, str] = {
    "spf": "2-4-3-5",
    "dkim": "2-4-3-5",
    "dmarc": "2-4-3-5",
    "ddos": "2-5-3-9",
}


def definitional_agreement() -> dict[str, Any]:
    key = expert_key()
    links = confirmed = 0
    ambiguous: list[str] = []
    for artifact, cid in _DEFINITIONAL_ARTIFACTS.items():
        naming = [
            e.native_id for e in subcontrol_entries() if artifact in (e.title + " " + e.statement_en).lower()
        ]
        if naming != [cid]:
            ambiguous.append(f"{artifact}:{naming}")
        names_it = naming == [cid]
        for check, gold in key.items():
            if artifact in check.value.lower():
                links += 1
                if names_it and cid in gold:
                    confirmed += 1
    return {
        "links": links,
        "confirmed": confirmed,
        "agreement_rate": round(confirmed / links, 3) if links else 1.0,
        "ambiguous_artifacts": ambiguous,
        "artifact_names_one_control": not ambiguous,
        "note": "finding-to-control links for artifacts named in both the control statement and the "
        "check (SPF, DKIM, DMARC, DDoS). Each artifact name is searched across all 95 candidate "
        "subcontrols; agreement counts only where the search returns exactly the curated control, so "
        "the definitional subset is grounded independently of the mapping rules.",
    }


def majority_class_mapper(n: int = 100, *, seed: int | None = None) -> dict[str, Any]:
    key = expert_key()
    freq = Counter(inj.check for c in generate_cases(n, seed=seed) for inj in c.injected)
    weight: Counter[str] = Counter()
    for check, count in freq.items():
        for cid in key.get(check, frozenset()):
            weight[cid] += count
    modal = min((cid for cid, w in weight.items() if w == max(weight.values())), default="")
    total = sum(count for check, count in freq.items() if key.get(check))
    result = score_check_mapping(
        dict.fromkeys(key, modal),
        n,
        seed=seed,
        method=f"constant: answer {modal} to every check, ignoring the finding",
        note="the degenerate floor every non-curated baseline must clear; it exploits the corpus's "
        "concentration on one control rather than reading the finding at all",
    )
    result["modal_control"] = modal
    result["modal_share"] = round(weight[modal] / total, 3) if total else 0.0
    return result


PARENT_READING_CHECKS: frozenset[str] = frozenset(
    {
        "missing_csp",
        "missing_x_frame_options",
        "missing_x_content_type_options",
        "missing_referrer_policy",
        "missing_permissions_policy",
        "directory_listing_enabled",
        "exposed_sensitive_file",
    }
)


def parent_reading_sensitivity(n: int = 100, *, seed: int | None = None) -> dict[str, Any]:
    key = expert_key()
    freq = Counter(inj.check for c in generate_cases(n, seed=seed) for inj in c.injected)

    def weights(remap: bool) -> Counter[str]:
        w: Counter[str] = Counter()
        for check, count in freq.items():
            for cid in key.get(check, frozenset()):
                moved = remap and check.value in PARENT_READING_CHECKS and cid == "2-15-3-3"
                w["2-15-3" if moved else cid] += count
        return w

    total = sum(count for check, count in freq.items() if key.get(check))
    gold = sum(count * len(key[check]) for check, count in freq.items() if key.get(check))
    out: dict[str, Any] = {}
    for label, remap in (("as_shipped", False), ("parent_reading", True)):
        w = weights(remap)
        modal, mw = max(w.items(), key=lambda kv: (kv[1], kv[0]))
        tp = 0
        for check, count in freq.items():
            ids = {
                "2-15-3" if (remap and check.value in PARENT_READING_CHECKS and cid == "2-15-3-3") else cid
                for cid in key.get(check, frozenset())
            }
            if modal in ids:
                tp += count
        precision, recall = tp / total, tp / gold
        out[label] = {
            "modal_control": modal,
            "modal_share": round(mw / total, 3),
            "constant_mapper_f1": round(2 * precision * recall / (precision + recall), 4),
        }
    out["note"] = (
        "sensitivity only. The shipped key is unchanged; the panel of Section 9.7 rules on the reading."
    )
    return out


def single_pick_ceiling(n: int = 100, *, seed: int | None = None) -> float:
    key = expert_key()
    freq = Counter(inj.check for c in generate_cases(n, seed=seed) for inj in c.injected)
    total = extra = 0
    for check, count in freq.items():
        gold = key.get(check, frozenset())
        if not gold:
            continue
        total += count
        extra += count * (len(gold) - 1)
    return round(2 * total / (2 * total + extra), 3) if total else 1.0
