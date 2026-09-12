from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from p2c.evaluation.metrics import cohens_kappa
from p2c.mapping.catalog import ControlEntry

SCAN = "scan"
ANSWER = "answer"

SYSTEM = (
    "You are a cybersecurity compliance auditor classifying one Saudi ECC-2:2024 or NCNICC-1:2025 "
    "control. Decide whether an EXTERNAL, unauthenticated internet scan of a firm's public assets "
    "can by itself PROVE compliance with the control, or whether the control can only be settled by "
    "the firm's own internal assessment or a written declaration. An external scan observes only the "
    "contents of published DNS records, the negotiated parameters of a TLS session, which ports "
    "answer, which HTTP response headers a web server returns, and the services and versions those "
    "responses reveal. It cannot read internal process, policy, staffing, physical premises, "
    "contracts, or records. Answer with exactly one word: SCAN if an external scan alone can prove "
    "the control, or ANSWER if it needs internal evidence or a declaration."
)


def build_prompt(entry: ControlEntry) -> str:
    lines = [f"Control {entry.native_id}: {entry.title}".rstrip()]
    if entry.statement_en:
        lines.append(f"Statement: {entry.statement_en}")
    if entry.assessment_en:
        lines.append(f"Assessment method: {entry.assessment_en}")
    lines.append("\nAnswer with exactly one word, SCAN or ANSWER.")
    return "\n".join(lines)


def author_binary(tier: int) -> str:
    return SCAN if tier == 1 else ANSWER


def parse_label(response: str) -> str | None:
    last: str | None = None
    for token in response.lower().replace("*", " ").replace(".", " ").split():
        if token.startswith("scan"):
            last = SCAN
        elif token.startswith("answer"):
            last = ANSWER
    return last


@dataclass(frozen=True)
class SecondCoderScore:

    n_rows: int
    n_scored: int
    n_unparseable: int
    agreement_rate: float
    cohen_kappa: float
    confusion: dict[str, int]
    n_scan_author: int
    n_scan_model: int
    disagreements: list[dict[str, str]]


def score_binary(rows: Sequence[tuple[str, str, str | None]]) -> SecondCoderScore:
    scored = [(cid, a, m) for cid, a, m in rows if m is not None]
    n_scored = len(scored)
    author_labels = [a for _, a, _ in scored]
    model_labels = [m for _, _, m in scored]
    agree = sum(1 for a, m in zip(author_labels, model_labels, strict=True) if a == m)
    agreement_rate = agree / n_scored if n_scored else 0.0
    kappa = cohens_kappa(author_labels, model_labels) if n_scored else 0.0
    confusion = {
        "scan_scan": 0,
        "scan_answer": 0,
        "answer_scan": 0,
        "answer_answer": 0,
    }
    for a, m in zip(author_labels, model_labels, strict=True):
        confusion[f"{a}_{m}"] += 1
    disagreements = [
        {"id": cid, "author": a, "model": m} for cid, a, m in scored if a != m
    ]
    disagreements.sort(key=lambda d: [int(p) for p in d["id"].split("-")])
    return SecondCoderScore(
        n_rows=len(rows),
        n_scored=n_scored,
        n_unparseable=len(rows) - n_scored,
        agreement_rate=agreement_rate,
        cohen_kappa=kappa,
        confusion=confusion,
        n_scan_author=sum(1 for a in author_labels if a == SCAN),
        n_scan_model=sum(1 for m in model_labels if m == SCAN),
        disagreements=disagreements,
    )


def score_recode(committed: dict[str, int], recoded: dict[str, int]) -> dict:
    ids = sorted(set(committed) & set(recoded), key=lambda i: [int(p) for p in i.split("-")])
    if not ids:
        raise ValueError("no control ids in common between the sort and the recode")
    c_tier = [committed[i] for i in ids]
    r_tier = [recoded[i] for i in ids]
    c_bin = [author_binary(t) for t in c_tier]
    r_bin = [author_binary(t) for t in r_tier]
    moved = [
        {"id": i, "committed_tier": committed[i], "recode_tier": recoded[i]}
        for i in ids
        if committed[i] != recoded[i]
    ]
    return {
        "n_rows": len(ids),
        "threeway": {
            "agreement_rate": round(sum(c == r for c, r in zip(c_tier, r_tier, strict=True)) / len(ids), 4),
            "cohen_kappa": round(cohens_kappa(c_tier, r_tier), 4),
        },
        "binary": {
            "agreement_rate": round(sum(c == r for c, r in zip(c_bin, r_bin, strict=True)) / len(ids), 4),
            "cohen_kappa": round(cohens_kappa(c_bin, r_bin), 4),
        },
        "n_moved": len(moved),
        "moved": moved,
    }
