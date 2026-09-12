from __future__ import annotations

import contextlib
import re
from typing import TYPE_CHECKING, Any

from p2c._embed import HashingEmbedder, cosine
from p2c.evaluation.ablation import (
    check_query_text,
    definitional_agreement,
    keyword_fulltext_baseline,
    majority_class_mapper,
    naive_keyword_baseline,
    naive_keyword_multilabel_baseline,
    naive_keyword_observable_baseline,
    observable_subcontrol_entries,
    parent_reading_sensitivity,
    score_check_mapping,
    single_pick_ceiling,
    subcontrol_entries,
    subcontrol_text,
    subcontrol_text_full,
)
from p2c.evaluation.synthetic import expert_key

if TYPE_CHECKING:
    from collections.abc import Callable

    from p2c._embed import Embedder
    from p2c.mapping.catalog import ControlEntry
    from p2c.scanning.catalog import CheckId

_ID_RE = re.compile(r"\d(?:-\d{1,2}){2,3}")
DEFAULT_LLM_MODEL = "qwen2.5:7b"
DEFAULT_OLLAMA_HOST = "http://127.0.0.1:11434"


def _ranked_checks() -> list[CheckId]:
    return sorted(expert_key(), key=lambda c: c.value)


def _embedding_mapping(
    embedder: Embedder,
    *,
    text_fn: Callable[[ControlEntry], str] = subcontrol_text,
    candidates: list[ControlEntry] | None = None,
) -> dict[CheckId, str | None]:
    candidates = candidates if candidates is not None else subcontrol_entries()
    candidate_vectors = embedder.embed([text_fn(e) for e in candidates])
    checks = _ranked_checks()
    query_vectors = embedder.embed([check_query_text(c) for c in checks])
    mapping: dict[CheckId, str | None] = {}
    for check, query in zip(checks, query_vectors, strict=True):
        best_id: str | None = None
        best_score = -2.0
        for entry, vector in zip(candidates, candidate_vectors, strict=True):
            score = cosine(query, vector)
            if score > best_score:
                best_score = score
                best_id = entry.native_id
        mapping[check] = best_id
    return mapping


def embedding_cosine_baseline(n: int = 100, *, seed: int | None = None) -> dict[str, Any]:
    mapping = _embedding_mapping(HashingEmbedder())
    return score_check_mapping(
        mapping,
        n,
        seed=seed,
        method="embedding cosine (hashing embedder) over the full catalog",
        note="cosine over a deterministic lexical embedding of check and control text; still far "
        "below the curated cross-walk because the two vocabularies barely overlap",
    )


def embedding_cosine_fulltext_baseline(n: int = 100, *, seed: int | None = None) -> dict[str, Any]:
    mapping = _embedding_mapping(HashingEmbedder(), text_fn=subcontrol_text_full)
    return score_check_mapping(
        mapping,
        n,
        seed=seed,
        method="embedding cosine (hashing) over the full public control text",
        note="deterministic lexical embedding over the complete public control statement; still far "
        "below the curated cross-walk, so the correspondence is not recoverable even from full text",
    )


def embedding_cosine_observable_baseline(
    n: int = 100, *, seed: int | None = None, full_text: bool = True
) -> dict[str, Any]:
    text_fn = subcontrol_text_full if full_text else subcontrol_text
    mapping = _embedding_mapping(
        HashingEmbedder(), text_fn=text_fn, candidates=observable_subcontrol_entries()
    )
    return score_check_mapping(
        mapping,
        n,
        seed=seed,
        method="embedding cosine (hashing) over the observable candidate set",
        note="deterministic lexical embedding restricted to the taxonomy's externally observable "
        "controls, the fair candidate set; still far below the curated cross-walk",
    )


def bge_semantic_baseline(
    n: int = 100, *, seed: int | None = None, full_text: bool = False
) -> dict[str, Any]:
    from p2c.rag.bge import BgeEmbedder

    text_fn = subcontrol_text_full if full_text else subcontrol_text
    mapping = _embedding_mapping(BgeEmbedder(), text_fn=text_fn)
    scope = "full public control text" if full_text else "the full catalog"
    return score_check_mapping(
        mapping,
        n,
        seed=seed,
        method=f"BGE-M3 semantic cosine over {scope}",
        note="a modern multilingual dense retriever mapping by meaning; still far below the "
        "curated cross-walk, so semantic similarity does not recover the finding-to-control link",
    )


def _extract_control_id(response: str, valid: frozenset[str]) -> str | None:
    for match in _ID_RE.findall(response):
        if match in valid:
            return str(match)
    return None


_LLM_TIMEOUT = 600.0


def _llm_mapping(
    *, model: str, host: str, seed: int, full_text: bool = False
) -> tuple[dict[CheckId, str | None], int]:
    import httpx

    from p2c.llm.provider import OllamaProvider

    candidates = subcontrol_entries()
    valid = frozenset(e.native_id for e in candidates)
    if full_text:
        catalog_block = "\n".join(f"{e.native_id}: {subcontrol_text_full(e)}" for e in candidates)
    else:
        catalog_block = "\n".join(f"{e.native_id}: {e.title}" for e in candidates)
    system = (
        "You are a cybersecurity compliance expert mapping one external scan finding to the single "
        "ECC-2:2024 control subcontrol it evidences. Reply with only one control id from the list."
    )
    provider = OllamaProvider(model=model, host=host)
    ctx = 8192 if full_text else 4096
    with contextlib.suppress(httpx.HTTPError, OSError):
        provider.complete("ready?", max_tokens=1, timeout=_LLM_TIMEOUT, num_ctx=ctx, think=False)
    mapping: dict[CheckId, str | None] = {}
    failures = 0
    for check in _ranked_checks():
        prompt = (
            f"Scan finding: {check_query_text(check)}\n\n"
            f"Candidate controls (id: title):\n{catalog_block}\n\n"
            "Reply with the single best control id and nothing else."
        )
        try:
            response = provider.complete(
                prompt,
                system=system,
                temperature=0.0,
                seed=seed,
                max_tokens=24,
                timeout=_LLM_TIMEOUT,
                num_ctx=ctx,
                think=False,
            )
        except (httpx.HTTPError, OSError):
            mapping[check] = None
            failures += 1
            continue
        control = _extract_control_id(response, valid)
        if control is None:
            failures += 1
        mapping[check] = control
    return mapping, failures


def llm_zeroshot_baseline(
    n: int = 100,
    *,
    seed: int | None = None,
    model: str = DEFAULT_LLM_MODEL,
    host: str = DEFAULT_OLLAMA_HOST,
    full_text: bool = False,
) -> dict[str, Any]:
    resolved_seed = 0 if seed is None else seed
    mapping, failures = _llm_mapping(model=model, host=host, seed=resolved_seed, full_text=full_text)
    context = "full public control text" if full_text else "titles alone"
    result = score_check_mapping(
        mapping,
        n,
        seed=seed,
        method=f"zero-shot LLM ({model}) over {context}, constrained to catalog ids",
        note=f"an instruction-tuned model choosing the control from {context}; still far below "
        "the curated cross-walk, so the mapping is not recoverable zero-shot",
    )
    result["unanswered_checks"] = failures
    return result


def hermetic_baselines(n: int = 100, *, seed: int | None = None) -> dict[str, Any]:
    return {
        "naive_keyword": naive_keyword_baseline(n, seed=seed),
        "keyword_fulltext": keyword_fulltext_baseline(n, seed=seed),
        "embedding_hashing": embedding_cosine_baseline(n, seed=seed),
        "embedding_hashing_fulltext": embedding_cosine_fulltext_baseline(n, seed=seed),
        "naive_keyword_observable": naive_keyword_observable_baseline(n, seed=seed),
        "naive_keyword_observable_fulltext": naive_keyword_observable_baseline(n, seed=seed, full_text=True),
        "naive_keyword_multilabel": naive_keyword_multilabel_baseline(n, seed=seed),
        "embedding_hashing_observable": embedding_cosine_observable_baseline(n, seed=seed),
        "majority_class_mapper": majority_class_mapper(n, seed=seed),
        "parent_reading_sensitivity": parent_reading_sensitivity(n, seed=seed),
        "single_pick_ceiling": single_pick_ceiling(n, seed=seed),
        "definitional_agreement": definitional_agreement(),
        "curated_f1": 1.0,
        "note": "non-curated mappers scored against the curated answer key; the curated cross-walk "
        "scores 1.000 by construction. Lexical mappers are run over the full catalog and over the "
        "observable Tier-1 candidate set (the fair set a real external mapper searches), single-pick "
        "and multi-label. single_pick_ceiling is the analytical micro-F1 cap for any one-control-per-"
        "check mapper. Model-backed baselines (BGE-M3, zero-shot LLM) are opt-in.",
    }


def baselines_report(
    n: int = 100,
    *,
    seed: int | None = None,
    models: bool = False,
    llm_model: str = DEFAULT_LLM_MODEL,
    host: str = DEFAULT_OLLAMA_HOST,
) -> dict[str, Any]:
    report = hermetic_baselines(n, seed=seed)
    if models:
        report["embedding_bge_m3"] = bge_semantic_baseline(n, seed=seed)
        report["embedding_bge_m3_fulltext"] = bge_semantic_baseline(n, seed=seed, full_text=True)
        report["llm_zeroshot"] = llm_zeroshot_baseline(n, seed=seed, model=llm_model, host=host)
        report["llm_zeroshot_fulltext"] = llm_zeroshot_baseline(
            n, seed=seed, model=llm_model, host=host, full_text=True
        )
    return report
