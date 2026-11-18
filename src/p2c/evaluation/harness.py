from __future__ import annotations

import dataclasses
import functools
import itertools
import json
import random
import statistics
import time
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

from p2c.config import get_settings
from p2c.evaluation import metrics as M
from p2c.evaluation import synthetic as _syn
from p2c.evaluation.ablation import (
    PARENT_READING_CHECKS,
    naive_keyword_baseline,
    parent_reading_sensitivity,
)
from p2c.evaluation.baselines import hermetic_baselines
from p2c.evaluation.synthetic import (
    _CHECK_CATEGORY,
    _HOST_FETCHED_CHECKS,
    EVAL_EPOCH,
    LOW_CONFIDENCE_CHECKS,
    EvalCase,
    expert_key,
    generate_cases,
)
from p2c.evaluation.synthetic_b import generate_cases_b
from p2c.mapping.models import ControlMapping, MappingMethod
from p2c.mapping.rules import MappingEngine, check_id_from_finding
from p2c.scanning.catalog import LIVE_CHECKS, CheckId
from p2c.schemas.enums import EvidenceTier
from p2c.schemas.models import Attestation
from p2c.scoring.assemble import (
    TIER1_CHECKABLE,
    attestation_assessments,
    merge_assessments,
    tier1_assessments,
)
from p2c.scoring.contradictions import control_related, detect_contradictions
from p2c.scoring.dual_score import apply_weights, compute_dual_score
from p2c.scoring.models import ComplianceStatus, ControlAssessment
from p2c.scoring.questionnaire import (
    Answer,
    Question,
    Questionnaire,
    QuestionnaireEngine,
    QuestionnaireResponse,
)
from p2c.scoring.weights import CR_THRESHOLD, ahp_weights

ATLAS_SECONDS_PER_FINDING = 0.05
_SUS_ITEMS = 10
_ANNOTATOR_AGREE_PROB = 0.75
_MIN_EFFECT_GROUP = 2
_MIN_CORROBORATION = 2


@dataclass(frozen=True)
class CasePrediction:

    case_id: str
    sector: str
    size_band: str
    posture: str
    predicted: frozenset[str]
    predicted_corroborated: frozenset[str]
    observed_gold: frozenset[str]
    true_gold: frozenset[str]
    n_findings: int
    n_true_findings: int


@dataclass
class EvaluationReport:
    seed: int
    n_profiles: int
    n_findings: int
    n_true_findings: int
    sector_counts: dict[str, int]
    size_band_counts: dict[str, int]
    mapping: dict[str, Any]
    end_to_end: dict[str, Any]
    end_to_end_corroborated: dict[str, Any]
    per_sector: dict[str, Any]
    per_posture: dict[str, Any]
    per_size: dict[str, Any]
    per_control: dict[str, Any]
    effect_size: dict[str, Any]
    ablation: dict[str, Any]
    baselines: dict[str, Any]
    detection: dict[str, Any]
    contradictions: dict[str, Any]
    posture: dict[str, Any]
    agreement: dict[str, Any]
    sus: dict[str, Any]
    latency: dict[str, Any]
    weighting: dict[str, Any] = field(default_factory=dict)
    realism: dict[str, Any] = field(default_factory=dict)
    scan_realism: dict[str, Any] = field(default_factory=dict)
    specificity: dict[str, Any] = field(default_factory=dict)
    trivial_floor: dict[str, Any] = field(default_factory=dict)
    detection_ceiling: dict[str, Any] = field(default_factory=dict)
    implemented_only: dict[str, Any] = field(default_factory=dict)
    rate_class_slice: dict[str, Any] = field(default_factory=dict)
    tier2_integrity: dict[str, Any] = field(default_factory=dict)
    dual_score_gap: dict[str, Any] = field(default_factory=dict)
    parent_reading: dict[str, Any] = field(default_factory=dict)
    cohort_firms: dict[str, Any] = field(default_factory=dict)


def _corroborated_controls(case: EvalCase, key: dict[Any, frozenset[str]]) -> frozenset[str]:
    supports: dict[str, list[Any]] = {}
    for inj in case.injected:
        for cid in key[inj.check]:
            supports.setdefault(cid, []).append(inj.check)
    confirmed: set[str] = set()
    for cid, checks in supports.items():
        has_high_confidence = any(c not in LOW_CONFIDENCE_CHECKS for c in checks)
        if has_high_confidence or len(checks) >= _MIN_CORROBORATION:
            confirmed.add(cid)
    return frozenset(confirmed)


def _predict(cases: list[EvalCase]) -> list[CasePrediction]:
    engine = MappingEngine()
    key = expert_key()
    out: list[CasePrediction] = []
    for case in cases:
        mappings = engine.map_findings(case.findings())
        out.append(
            CasePrediction(
                case_id=case.case_id,
                sector=case.sector,
                size_band=case.size_band,
                posture=case.posture,
                predicted=frozenset(m.control_id for m in mappings),
                predicted_corroborated=_corroborated_controls(case, key),
                observed_gold=case.ground_truth.observed_ids,
                true_gold=case.ground_truth.control_ids,
                n_findings=len(case.injected),
                n_true_findings=len(case.true_injected),
            )
        )
    return out


def _estimate(est: M.Estimate) -> dict[str, float]:
    return {"point": est.point, "ci_low": est.ci_low, "ci_high": est.ci_high, "level": est.level}


def _prf_block(pairs: list[tuple[set[str], set[str]]], *, seed: int) -> dict[str, Any]:
    micro = M.micro_prf(pairs)

    def _fuzzy_micro(threshold: float) -> dict[str, float]:
        fuzzy = [M.fuzzy_set_prf(pred, gold, threshold=threshold) for pred, gold in pairs]
        agg = M.prf_from_counts(
            sum(f.true_positive for f in fuzzy),
            sum(f.false_positive for f in fuzzy),
            sum(f.false_negative for f in fuzzy),
        )
        return {"precision": agg.precision, "recall": agg.recall, "f1": agg.f1}

    fuzzy_by_threshold = {f"{t:.2f}": _fuzzy_micro(t) for t in (0.5, 0.7, 0.9)}
    per_case_f1 = [M.case_f1(pred, gold) for pred, gold in pairs]
    f1_ci = M.bootstrap_ci(per_case_f1, seed=seed)
    counts = [(len(p & g), len(p - g), len(g - p)) for p, g in pairs]
    micro_ci = _bootstrap_pooled_f1(counts, seed=seed)
    return {
        "exact_micro": {"precision": micro.precision, "recall": micro.recall, "f1": micro.f1},
        "exact_micro_f1_ci": micro_ci,
        "fuzzy70_micro": fuzzy_by_threshold["0.70"],
        "fuzzy_by_threshold": fuzzy_by_threshold,
        "macro_f1": _estimate(f1_ci),
        "confusion": {"tp": micro.true_positive, "fp": micro.false_positive, "fn": micro.false_negative},
    }


def _mapping_metrics(preds: list[CasePrediction], *, seed: int) -> dict[str, Any]:
    pairs = [(set(p.predicted), set(p.observed_gold)) for p in preds]
    return _prf_block(pairs, seed=seed)


def _decision_universe(pairs: list[tuple[set[str], set[str]]]) -> dict[str, Any]:
    controls = {c for pred, gold in pairs for c in pred | gold}
    micro = M.micro_prf(pairs)
    tp, fp, fn = micro.true_positive, micro.false_positive, micro.false_negative
    decisions = len(pairs) * len(controls)
    tn = decisions - tp - fp - fn
    return {
        "n_controls": len(controls),
        "n_decisions": decisions,
        "tn": tn,
        "mcc": M.mcc_from_counts(tp, fp, fn, tn),
        "balanced_accuracy": M.balanced_accuracy_from_counts(tp, fp, fn, tn),
        "note": "the whole 2x2 table over organizations x controls. F1 reads three of its cells; MCC and "
        "balanced accuracy read all four, and the predict-all floor scores 0.0 and 0.5 on them by "
        "construction, so the margin over that floor survives a measure the base rate cannot inflate.",
    }


def _end_to_end_metrics(preds: list[CasePrediction], *, seed: int) -> dict[str, Any]:
    pairs = [(set(p.predicted), set(p.true_gold)) for p in preds]
    return {**_prf_block(pairs, seed=seed), "decision_universe": _decision_universe(pairs)}


_HALF_WIDTH_UNDERPOWERED = 0.10


def _stratum_block(pairs: list[tuple[set[str], set[str]]], *, seed: int) -> dict[str, Any]:
    prf = M.micro_prf(pairs)
    counts = [(len(p & g), len(p - g), len(g - p)) for p, g in pairs]
    ci = _bootstrap_pooled_f1(counts, seed=seed)
    half_width = (ci["ci_high"] - ci["ci_low"]) / 2.0
    tp, fp, fn = prf.true_positive, prf.false_positive, prf.false_negative
    prec_ci = M.wilson_interval(tp, tp + fp) if tp + fp else None
    rec_ci = M.wilson_interval(tp, tp + fn) if tp + fn else None
    return {
        "n": len(pairs),
        "precision": prf.precision,
        "recall": prf.recall,
        "f1": prf.f1,
        "f1_ci": ci,
        "precision_ci": _estimate(prec_ci) if prec_ci else None,
        "recall_ci": _estimate(rec_ci) if rec_ci else None,
        "underpowered": half_width > _HALF_WIDTH_UNDERPOWERED,
    }


def _end_to_end_corroborated_metrics(preds: list[CasePrediction], *, seed: int) -> dict[str, Any]:
    pairs = [(set(p.predicted_corroborated), set(p.true_gold)) for p in preds]
    return _prf_block(pairs, seed=seed)


def _per_sector(preds: list[CasePrediction], *, seed: int) -> dict[str, Any]:
    sectors = sorted({p.sector for p in preds})
    out: dict[str, Any] = {}
    for s in sectors:
        pairs = [(set(p.predicted), set(p.true_gold)) for p in preds if p.sector == s]
        out[s] = _stratum_block(pairs, seed=seed)
    return out


def _per_posture(preds: list[CasePrediction], *, seed: int) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for level in ("strong", "moderate", "weak"):
        pairs = [(set(p.predicted), set(p.true_gold)) for p in preds if p.posture == level]
        if not pairs:
            continue
        out[level] = _stratum_block(pairs, seed=seed)
    return out


def _per_size(preds: list[CasePrediction], *, seed: int) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for band in ("small", "medium"):
        pairs = [(set(p.predicted), set(p.true_gold)) for p in preds if p.size_band == band]
        if not pairs:
            continue
        out[band] = _stratum_block(pairs, seed=seed)
    return out


LIVE_INSPECTOR_CHECKS: frozenset[str] = frozenset(check.value for check in LIVE_CHECKS)


def _implemented_only(cases: list[EvalCase]) -> dict[str, Any]:
    from p2c.evaluation.synthetic import expert_key

    key = expert_key()
    live_checks = {check for check in key if check.value in LIVE_INSPECTOR_CHECKS}
    live = {c for check in live_checks for c in key[check]}
    engine = MappingEngine()
    pairs: list[tuple[set[str], set[str]]] = []
    for case in cases:
        findings = [f for f in case.findings() if check_id_from_finding(f) in live_checks]
        predicted = {m.control_id for m in engine.map_findings(findings)} & live
        gold = {c for inj in case.true_injected if inj.check in live_checks for c in key[inj.check]} & live
        pairs.append((predicted, gold))
    micro = M.micro_prf(pairs)
    true_cells = sum(len(g) for _, g in pairs)
    base = true_cells / (len(pairs) * len(live)) if pairs and live else 0.0
    return {
        "n_controls": len(live),
        "controls": sorted(live),
        "n_live_detectors": len(live_checks),
        "precision": round(micro.precision, 6),
        "recall": round(micro.recall, 6),
        "f1": round(micro.f1, 6),
        "true_assignments": true_cells,
        "trivial_floor_f1": round(2 * base / (base + 1), 6) if base else 0.0,
        "note": "recovery from the implemented detectors alone: findings and true issues of detectors "
        "without a live inspector are dropped from both sides, over the controls the implemented "
        "inspectors reach. Detection is modelled here exactly as in the full result, so this is a "
        "dependence check on the implementation gap, not a field measurement.",
    }


def _rate_class_slice(cases: list[EvalCase]) -> dict[str, Any]:
    from p2c.evaluation import synthetic as S
    from p2c.evaluation.appendix_tables import provenance

    key = expert_key()
    judged = {c for c in S.SENSITIVITY if provenance(S.SENSITIVITY[c], S.FALSE_ALARM[c]) == "author judgment"}
    kept = set(S.SENSITIVITY) - judged
    universe = {cid for check in kept for cid in key[check]}
    engine = MappingEngine()
    pairs: list[tuple[set[str], set[str]]] = []
    for case in cases:
        findings = [f for f in case.findings() if check_id_from_finding(f) in kept]
        predicted = {m.control_id for m in engine.map_findings(findings)} & universe
        gold = {cid for inj in case.true_injected if inj.check in kept for cid in key[inj.check]} & universe
        pairs.append((predicted, gold))
    micro = M.micro_prf(pairs)
    tp, fp, fn = micro.true_positive, micro.false_positive, micro.false_negative
    decisions = len(pairs) * len(universe)
    tn = decisions - tp - fp - fn
    base = (tp + fn) / decisions if decisions else 0.0
    return {
        "n_dropped_detectors": len(judged),
        "dropped_detectors": sorted(c.value for c in judged),
        "n_controls": len(universe),
        "controls": sorted(universe),
        "precision": round(micro.precision, 6),
        "recall": round(micro.recall, 6),
        "f1": round(micro.f1, 6),
        "true_assignments": tp + fn,
        "n_decisions": decisions,
        "base_rate": round(base, 6),
        "trivial_floor_f1": round(2 * base / (base + 1), 6) if base else 0.0,
        "mcc": round(M.mcc_from_counts(tp, fp, fn, tn), 6),
        "balanced_accuracy": round(M.balanced_accuracy_from_counts(tp, fp, fn, tn), 6),
        "note": "violation detection with the analyst-judgement detectors dropped from predictions and "
        "ground truth alike, over the controls the deterministic reads and probes reach; the floor is the "
        "predict-all baseline on the same decisions. Detection is modelled exactly as in the full result.",
    }


def _p_finding(check: Any, host: str, case: EvalCase, present: bool) -> float:
    from p2c.evaluation import synthetic as S

    if present:
        return S._effective_sensitivity(check, host, case.scan_conditions, case.scanner_competence)
    if check not in S._FALSE_ALARM_CHECKS:
        return 0.0
    apex = case.profile.apex
    if check in S._APEX_ONLY_CHECKS and host != apex:
        return 0.0
    if check in S._DEV_ONLY_CHECKS and S._host_label(host, apex) not in S._DEV_LABELS:
        return 0.0
    rate = S.FALSE_ALARM[check]
    if check in S._HOST_FETCHED_CHECKS:
        rate *= S._condition_factor(check, case.scan_conditions[host])
    return rate


def _assert_probabilities(cases: list[EvalCase]) -> list[tuple[float, bool]]:
    from p2c.evaluation import synthetic as S

    key = S.expert_key()
    universe = sorted({c for case in cases for c in case.ground_truth.control_ids})
    by_control: dict[str, list[Any]] = {c: [] for c in universe}
    for check, gold in key.items():
        for cid in gold:
            if cid in by_control:
                by_control[cid].append(check)

    cells: list[tuple[float, bool]] = []
    for case in cases:
        present = {(i.asset, i.check) for i in case.true_injected}
        for cid in universe:
            miss = 1.0
            for host in case.scan_conditions:
                for check in by_control[cid]:
                    miss *= 1.0 - _p_finding(check, host, case, (host, check) in present)
            cells.append((1.0 - miss, cid in case.ground_truth.control_ids))
    return cells


def _detection_ceiling(cases: list[EvalCase]) -> dict[str, Any]:
    e_tp = e_fp = e_fn = 0.0
    for assert_p, violated in _assert_probabilities(cases):
        if violated:
            e_tp += assert_p
            e_fn += 1.0 - assert_p
        else:
            e_fp += assert_p
    precision = e_tp / (e_tp + e_fp) if e_tp + e_fp else 0.0
    recall = e_tp / (e_tp + e_fn) if e_tp + e_fn else 0.0
    return {
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(2 * precision * recall / (precision + recall), 6) if precision + recall else 0.0,
        "expected_tp": round(e_tp, 1),
        "expected_fp": round(e_fp, 1),
        "expected_fn": round(e_fn, 1),
        "note": "analytic: the score a perfect mapper reaches given the detection rates and the corpus "
        "base rate alone, with no seeded draw. The measured end-to-end score should match it to within "
        "seed variation, which is what makes that score an integrity check rather than a performance result.",
    }


def _trivial_floor(preds: list[CasePrediction]) -> dict[str, Any]:
    universe = sorted({c for p in preds for c in p.true_gold})
    out: dict[str, Any] = {}
    for level in (None, "strong", "moderate", "weak"):
        rows = preds if level is None else [p for p in preds if p.posture == level]
        if not rows:
            continue
        cells = len(rows) * len(universe)
        true_cells = sum(len(p.true_gold) for p in rows)
        base = true_cells / cells if cells else 0.0
        tp, fp = true_cells, cells - true_cells
        out[level or "corpus"] = {
            "base_rate": round(base, 6),
            "f1": round(2 * base / (base + 1), 6) if base else 0.0,
            "mcc": M.mcc_from_counts(tp, fp, 0, 0),
            "balanced_accuracy": M.balanced_accuracy_from_counts(tp, fp, 0, 0),
            "n_orgs": len(rows),
        }
    out["note"] = (
        "predict-all-controls floor: precision = base rate, recall = 1.0. The measured end-to-end F1 "
        "must be read as its margin over this, not against 0. On the whole-table measures the floor is "
        "0.0 (MCC) and 0.5 (balanced accuracy) at any base rate."
    )
    out["control_universe"] = len(universe)
    return out


def _per_control(preds: list[CasePrediction]) -> dict[str, Any]:
    controls = sorted({c for p in preds for c in (p.true_gold | p.predicted)})
    out: dict[str, Any] = {}
    for cid in controls:
        tp = sum(1 for p in preds if cid in p.true_gold and cid in p.predicted)
        fp = sum(1 for p in preds if cid in p.predicted and cid not in p.true_gold)
        fn = sum(1 for p in preds if cid in p.true_gold and cid not in p.predicted)
        support = tp + fn
        prec_ci = M.wilson_interval(tp, tp + fp) if tp + fp else None
        rec_ci = M.wilson_interval(tp, support) if support else None
        out[cid] = {
            "support": support,
            "precision": tp / (tp + fp) if tp + fp else 1.0,
            "recall": tp / support if support else 1.0,
            "precision_ci": _estimate(prec_ci) if prec_ci else None,
            "recall_ci": _estimate(rec_ci) if rec_ci else None,
        }
    return out


def _effect_size(preds: list[CasePrediction]) -> dict[str, Any]:
    by_posture: dict[str, list[float]] = {"strong": [], "weak": []}
    for p in preds:
        if p.posture in by_posture:
            by_posture[p.posture].append(M.case_f1(set(p.predicted), set(p.true_gold)))
    strong, weak = by_posture["strong"], by_posture["weak"]
    enough = len(strong) >= _MIN_EFFECT_GROUP and len(weak) >= _MIN_EFFECT_GROUP
    d = M.cohens_d(weak, strong) if enough else 0.0
    delta = M.cliffs_delta(weak, strong) if (strong and weak) else 0.0
    return {
        "metric": "posture_effect_end_to_end_f1_weak_vs_strong",
        "cliffs_delta": round(delta, 3),
        "cohen_d": d,
        "n_strong": len(strong),
        "n_weak": len(weak),
        "note": "effect size of posture on per-case end-to-end F1 (weak minus strong). Cliff's delta is "
        "the primary nonparametric measure (F1 is bounded and non-normal); Cohen's d is reported for "
        "reference. Positive means weak estates are recovered better, the base-rate effect.",
    }


def _index_by_category(cases: list[EvalCase], attr: str) -> dict[str, set[tuple[str, str, str]]]:
    out: dict[str, set[tuple[str, str, str]]] = {}
    for c in cases:
        for inj in getattr(c, attr):
            out.setdefault(_CHECK_CATEGORY[inj.check], set()).add((c.case_id, inj.asset, inj.check.value))
    return out


def _detection(cases: list[EvalCase]) -> dict[str, Any]:
    true_present = _index_by_category(cases, "true_injected")
    observed = _index_by_category(cases, "injected")
    cats = sorted(set(true_present) | set(observed))
    per_category: dict[str, dict[str, int]] = {}
    n_true = n_detected = n_missed = n_false = 0
    for cat in cats:
        t = true_present.get(cat, set())
        o = observed.get(cat, set())
        detected, missed, false = len(t & o), len(t - o), len(o - t)
        per_category[cat] = {"true": len(t), "detected": detected, "missed": missed, "false_alarm": false}
        n_true += len(t)
        n_detected += detected
        n_missed += missed
        n_false += false
    return {
        "n_true_findings": n_true,
        "n_detected": n_detected,
        "n_missed": n_missed,
        "n_false_alarm": n_false,
        "recall": (n_detected / n_true) if n_true else 1.0,
        "per_category": per_category,
        "note": "modelled external-scanner sensitivity and false alarms; see docs/threats-to-validity.md",
    }


def _bootstrap_pooled_f1(
    counts: list[tuple[int, int, int]], *, seed: int, iters: int = 2000
) -> dict[str, float]:
    if not counts:
        return {"point": 1.0, "ci_low": 1.0, "ci_high": 1.0, "level": 0.95}
    rng = random.Random(seed + 313)
    n = len(counts)
    point = M.prf_from_counts(*(sum(c[i] for c in counts) for i in range(3))).f1
    f1s: list[float] = []
    for _ in range(iters):
        sample = [counts[rng.randrange(n)] for _ in range(n)]
        f1s.append(M.prf_from_counts(*(sum(c[i] for c in sample) for i in range(3))).f1)
    f1s.sort()
    return {
        "point": point,
        "ci_low": f1s[int(0.025 * iters)],
        "ci_high": f1s[int(0.975 * iters)],
        "level": 0.95,
    }


def _internal_assessments(case: EvalCase) -> list[ControlAssessment]:
    if not case.internal_evidence:
        return []
    questions = [
        Question(
            question_id=f"q-{record.control_id}",
            control_id=record.control_id,
            prompt_en=f"Is {record.control_id} implemented?",
        )
        for record in case.internal_evidence
    ]
    questionnaire = Questionnaire(
        questionnaire_id=f"iq-{case.case_id}", title="Internal assessment", questions=questions
    )
    response = QuestionnaireResponse(
        questionnaire_id=questionnaire.questionnaire_id,
        respondent=f"ciso@{case.case_id}",
        consent_ref="eval",
        answers=[
            Answer(question_id=f"q-{record.control_id}", compliant=record.compliant)
            for record in case.internal_evidence
        ],
    )
    return QuestionnaireEngine().assessments(questionnaire, response)


@functools.cache
def _documented_universe() -> frozenset[str]:
    internal, declared = _syn.off_surface_pools()
    return frozenset(TIER1_CHECKABLE) | frozenset(internal) | frozenset(declared)


@functools.cache
def _class_b_status() -> dict[str, str | None]:
    rows = json.loads(_syn._OVERLAY_PATH.read_text(encoding="utf-8"))["controls"]
    return {str(r["id"]): r.get("ncnicc_class_b_status") for r in rows}


def _unobserved(case: EvalCase, unread: frozenset[tuple[str, Any]] = frozenset()) -> frozenset[str]:
    from p2c.evaluation import synthetic as S

    conditions = case.scan_conditions
    apex = case.profile.apex
    missing: set[str] = set()
    for check, controls in expert_key().items():
        if check in S._APEX_ONLY_CHECKS:
            read = apex in conditions and (apex, check) not in unread
        else:
            read = bool(conditions) and all(
                (
                    cond in ("reachable", "throttled")
                    or (cond == "cdn_fronted" and check not in S._ORIGIN_CHECKS)
                )
                and (host, check) not in unread
                for host, cond in conditions.items()
            )
        if not read:
            missing |= set(controls)
    return frozenset(missing & TIER1_CHECKABLE)


def _all_tier_assessments(case: EvalCase, mappings: Sequence[ControlMapping]) -> list[ControlAssessment]:
    return merge_assessments(
        tier1_assessments(mappings, unobserved=_unobserved(case)),
        _internal_assessments(case),
        attestation_assessments(case.attestations, now=EVAL_EPOCH),
    )


def _claim_flags(
    case: EvalCase, mappings: Sequence[ControlMapping], truth: Iterable[str]
) -> tuple[set[tuple[int, str]], set[tuple[int, str]]]:
    tier2 = _internal_assessments(case)
    live = [a for a in case.attestations if a.valid_from <= EVAL_EPOCH <= a.valid_until]
    claims = {(int(EvidenceTier.TIER_3), a.control_id) for a in live}
    claims |= {
        (int(EvidenceTier.TIER_2), r.control_id) for r in tier2 if r.status is ComplianceStatus.COMPLIANT
    }
    truth = set(truth)
    gt = {(t, c) for t, c in claims if any(control_related(c, x) for x in truth)}
    detected = {
        (x.tier, x.control_id)
        for x in detect_contradictions(case.attestations, mappings, now=EVAL_EPOCH, tier2=tier2)
    }
    return gt, detected


def _governance(cases: list[EvalCase], *, seed: int) -> dict[str, Any]:
    engine = MappingEngine()
    n_check = len(TIER1_CHECKABLE)
    c_tp = c_fp = c_fn = 0
    gt_total = flagged = n_att = 0
    n_lapsed = 0
    n_unrefutable = n_unrefutable_live = 0
    n_checkable_records = 0
    d_tp = d_fn = 0
    lapsed_wrongly_flagged = 0
    contra_counts: list[tuple[int, int, int]] = []
    true_assessed: list[float] = []
    abs_err: list[float] = []
    documented: list[float] = []
    for case in cases:
        mappings = engine.map_findings(case.findings())
        true = case.ground_truth.control_ids
        live = [a for a in case.attestations if a.valid_from <= EVAL_EPOCH <= a.valid_until]
        lapsed_ids = {a.control_id for a in case.attestations if a not in live}
        attested = {a.control_id for a in live}
        gt, detected = _claim_flags(case, mappings, true)
        n_checkable_records += sum(
            1
            for r in _internal_assessments(case)
            if r.status is ComplianceStatus.COMPLIANT
            and any(control_related(r.control_id, c) for c in TIER1_CHECKABLE)
        )
        tp_i, fp_i, fn_i = len(gt & detected), len(detected - gt), len(gt - detected)
        declared = {c for c in gt if c[0] == int(EvidenceTier.TIER_3)}
        d_tp += len(declared & detected)
        d_fn += len(declared - detected)
        c_tp += tp_i
        c_fn += fn_i
        c_fp += fp_i
        contra_counts.append((tp_i, fp_i, fn_i))
        gt_total += len(gt)
        flagged += len(detected)
        n_att += len(case.attestations)
        n_lapsed += len(case.attestations) - len(live)
        unrefutable = {
            a.control_id
            for a in case.attestations
            if not any(control_related(a.control_id, c) for c in TIER1_CHECKABLE)
        }
        n_unrefutable += sum(1 for a in case.attestations if a.control_id in unrefutable)
        n_unrefutable_live += sum(1 for a in live if a.control_id in unrefutable)
        lapsed_wrongly_flagged += len(
            {c for t, c in detected if t == EvidenceTier.TIER_3} & (lapsed_ids - attested)
        )
        score = compute_dual_score(_all_tier_assessments(case, mappings), universe=_documented_universe())
        true_a = (n_check - len(true & TIER1_CHECKABLE)) / n_check
        true_assessed.append(true_a)
        abs_err.append(abs(score.assessed_score - true_a))
        documented.append(score.documented_score)
    cprf = M.prf_from_counts(c_tp, c_fp, c_fn)
    f1_ci = _bootstrap_pooled_f1(contra_counts, seed=seed)
    return {
        "contradictions": {
            "precision": cprf.precision,
            "recall": cprf.recall,
            "f1": cprf.f1,
            "f1_ci": f1_ci,
            "true_contradictions": gt_total,
            "flagged": flagged,
            "tp": c_tp,
            "fp": c_fp,
            "fn": c_fn,
            "n_attestations": n_att,
            "n_lapsed_attestations": n_lapsed,
            "n_unrefutable_attestations": n_unrefutable,
            "n_unrefutable_active_attestations": n_unrefutable_live,
            "n_checkable_tier2_records": n_checkable_records,
            "declarations_only": {
                "true_contradictions": d_tp + d_fn,
                "recall": d_tp / (d_tp + d_fn) if d_tp + d_fn else 0.0,
            },
            "lapsed_wrongly_flagged": lapsed_wrongly_flagged,
            "note": "overstatement detection: a Tier-3 attestation refuted by a Tier-1 finding; "
            "recall limited by scanner misses, precision by false alarms. Lapsed (expired or not yet "
            "effective) attestations are excluded from both the ground truth and the detector. "
            "Declarations on off-surface controls, which no Tier-1 finding can reach, are counted "
            "separately: the detector sees them and correctly leaves them alone, so they enter "
            "neither the ground truth nor the flagged set and move no rate here. Tier-2 records "
            "that a list of requirements is implemented (rule 4) are checkable, counted apart.",
        },
        "posture": {
            "true_assessed_min": min(true_assessed),
            "true_assessed_median": statistics.median(true_assessed),
            "true_assessed_max": max(true_assessed),
            "assessed_mae": statistics.fmean(abs_err),
            "documented_mean": statistics.fmean(documented),
            "note": "assessed score spans strong to weak posture; MAE is |ATLAS observed assessed "
            "minus true assessed| under the modelled detection error",
        },
    }


def _tier2_integrity(cases: list[EvalCase], *, seed: int) -> dict[str, Any]:
    engine = MappingEngine()
    qeng = QuestionnaireEngine()
    n_with_tier2 = precedence_total = precedence_correct = tier2_flagged = 0
    for case in cases:
        mappings = engine.map_findings(case.findings())
        t1 = tier1_assessments(mappings, unobserved=_unobserved(case))
        refuted = sorted({a.control_id for a in t1 if a.status == ComplianceStatus.NON_COMPLIANT})
        if not refuted:
            continue
        n_with_tier2 += 1
        questions = [
            Question(question_id=f"q-{cid}", control_id=cid, prompt_en=f"Is {cid} implemented?")
            for cid in refuted
        ]
        questionnaire = Questionnaire(
            questionnaire_id=f"tq-{case.case_id}", title="Internal controls", questions=questions
        )
        response = QuestionnaireResponse(
            questionnaire_id=questionnaire.questionnaire_id,
            respondent=f"ciso@{case.case_id}",
            consent_ref="eval",
            answers=[Answer(question_id=f"q-{cid}", compliant=True) for cid in refuted],
        )
        t2 = qeng.assessments(questionnaire, response)
        merged = merge_assessments(t1, t2, attestation_assessments(case.attestations, now=EVAL_EPOCH))
        status = {a.control_id: a.status for a in merged}
        flagged = {
            x.control_id
            for x in detect_contradictions([], mappings, tier2=t2)
            if x.tier == EvidenceTier.TIER_2
        }
        for cid in refuted:
            precedence_total += 1
            if status.get(cid) == ComplianceStatus.NON_COMPLIANT:
                precedence_correct += 1
            if cid in flagged:
                tier2_flagged += 1
    return {
        "n_orgs_with_tier2": n_with_tier2,
        "precedence_checks": precedence_total,
        "precedence_correct": precedence_correct,
        "precedence_rate": precedence_correct / precedence_total if precedence_total else 1.0,
        "tier2_flagged": tier2_flagged,
        "tier2_flag_rate": tier2_flagged / precedence_total if precedence_total else 1.0,
        "note": "three-tier assembly at scale: a Tier-2 compliant self-report on a control a Tier-1 "
        "finding refutes must not raise the score (lowest-tier-wins), and the contradiction check "
        "must flag it, so filing an overstatement as a Tier-2 record instead of a declaration "
        "(relabelling) does not escape the check. Tier-2 answers are synthesized, so this is a "
        "precedence-integrity check, not accuracy against experts.",
    }


def _simulated_annotations(preds: list[CasePrediction], *, seed: int) -> dict[str, Any]:
    rng = random.Random(seed + 991)
    n_raters = 5
    matrix: list[list[object]] = [[] for _ in range(n_raters)]
    for p in preds:
        true_coverage = len(p.true_gold)
        if true_coverage == 0:
            continue
        for r in range(n_raters):
            delta = 0 if rng.random() < _ANNOTATOR_AGREE_PROB else rng.choice([-1, 1])
            matrix[r].append(max(1, true_coverage + delta))
    have_data = bool(matrix[0])
    kappa = M.cohens_kappa(matrix[0], matrix[1]) if have_data else 1.0
    alpha_nom = float(M.krippendorff_alpha(matrix, level="nominal")) if have_data else 1.0
    alpha_ord = float(M.krippendorff_alpha(matrix, level="ordinal")) if have_data else 1.0
    return {
        "simulated": True,
        "note": "seeded 5-annotator simulation over true-control coverage; real expert panel pending",
        "cohen_kappa": kappa,
        "krippendorff_alpha_nominal": alpha_nom,
        "krippendorff_alpha_ordinal": alpha_ord,
        "n_raters": n_raters,
    }


def _sus(*, seed: int, n: int = 12) -> dict[str, Any]:
    rng = random.Random(seed + 777)
    responses = [
        [rng.randint(3, 5) if i % 2 == 0 else rng.randint(1, 3) for i in range(_SUS_ITEMS)] for _ in range(n)
    ]
    scores = [M.sus_score(r) for r in responses]
    ci = M.bootstrap_ci(scores, seed=seed)
    return {"simulated": True, "n": n, "mean": M.sus_mean(responses), "ci": _estimate(ci)}


def _latency(cases: list[EvalCase], preds: list[CasePrediction], *, seed: int) -> dict[str, Any]:
    atlas = [ATLAS_SECONDS_PER_FINDING * max(1, p.n_findings) for p in preds]
    baseline = [c.baseline_seconds for c in cases]
    speedups = [b / a for a, b in zip(atlas, baseline, strict=True)]
    ci = M.bootstrap_ci(speedups, seed=seed)
    return {
        "atlas_seconds_total": sum(atlas),
        "baseline_seconds_total": sum(baseline),
        "speedup_mean": _estimate(ci),
        "model": f"{ATLAS_SECONDS_PER_FINDING}s/finding vs modelled manual baseline",
    }


def _specificity(n_clean: int, *, seed: int | None) -> dict[str, Any]:
    from p2c.evaluation.synthetic import generate_clean_cases

    clean = generate_clean_cases(n_clean, seed=seed)
    preds = _predict(clean)
    n = len(preds)
    n_controls = len(TIER1_CHECKABLE)
    raw_clean = sum(1 for p in preds if not p.predicted)
    cor_clean = sum(1 for p in preds if not p.predicted_corroborated)
    raw_fp = sum(len(p.predicted) for p in preds)
    cor_fp = sum(len(p.predicted_corroborated) for p in preds)
    decisions = n * n_controls
    return {
        "n_clean_orgs": n,
        "default": {
            "org_true_negative_rate": raw_clean / n if n else 1.0,
            "control_true_negative_rate": (decisions - raw_fp) / decisions if decisions else 1.0,
            "mean_false_controls_per_org": raw_fp / n if n else 0.0,
        },
        "corroborated": {
            "org_true_negative_rate": cor_clean / n if n else 1.0,
            "control_true_negative_rate": (decisions - cor_fp) / decisions if decisions else 1.0,
            "mean_false_controls_per_org": cor_fp / n if n else 0.0,
        },
        "note": "on truly-clean estates the only findings are scanner false alarms. The org-level rate is "
        "deliberately strict (a single false challenge fails an org), so it reads near zero; the "
        "per-decision control-level rate is the fairer specificity. Corroboration cuts the ambiguous-signal "
        "false challenges (mean spurious controls per org), so an operator sees fewer on a well-run "
        "organization, though the rare high-confidence false alarm still raises one.",
    }


def _scan_realism(cases: list[EvalCase]) -> dict[str, Any]:
    cond_hosts: dict[str, int] = {}
    per_cond: dict[str, dict[str, float]] = {}
    competences: list[float] = []
    for c in cases:
        competences.append(c.scanner_competence)
        for cond in c.scan_conditions.values():
            cond_hosts[cond] = cond_hosts.get(cond, 0) + 1
        observed = {(i.asset, i.check) for i in c.injected}
        for inj in c.true_injected:
            if inj.check not in _HOST_FETCHED_CHECKS:
                continue
            cond = c.scan_conditions.get(inj.asset, "reachable")
            bucket = per_cond.setdefault(cond, {"true": 0.0, "detected": 0.0})
            bucket["true"] += 1
            if (inj.asset, inj.check) in observed:
                bucket["detected"] += 1
    for bucket in per_cond.values():
        bucket["recall"] = bucket["detected"] / bucket["true"] if bucket["true"] else 1.0
    return {
        "condition_host_counts": cond_hosts,
        "mean_competence": statistics.fmean(competences) if competences else 1.0,
        "host_fetched_detection_by_condition": per_cond,
        "note": "host-fetched detection by per-host scan condition; misses cluster on CDN-fronted and "
        "blocked hosts while reachable hosts are recovered at high recall (~0.90, residual from finite "
        "signal reliability, not acquisition). Control recovery stays high via cross-host co-evidence. "
        "See docs/detection-calibration.md.",
    }


def _realism(cases: list[EvalCase]) -> dict[str, Any]:
    category_counts: dict[str, int] = {}
    for c in cases:
        for inj in c.injected:
            cat = _CHECK_CATEGORY[inj.check]
            category_counts[cat] = category_counts.get(cat, 0) + 1
    sector_counts: dict[str, int] = {}
    for c in cases:
        sector_counts[c.sector] = sector_counts.get(c.sector, 0) + 1
    size_band_counts: dict[str, int] = {}
    for c in cases:
        size_band_counts[c.size_band] = size_band_counts.get(c.size_band, 0) + 1
    return {
        "category_finding_counts": category_counts,
        "sector_counts": sector_counts,
        "size_band_counts": size_band_counts,
    }


def _cohort_firms(cases: list[EvalCase], *, seed: int) -> dict[str, Any]:
    engine = MappingEngine()
    firms: list[dict[str, Any]] = []
    for case in cases:
        mappings = engine.map_findings(case.findings())
        score = compute_dual_score(_all_tier_assessments(case, mappings), universe=_documented_universe())
        claim_truth, claim_flags = _claim_flags(case, mappings, case.ground_truth.control_ids)
        true_states = {(i.asset, i.check) for i in case.true_injected}
        firms.append(
            {
                "case_id": case.case_id,
                "sector": case.sector,
                "size_band": case.size_band,
                "posture": case.posture,
                "n_hosts": len(case.profile.assets),
                "n_true_issues": len(case.true_injected),
                "n_findings": len(case.injected),
                "n_false_positives": sum(1 for i in case.injected if (i.asset, i.check) not in true_states),
                "n_declarations": len(case.attestations),
                "n_overstated": len(claim_truth),
                "n_flags": len(claim_flags),
                "n_flags_true": len(claim_flags & claim_truth),
                "n_flags_false": len(claim_flags - claim_truth),
                "assessed_score": round(score.assessed_score, 6),
                "documented_score": round(score.documented_score, 6),
            }
        )
    return {
        "seed": seed,
        "n_profiles": len(firms),
        "firms": sorted(firms, key=lambda f: f["case_id"]),
        "note": (
            "one record per synthetic firm of the reported seed: counts are the per-firm terms of "
            "the cohort totals (hosts, true issues, findings, false positives, declarations, "
            "overstatements) and the two scores are the assessed (Tier-1, 11 externally testable "
            "subcontrols) and documented (every evidenced control) shares the toolkit reports"
        ),
    }


def _dual_score_gap(cases: list[EvalCase], *, seed: int) -> dict[str, Any]:
    engine = MappingEngine()
    assessed: list[float] = []
    documented: list[float] = []
    coverage: list[float] = []
    evidence_coverage: list[float] = []
    gaps: list[float] = []
    off_surface_counts: list[int] = []
    tier2_3_only = 0
    must_answer_rows = sum(len(pool) for pool in _syn.off_surface_pools())
    mandatory = frozenset(c for c in _documented_universe() if _class_b_status().get(c) == "M")
    assessed_m: list[float] = []
    documented_m: list[float] = []
    worked: dict[str, Any] = {}
    for case in cases:
        mappings = engine.map_findings(case.findings())
        merged = _all_tier_assessments(case, mappings)
        score = compute_dual_score(merged, universe=_documented_universe())
        on_mandatory = compute_dual_score([a for a in merged if a.control_id in mandatory], universe=mandatory)
        assessed_m.append(on_mandatory.assessed_score)
        documented_m.append(on_mandatory.documented_score)
        assessed.append(score.assessed_score)
        coverage.append(score.coverage)
        evidence_coverage.append(score.evidence_coverage)
        documented.append(score.documented_score)
        gaps.append(score.documented_score - score.assessed_score)
        off_surface = sum(1 for a in merged if a.control_id not in TIER1_CHECKABLE)
        off_surface_counts.append(off_surface)
        tier2_3_only += sum(1 for a in merged if a.tier != EvidenceTier.TIER_1)
        if case.case_id == "eval-000":
            worked = {
                "case_id": case.case_id,
                "assessed": round(score.assessed_score, 6),
                "documented": round(score.documented_score, 6),
                "off_surface_controls": off_surface,
                "evidenced_controls": len(merged),
                "documented_universe": len(_documented_universe() | {a.control_id for a in merged}),
                "coverage": round(score.coverage, 6),
                "evidence_coverage": round(score.evidence_coverage, 6),
                "must_answer_remaining": must_answer_rows - off_surface,
                "must_answer_remaining_class_b_mandatory": sum(
                    1
                    for cid in _documented_universe() - TIER1_CHECKABLE - {a.control_id for a in merged}
                    if _class_b_status().get(cid) == "M"
                ),
                "n_declarations": len(case.attestations),
                "n_declarations_on_surface": sum(
                    1 for a in case.attestations if a.control_id in TIER1_CHECKABLE
                ),
            }
    n_differ = sum(1 for g in gaps if abs(g) > 1e-9)
    return {
        "n_profiles": len(cases),
        "gap_mean": round(statistics.fmean(gaps), 6),
        "gap_median": round(statistics.median(gaps), 6),
        "gap_min": round(min(gaps), 6),
        "gap_max": round(max(gaps), 6),
        "n_firms_scores_differ": n_differ,
        "share_firms_differ": round(n_differ / len(gaps), 6) if gaps else 0.0,
        "assessed_mean": round(statistics.fmean(assessed), 6),
        "documented_mean": round(statistics.fmean(documented), 6),
        "class_b_mandatory": {
            "n_rows": len(mandatory),
            "n_subcontrols": len(mandatory & frozenset(TIER1_CHECKABLE)),
            "assessed_mean": round(statistics.fmean(assessed_m), 6),
            "documented_mean": round(statistics.fmean(documented_m), 6),
            "n_firms_documented_lower": sum(1 for a, d in zip(assessed_m, documented_m, strict=True) if d < a),
        },
        "documented_universe": len(_documented_universe()),
        "coverage_mean": round(statistics.fmean(coverage), 6),
        "coverage_min": round(min(coverage), 6),
        "n_firms_not_fully_observed": sum(1 for c in coverage if c < 1.0),
        "n_firms_with_obstructed_host": sum(
            1 for c in cases if any(v in ("blocked", "cdn_fronted") for v in c.scan_conditions.values())
        ),
        "evidence_coverage_mean": round(statistics.fmean(evidence_coverage), 6),
        "evidence_coverage_min": round(min(evidence_coverage), 6),
        "evidence_coverage_max": round(max(evidence_coverage), 6),
        "off_surface_controls_mean": round(statistics.fmean(off_surface_counts), 2),
        "off_surface_controls_min": min(off_surface_counts),
        "off_surface_controls_max": max(off_surface_counts),
        "must_answer_rows": must_answer_rows,
        "surviving_tier2_3_only_assessments": tier2_3_only,
        "worked_firm": worked,
        "note": (
            "documented minus assessed across the cohort, under uniform (unweighted) control "
            "weights, the reported default. The assessed score is the share of the 11 externally "
            "testable subcontrols observed with no violation (a control the scan could not read "
            "never passes; coverage is the share it did read). The documented score is over a fixed "
            "set, the 11 plus every attestation-required row (197), each determined by its highest-priority "
            "evidence; a row with no evidence counts as not passing, so withholding evidence cannot "
            "raise it, and evidence coverage is the share of the 197 that is evidenced. Its level is "
            "driven by the declared off-surface evidence rates (OFF_SURFACE_COVERAGE), which have "
            "no source. A declaration on an externally testable control contributes nothing, because "
            "the evidence-precedence rule collapses it onto that control's Tier-1 assessment."
        ),
    }


COARSE_PARENT = "2-15-3"


def _parent_reading(cases: list[EvalCase], *, seed: int) -> dict[str, Any]:
    engine = MappingEngine()

    def block(remap: bool) -> dict[str, Any]:
        rec_pairs: list[tuple[set[str], set[str]]] = []
        c_tp = c_fp = c_fn = 0
        for case in cases:
            findings = case.findings()
            mappings = engine.map_findings(findings)
            true = set(case.ground_truth.control_ids)
            if remap:
                for f in findings:
                    chk = check_id_from_finding(f)
                    if chk is not None and chk.value in PARENT_READING_CHECKS:
                        mappings.append(
                            ControlMapping(
                                control_id=COARSE_PARENT,
                                framework="ecc",
                                tier=EvidenceTier.TIER_1,
                                finding_id=f.finding_id,
                                asset=f.asset,
                                severity=f.severity,
                                method=MappingMethod.DETERMINISTIC,
                                confidence=1.0,
                                rule_id=f"coarse-{chk.value}",
                            )
                        )
                if any(inj.check.value in PARENT_READING_CHECKS for inj in case.true_injected):
                    true.add(COARSE_PARENT)
            rec_pairs.append(({m.control_id for m in mappings}, true))
            gt, detected = _claim_flags(case, mappings, true)
            c_tp += len(gt & detected)
            c_fp += len(detected - gt)
            c_fn += len(gt - detected)
        rec = M.micro_prf(rec_pairs)
        con = M.prf_from_counts(c_tp, c_fp, c_fn)
        return {
            "recovery": {
                "precision": round(rec.precision, 6),
                "recall": round(rec.recall, 6),
                "f1": round(rec.f1, 6),
            },
            "contradiction": {
                "precision": round(con.precision, 6),
                "recall": round(con.recall, 6),
                "f1": round(con.f1, 6),
            },
        }

    sens = parent_reading_sensitivity(len(cases), seed=seed)
    fine = block(False)
    coarse = block(True)
    for label, dst in (("as_shipped", fine), ("parent_reading", coarse)):
        dst["modal_control"] = sens[label]["modal_control"]
        dst["modal_share"] = sens[label]["modal_share"]
        dst["constant_mapper_f1"] = sens[label]["constant_mapper_f1"]
    return {
        "n_checks_moved": len(PARENT_READING_CHECKS),
        "moved_checks": sorted(PARENT_READING_CHECKS),
        "fine": fine,
        "coarse": coarse,
        "note": (
            "recovery (end-to-end micro P/R/F1) and contradiction P/R/F1 as shipped (the seven web "
            "hardening checks recorded against no control) and under the coarse reading (the same "
            "checks recorded at the parent 2-15-3), with the finding-weighted modal share and the "
            "constant-mapper floor from parent_reading_sensitivity. Each reading is scored on its own "
            "truth, and the direction-sensitive relation never lets a parent-level finding flag or make "
            "true a subcontrol declaration. As shipped is the object the expert panel tests and is held "
            "fixed."
        ),
    }


def relinked_reading(
    table: Mapping[CheckId, frozenset[str]], n: int = 100, *, seed: int | None = None
) -> dict[str, Any]:
    resolved = get_settings().global_seed if seed is None else seed
    cases = generate_cases(n, seed=resolved)
    engine = MappingEngine()

    def block(links: Mapping[CheckId, frozenset[str]]) -> dict[str, Any]:
        rec_pairs: list[tuple[set[str], set[str]]] = []
        c_tp = c_fp = c_fn = 0
        for case in cases:
            mappings = engine.map_findings(case.findings())
            true = {cid for inj in case.true_injected for cid in links.get(inj.check, frozenset())}
            rec_pairs.append(({m.control_id for m in mappings}, true))
            gt, detected = _claim_flags(case, mappings, true)
            c_tp += len(gt & detected)
            c_fp += len(detected - gt)
            c_fn += len(gt - detected)
        rec, con = M.micro_prf(rec_pairs), M.prf_from_counts(c_tp, c_fp, c_fn)
        return {
            "violation_detection": {k: round(getattr(rec, k), 6) for k in ("precision", "recall", "f1")},
            "contradiction": {k: round(getattr(con, k), 6) for k in ("precision", "recall", "f1")},
        }

    return {
        "seed": resolved,
        "n_firms": len(cases),
        "against_curated": block(expert_key()),
        "against_table": block(table),
    }


def kept_tier1_reading(kept: Collection[str], n: int = 100, *, seed: int | None = None) -> dict[str, Any]:
    resolved = get_settings().global_seed if seed is None else seed
    keep, cases, engine = set(kept), generate_cases(n, seed=resolved), MappingEngine()
    rec_pairs: list[tuple[set[str], set[str]]] = []
    c_tp = c_fp = c_fn = 0
    for case in cases:
        mappings = [m for m in engine.map_findings(case.findings()) if m.control_id in keep]
        true = {cid for inj in case.true_injected for cid in expert_key().get(inj.check, ()) if cid in keep}
        rec_pairs.append(({m.control_id for m in mappings}, true))
        gt, detected = _claim_flags(case, mappings, true)
        c_tp += len(gt & detected)
        c_fp += len(detected - gt)
        c_fn += len(gt - detected)
    rec, con = M.micro_prf(rec_pairs), M.prf_from_counts(c_tp, c_fp, c_fn)
    return {
        "seed": resolved,
        "kept_subcontrols": sorted(keep),
        "violation_detection": {k: round(getattr(rec, k), 6) for k in ("precision", "recall", "f1")},
        "contradiction": {k: round(getattr(con, k), 6) for k in ("precision", "recall", "f1")},
    }


def _evidence_level(cases: list[EvalCase]) -> dict[str, float]:
    key = expert_key()

    def controls(findings: list[Any]) -> frozenset[str]:
        return frozenset(c for f in findings for c in key[f.check])

    tp = fp = fn = 0
    for case in cases:
        true = {(i.asset, i.check) for i in case.true_injected}
        predicted = controls(list(case.injected))
        supported = controls([i for i in case.injected if (i.asset, i.check) in true])
        gold = case.ground_truth.control_ids
        tp, fp, fn = tp + len(supported & gold), fp + len(predicted - supported), fn + len(gold - supported)
    prf = M.prf_from_counts(tp, fp, fn)
    return {"precision": prf.precision, "recall": prf.recall, "f1": prf.f1, "tp": tp, "fp": fp, "fn": fn}


def run_evaluation(n: int = 100, *, seed: int | None = None) -> EvaluationReport:
    resolved = get_settings().global_seed if seed is None else seed
    cases = generate_cases(n, seed=resolved)
    preds = _predict(cases)
    governance = _governance(cases, seed=resolved)
    return EvaluationReport(
        seed=resolved,
        n_profiles=len(cases),
        n_findings=sum(len(c.injected) for c in cases),
        n_true_findings=sum(len(c.true_injected) for c in cases),
        sector_counts={s: sum(1 for c in cases if c.sector == s) for s in sorted({c.sector for c in cases})},
        size_band_counts={
            b: sum(1 for c in cases if c.size_band == b) for b in sorted({c.size_band for c in cases})
        },
        mapping=_mapping_metrics(preds, seed=resolved),
        end_to_end={**_end_to_end_metrics(preds, seed=resolved), "evidence_level": _evidence_level(cases)},
        end_to_end_corroborated=_end_to_end_corroborated_metrics(preds, seed=resolved),
        per_sector=_per_sector(preds, seed=resolved),
        per_posture=_per_posture(preds, seed=resolved),
        per_size=_per_size(preds, seed=resolved),
        trivial_floor=_trivial_floor(preds),
        detection_ceiling=_detection_ceiling(cases),
        implemented_only=_implemented_only(cases),
        rate_class_slice=_rate_class_slice(cases),
        per_control=_per_control(preds),
        effect_size=_effect_size(preds),
        ablation=naive_keyword_baseline(n, seed=resolved),
        baselines=hermetic_baselines(n, seed=resolved),
        detection=_detection(cases),
        contradictions=governance["contradictions"],
        posture=governance["posture"],
        agreement=_simulated_annotations(preds, seed=resolved),
        sus=_sus(seed=resolved),
        latency=_latency(cases, preds, seed=resolved),
        weighting=sensitivity_to_weighting(n, seed=resolved),
        realism=_realism(cases),
        scan_realism=_scan_realism(cases),
        specificity=_specificity(max(20, n // 3), seed=resolved),
        tier2_integrity=_tier2_integrity(cases, seed=resolved),
        dual_score_gap=_dual_score_gap(cases, seed=resolved),
        parent_reading=_parent_reading(cases, seed=resolved),
        cohort_firms=_cohort_firms(cases, seed=resolved),
    )


def stability_across_seeds(
    n: int = 100,
    seeds: tuple[int, ...] = (
        1337,
        2025,
        3,
        202,
        303,
        404,
        505,
        606,
        707,
        808,
        909,
        1234,
        4242,
        5150,
        8675,
        314159,
        271828,
        161803,
        10_000,
        20_000,
        30_000,
        40_000,
        50_000,
        60_000,
        70_000,
        80_000,
        90_000,
        100_000,
        110_000,
        120_000,
    ),
) -> dict[str, Any]:
    ordered = sorted(seeds)
    if any(b - a < n for a, b in itertools.pairwise(ordered)):
        raise ValueError(f"seeds closer than {n} share firms (firm i of seed s uses s + i)")
    f1s = [run_evaluation(n, seed=s).end_to_end["exact_micro"]["f1"] for s in seeds]
    return {
        "seeds": list(seeds),
        "end_to_end_f1": f1s,
        "mean": statistics.fmean(f1s),
        "stdev": statistics.pstdev(f1s),
        "min": min(f1s),
        "max": max(f1s),
    }


def sensitivity_to_detection_assumptions(
    n: int = 100, *, shifts: tuple[float, ...] = (-0.10, -0.05, 0.05, 0.10), seed: int | None = None
) -> dict[str, Any]:
    base_sens = dict(_syn.SENSITIVITY)
    base_fa = dict(_syn.FALSE_ALARM)
    results: dict[str, float] = {}
    try:
        for s in shifts:
            for cid, sens in base_sens.items():
                _syn.SENSITIVITY[cid] = min(1.0, max(0.0, sens + s))
                _syn.FALSE_ALARM[cid] = min(1.0, max(0.0, base_fa[cid] - s))
            results[f"{s:+.2f}"] = run_evaluation(n, seed=seed).end_to_end["exact_micro"]["f1"]
    finally:
        _syn.SENSITIVITY.update(base_sens)
        _syn.FALSE_ALARM.update(base_fa)
    baseline_f1 = run_evaluation(n, seed=seed).end_to_end["exact_micro"]["f1"]
    band = [baseline_f1, *results.values()]
    return {"baseline_f1": baseline_f1, "shifted_f1": results, "min": min(band), "max": max(band)}


def sensitivity_to_attestation_rate(
    n: int = 100, *, rates: tuple[float, ...] = (0.30, 0.50, 0.70), seed: int | None = None
) -> dict[str, Any]:
    base = _syn.P_OVERSTATE
    out: dict[str, Any] = {}
    try:
        for r in rates:
            _syn.P_OVERSTATE = r
            c = run_evaluation(n, seed=seed).contradictions
            out[f"{r:.2f}"] = {"precision": c["precision"], "recall": c["recall"], "f1": c["f1"]}
    finally:
        _syn.P_OVERSTATE = base
    return out


def sensitivity_to_scan_conditions(
    n: int = 100, *, obstruction_scales: tuple[float, ...] = (0.5, 1.5, 2.0), seed: int | None = None
) -> dict[str, Any]:
    base = dict(_syn.CONDITION_SHARES)
    obstructed = ("throttled", "cdn_fronted", "blocked")
    results: dict[str, float] = {}
    try:
        for scale in obstruction_scales:
            scaled = {k: min(1.0, base[k] * scale) for k in obstructed}
            reachable = max(0.0, 1.0 - sum(scaled.values()))
            _syn.CONDITION_SHARES.update({"reachable": reachable, **scaled})
            results[f"{scale:.1f}x"] = run_evaluation(n, seed=seed).end_to_end["exact_micro"]["f1"]
    finally:
        _syn.CONDITION_SHARES.update(base)
    baseline_f1 = run_evaluation(n, seed=seed).end_to_end["exact_micro"]["f1"]
    band = [baseline_f1, *results.values()]
    return {
        "baseline_f1": baseline_f1,
        "scaled_f1": results,
        "min": min(band),
        "max": max(band),
        "note": "end-to-end F1 as the obstructed-host share is scaled 0.5x to 2x; the freed or taken "
        "mass moves to or from reachable. Shows the result is not knife-edge on the obstruction rate.",
    }


def sensitivity_to_corpus_priors(
    n: int = 100, *, factors: tuple[float, ...] = (0.8, 0.9, 1.1, 1.2), seed: int | None = None
) -> dict[str, Any]:
    base_weights = {s.name: dict(s.weights) for s in _syn.SECTORS}
    base_subset = dict(_syn._SUBSET_PROB)
    results: dict[str, float] = {}
    try:
        for f in factors:
            for s in _syn.SECTORS:
                for k, v in base_weights[s.name].items():
                    s.weights[k] = min(1.0, max(0.0, v * f))
            for cid, p in base_subset.items():
                _syn._SUBSET_PROB[cid] = min(1.0, max(0.0, p * f))
            results[f"{f:.2f}"] = run_evaluation(n, seed=seed).end_to_end["exact_micro"]["f1"]
    finally:
        for s in _syn.SECTORS:
            s.weights.update(base_weights[s.name])
        _syn._SUBSET_PROB.update(base_subset)
    baseline_f1 = run_evaluation(n, seed=seed).end_to_end["exact_micro"]["f1"]
    band = [baseline_f1, *results.values()]
    return {
        "baseline_f1": baseline_f1,
        "scaled_f1": results,
        "min": min(band),
        "max": max(band),
        "note": "end-to-end F1 under a common +-20% scaling of the sector weights and conditional "
        "propensities (incident-informed declared priors, SOURCES.md section 4); shows the result "
        "is not knife-edge on them",
    }


_TIER1_SUBDOMAIN_PRIORITY: dict[str, int] = {
    "2-4": 7,
    "2-5": 6,
    "2-15": 5,
    "2-2": 4,
    "2-8": 3,
    "2-10": 2,
    "2-3": 1,
}
_SAATY_MAX = 9


def _saaty_round(ratio: float) -> float:
    if ratio >= 1.0:
        return float(min(_SAATY_MAX, max(1, round(ratio))))
    return 1.0 / float(min(_SAATY_MAX, max(1, round(1.0 / ratio))))


def _ahp_subdomain_weights(subdomains: list[str]) -> tuple[dict[str, float], float]:
    order = sorted(subdomains)
    priorities = [float(_TIER1_SUBDOMAIN_PRIORITY.get(s, 1)) for s in order]
    size = len(order)
    matrix = [[1.0] * size for _ in range(size)]
    for i in range(size):
        for j in range(i + 1, size):
            a_ij = _saaty_round(priorities[i] / priorities[j])
            matrix[i][j] = a_ij
            matrix[j][i] = 1.0 / a_ij
    result = ahp_weights(matrix)
    return dict(zip(order, result.weights, strict=True)), result.consistency_ratio


def sensitivity_to_weighting(n: int = 100, *, seed: int | None = None) -> dict[str, Any]:
    from scipy.stats import spearmanr

    resolved = get_settings().global_seed if seed is None else seed
    cases = generate_cases(n, seed=resolved)
    engine = MappingEngine()
    subdomains = sorted({"-".join(cid.split("-")[:2]) for cid in TIER1_CHECKABLE})
    weights, cr = _ahp_subdomain_weights(subdomains)
    uniform: list[float] = []
    weighted: list[float] = []
    for case in cases:
        tier1 = tier1_assessments(engine.map_findings(case.findings()), unobserved=_unobserved(case))
        uniform.append(compute_dual_score(tier1).assessed_score)
        weighted.append(
            compute_dual_score(
                apply_weights(tier1, weights, key="subdomain"), weights_source="ahp"
            ).assessed_score
        )
    deltas = [abs(u - w) for u, w in zip(uniform, weighted, strict=True)]
    rho = spearmanr(uniform, weighted).statistic if len(uniform) > 1 else 1.0
    return {
        "ahp_consistency_ratio": cr,
        "ahp_consistent": cr <= CR_THRESHOLD,
        "subdomain_weights": weights,
        "assessed_mean_abs_delta": statistics.fmean(deltas),
        "assessed_max_abs_delta": max(deltas),
        "assessed_rank_spearman": float(rho),
        "note": "uniform vs illustrative AHP subdomain weighting (consistency-gated). Reweighting has "
        "a bounded effect on the assessed score (mean and max |delta|, rank correlation reported), "
        "which is why the paper reports uniform-weighted scores and treats the assessed score as a "
        "lower bound pending the expert AHP elicitation. The end-to-end recovery is an unweighted set "
        "measure and is unaffected by weighting.",
    }


def precision_stress(
    n: int = 100, *, fa_scales: tuple[float, ...] = (1.5, 2.0), seed: int | None = None
) -> dict[str, Any]:
    base_fa = dict(_syn.FALSE_ALARM)
    out: dict[str, Any] = {}
    try:
        for scale in fa_scales:
            for cid, fa in base_fa.items():
                _syn.FALSE_ALARM[cid] = min(1.0, fa * scale)
            report = run_evaluation(n, seed=seed)
            exact = report.end_to_end["exact_micro"]
            out[f"{scale:.1f}x"] = {
                "precision": exact["precision"],
                "recall": exact["recall"],
                "f1": exact["f1"],
                "strong_precision": report.per_posture["strong"]["precision"],
            }
    finally:
        _syn.FALSE_ALARM.update(base_fa)
    return {
        "fa_scaled": out,
        "note": "false-alarm rates scaled up with sensitivity held; reports precision and "
        "strong-posture precision, answering whether the false-alarm assumptions are too low.",
    }


def worst_case_corner(n: int = 100, *, seed: int | None = None) -> dict[str, Any]:
    from p2c.evaluation.appendix_tables import DETERMINISTIC_MIN

    base_sens = dict(_syn.SENSITIVITY)
    base_fa = dict(_syn.FALSE_ALARM)
    judged = [cid for cid, sens in base_sens.items() if sens < DETERMINISTIC_MIN]
    try:
        for cid in judged:
            _syn.FALSE_ALARM[cid] = min(1.0, base_fa[cid] * 2.0)
            _syn.SENSITIVITY[cid] = max(0.0, base_sens[cid] * 0.8)
        report = run_evaluation(n, seed=seed)
        exact = report.end_to_end["exact_micro"]
        corner = {
            "precision": exact["precision"],
            "recall": exact["recall"],
            "f1": exact["f1"],
            "strong_precision": report.per_posture["strong"]["precision"],
        }
    finally:
        _syn.SENSITIVITY.update(base_sens)
        _syn.FALSE_ALARM.update(base_fa)
    return {
        "corner": corner,
        "note": "all nine analyst-judgement checks at their pessimistic end at once (false alarm x2, "
        "sensitivity x0.8): a defended simultaneous worst case for the scanner-dependent numbers.",
    }


def detection_uncertainty_ensemble(n: int = 100, *, draws: int = 500, seed: int = 1337) -> dict[str, Any]:
    from p2c.evaluation.appendix_tables import DETERMINISTIC_MIN

    rng = random.Random(seed)
    base_sens = dict(_syn.SENSITIVITY)
    base_fa = dict(_syn.FALSE_ALARM)
    judged = frozenset(cid for cid, sens in base_sens.items() if sens < DETERMINISTIC_MIN)

    def _sample(mean: float, *, wide: bool) -> float:
        if not 0.0 < mean < 1.0:
            return mean
        kappa = 25.0 if wide else 250.0
        return rng.betavariate(mean * kappa, (1.0 - mean) * kappa)

    f1s: list[float] = []
    precisions: list[float] = []
    fa_samples: dict[str, list[float]] = {c.value: [] for c in base_fa}
    try:
        for _ in range(draws):
            for cid, mean in base_sens.items():
                _syn.SENSITIVITY[cid] = _sample(mean, wide=cid in judged)
            for cid, mean in base_fa.items():
                drawn = _sample(mean, wide=cid in judged)
                _syn.FALSE_ALARM[cid] = drawn
                fa_samples[cid.value].append(drawn)
            exact = run_evaluation(n, seed=seed).end_to_end["exact_micro"]
            f1s.append(exact["f1"])
            precisions.append(exact["precision"])
    finally:
        _syn.SENSITIVITY.update(base_sens)
        _syn.FALSE_ALARM.update(base_fa)

    def _pct(values: list[float], p: float) -> float:
        ordered = sorted(values)
        return round(ordered[min(len(ordered) - 1, max(0, round(p * (len(ordered) - 1))))], 3)

    drivers: list[tuple[str, float]] = []
    for cid_value, samples in fa_samples.items():
        if len(set(samples)) > 1:
            drivers.append((cid_value, round(statistics.correlation(samples, f1s), 3)))
    drivers.sort(key=lambda t: -abs(t[1]))
    return {
        "draws": draws,
        "f1_median": _pct(f1s, 0.5),
        "f1_predictive_interval": [_pct(f1s, 0.025), _pct(f1s, 0.975)],
        "precision_median": _pct(precisions, 0.5),
        "precision_predictive_interval": [_pct(precisions, 0.025), _pct(precisions, 0.975)],
        "top_variance_drivers": drivers[:5],
        "note": "Monte-Carlo ensemble with per-check Beta priors (wide for the nine analyst-judgement checks, tight "
        "for the reads and probes); the predictive interval is the honest uncertainty from the modelled "
        "detection rates, distinct from the per-run bootstrap CI which is corpus-sampling variability.",
    }


def robustness_report(
    n: int = 100,
    *,
    seed: int | None = None,
    ensemble_draws: int = 2000,
) -> dict[str, Any]:
    return {
        "stability_across_seeds": stability_across_seeds(n),
        "detection_sensitivity": sensitivity_to_detection_assumptions(n, seed=seed),
        "precision_stress": precision_stress(n, seed=seed),
        "worst_case_corner": worst_case_corner(n, seed=seed),
        "detection_uncertainty_ensemble": detection_uncertainty_ensemble(n, draws=ensemble_draws),
        "scan_conditions": sensitivity_to_scan_conditions(n, seed=seed),
        "attestation_sensitivity": sensitivity_to_attestation_rate(n, seed=seed),
        "corpus_priors": sensitivity_to_corpus_priors(n, seed=seed),
        "weighting": sensitivity_to_weighting(n, seed=seed),
    }


def exposure_toward_anchors(
    n: int = 100, *, factors: tuple[float, ...] = (1.0, 1.5, 2.0, 3.0), seed: int | None = None
) -> dict[str, Any]:
    base_weights = {s.name: dict(s.weights) for s in _syn.SECTORS}
    base_subset = dict(_syn._SUBSET_PROB)
    rows: dict[str, Any] = {}
    try:
        for f in factors:
            for sector in _syn.SECTORS:
                for k, v in base_weights[sector.name].items():
                    sector.weights[k] = min(1.0, max(0.0, v * f))
            for cid, p in base_subset.items():
                _syn._SUBSET_PROB[cid] = min(1.0, max(0.0, p * f))
            report = run_evaluation(n, seed=seed)
            anchors = exposure_anchor_report(n, seed=seed)
            floor = report.trivial_floor["corpus"]
            rows[f"{f:.2f}"] = {
                "realized_missing_csp_per_host": anchors["realized_exposure"]["web_headers_per_host"][
                    "missing_csp"
                ],
                "realized_exposure": anchors["realized_exposure"],
                "precision": round(report.end_to_end["exact_micro"]["precision"], 6),
                "base_rate": floor["base_rate"],
                "f1": round(report.end_to_end["exact_micro"]["f1"], 6),
                "mcc": round(report.end_to_end["decision_universe"]["mcc"], 6),
                "balanced_accuracy": round(report.end_to_end["decision_universe"]["balanced_accuracy"], 6),
                "predict_all_f1": floor["f1"],
                "predict_all_mcc": floor["mcc"],
                "predict_all_balanced_accuracy": floor["balanced_accuracy"],
            }
    finally:
        for sector in _syn.SECTORS:
            sector.weights.update(base_weights[sector.name])
        _syn._SUBSET_PROB.update(base_subset)
    return {
        "n_profiles": n,
        "factors": [f"{f:.2f}" for f in factors],
        "by_factor": rows,
        "published_missing_csp": {"global": 0.81, "saudi_audience": 0.76},
        "note": "exposure scaled toward the published anchors; F1 and the predict-all floor rise together, "
        "while MCC and balanced accuracy, on which the floor is fixed at 0 and 0.5, show the margin.",
    }


_GOVERNANCE_DOMAIN = "1"
_DEFENCE_DOMAIN = "2"
_EVAL_DIR = Path(__file__).resolve().parents[3] / "evaluation"


def mapper_disagreement_audit(model: str = "gemma3:12b", condition: str = "title") -> dict[str, Any]:
    from p2c.mapping.catalog import load_default_index

    preds = json.loads((_EVAL_DIR / "baseline_ladder_predictions.json").read_text(encoding="utf-8"))
    picks = preds[model][condition]
    index = load_default_index()
    key = expert_key()

    def title(cid: str) -> str:
        entry = index.get(cid)
        return entry.title if entry is not None else ""

    def subdomain(cid: str) -> str:
        return "-".join(cid.split("-")[:2])

    detectors: list[dict[str, Any]] = []
    kinds = {
        "same_subdomain": 0,
        "governance_domain": 0,
        "other_defence_subdomain": 0,
        "elsewhere": 0,
        "no_answer": 0,
        "curated_none": 0,
    }
    tier1_picks = 0
    for check in sorted((c for c in key if c.value in picks), key=lambda c: c.value):
        curated = sorted(key[check])
        pick = picks.get(check.value)
        agrees = pick in curated
        kind = None
        if not agrees:
            if not pick:
                kind = "no_answer"
            elif not curated:
                kind = "curated_none"
            elif any(subdomain(pick) == subdomain(c) for c in curated):
                kind = "same_subdomain"
            elif pick.split("-")[0] == _GOVERNANCE_DOMAIN:
                kind = "governance_domain"
            elif pick.split("-")[0] == _DEFENCE_DOMAIN:
                kind = "other_defence_subdomain"
            else:
                kind = "elsewhere"
            kinds[kind] += 1
            tier1_picks += int(bool(pick) and pick in TIER1_CHECKABLE)
        detectors.append(
            {
                "detector": check.value,
                "curated": [{"id": c, "title": title(c)} for c in curated],
                "pick": {"id": pick, "title": title(pick)} if pick else None,
                "agrees": agrees,
                "disagreement": kind,
            }
        )
    return {
        "model": model,
        "condition": condition,
        "n_detectors": len(detectors),
        "n_disagreements": sum(1 for d in detectors if not d["agrees"]),
        "disagreement_kinds": kinds,
        "disagreeing_picks_externally_testable": tier1_picks,
        "detectors": detectors,
        "note": "single-pick output of the best generic mapper against the curated table, per detector; "
        "the disagreement class is positional (same subdomain, governance domain, elsewhere), read from "
        "the identifiers, so it describes where the pick lands, not who is right.",
    }


_VERSION_CHECKS: frozenset[str] = frozenset({"outdated_exposed_software", "eol_software_exposed"})
_MARKER_CHECKS: frozenset[str] = frozenset({"exposed_dev_environment"})
_SPOOFABLE_CHECKS: frozenset[str] = _VERSION_CHECKS | _MARKER_CHECKS | {"waf_absent"}


def _block_hosts(case: EvalCase, hosts: set[str]) -> EvalCase:
    from p2c.evaluation import synthetic as S

    conditions = dict(case.scan_conditions)
    kept = tuple(i for i in case.injected if not (i.asset in hosts and i.check in S._HOST_FETCHED_CHECKS))
    for host in hosts:
        conditions[host] = "blocked"
    return dataclasses.replace(case, injected=kept, scan_conditions=conditions)


def _throttle_hosts(case: EvalCase, rng: random.Random) -> EvalCase:
    from p2c.evaluation import synthetic as S

    conditions = dict(case.scan_conditions)
    targets = {h for h, c in conditions.items() if c == "reachable"}
    kept = []
    for inj in case.injected:
        if inj.asset in targets and inj.check in S._HOST_FETCHED_CHECKS:
            ratio = S._condition_factor(inj.check, "throttled") / S._condition_factor(inj.check, "reachable")
            if rng.random() >= ratio:
                continue
        kept.append(inj)
    for host in targets:
        conditions[host] = "throttled"
    return dataclasses.replace(case, injected=tuple(kept), scan_conditions=conditions)


def _scope(case: EvalCase, hosts: set[str]) -> EvalCase:
    return dataclasses.replace(
        case,
        injected=tuple(i for i in case.injected if i.asset in hosts),
        scan_conditions={h: c for h, c in case.scan_conditions.items() if h in hosts},
    )


def _without_checks(case: EvalCase, checks: frozenset[str]) -> EvalCase:
    return dataclasses.replace(case, injected=tuple(i for i in case.injected if i.check.value not in checks))


def _overstated_on_surface(case: EvalCase) -> list[str]:
    truth = case.ground_truth.control_ids
    return [
        a.control_id
        for a in case.attestations
        if a.valid_from <= EVAL_EPOCH <= a.valid_until
        and a.control_id in TIER1_CHECKABLE
        and any(control_related(a.control_id, t) for t in truth)
    ]


def _evasion_block(variants: list[tuple[EvalCase, frozenset[tuple[str, Any]]]]) -> dict[str, Any]:
    engine = MappingEngine()
    old: list[float] = []
    new: list[float] = []
    coverage: list[float] = []
    tp = fn = unverified = 0
    for case, unread in variants:
        mappings = engine.map_findings(case.findings())
        unobserved = _unobserved(case, unread)
        old.append(compute_dual_score(tier1_assessments(mappings, unobserved=frozenset())).assessed_score)
        score = compute_dual_score(tier1_assessments(mappings, unobserved=unobserved))
        new.append(score.assessed_score)
        coverage.append(score.coverage)
        flagged = {x.control_id for x in detect_contradictions(case.attestations, mappings, now=EVAL_EPOCH)}
        over = _overstated_on_surface(case)
        tp += sum(1 for c in over if c in flagged)
        fn += sum(1 for c in over if c not in flagged)
        not_observed = unobserved - {m.control_id for m in mappings}
        unverified += sum(
            1
            for a in case.attestations
            if a.valid_from <= EVAL_EPOCH <= a.valid_until and a.control_id in not_observed
        )
    return {
        "assessed_absent_is_pass": round(statistics.fmean(old), 6),
        "assessed": round(statistics.fmean(new), 6),
        "coverage": round(statistics.fmean(coverage), 6),
        "contradiction_recall": round(tp / (tp + fn), 6) if tp + fn else 0.0,
        "n_overstated": tp + fn,
        "declarations_on_unobserved_controls": unverified,
    }


_ONE_YEAR = timedelta(days=365)


def _declarer_recall(cases: list[EvalCase], choose: Any) -> dict[str, Any]:
    engine = MappingEngine()
    tp = total = 0
    for case in cases:
        mappings = engine.map_findings(case.findings())
        chosen = choose(case, mappings)
        claims = [
            Attestation(
                attestation_id=f"adaptive:{case.case_id}:{cid}",
                control_id=cid,
                statement="control fully implemented",
                signer_identity="declarer",
                payload_hash="adaptive",
                valid_from=EVAL_EPOCH - _ONE_YEAR,
                valid_until=EVAL_EPOCH + _ONE_YEAR,
            )
            for cid in chosen
        ]
        flagged = {x.control_id for x in detect_contradictions(claims, mappings, now=EVAL_EPOCH)}
        total += len(chosen)
        tp += sum(1 for cid in chosen if cid in flagged)
    return {"n_overstated": total, "contradiction_recall": round(tp / total, 6) if total else 0.0}


def evasion_report(n: int = 100, *, seed: int | None = None) -> dict[str, Any]:
    resolved = get_settings().global_seed if seed is None else seed
    cases = generate_cases(n, seed=resolved)

    def subdomains(case: EvalCase) -> list[str]:
        return sorted(h for h in case.scan_conditions if h != case.profile.apex)

    def version_unread(case: EvalCase) -> frozenset[tuple[str, Any]]:
        return frozenset(
            (h, c) for h in case.scan_conditions for c in expert_key() if c.value in _VERSION_CHECKS
        )

    half_rng = random.Random(resolved + 4049)
    throttle_rng = random.Random(resolved + 4051)
    scenarios: dict[str, Any] = {}
    scenarios["baseline"] = _evasion_block([(c, frozenset()) for c in cases])
    scenarios["block_all_hosts"] = _evasion_block(
        [(_block_hosts(c, set(c.scan_conditions)), frozenset()) for c in cases]
    )
    halves: list[tuple[EvalCase, frozenset[tuple[str, Any]]]] = []
    for c in cases:
        subs = subdomains(c)
        halves.append((_block_hosts(c, set(half_rng.sample(subs, (len(subs) + 1) // 2))), frozenset()))
    scenarios["block_half_subdomains"] = _evasion_block(halves)
    scenarios["throttle_all_hosts"] = _evasion_block(
        [(_throttle_hosts(c, throttle_rng), frozenset()) for c in cases]
    )
    scenarios["omit_apex"] = _evasion_block([(_scope(c, set()), frozenset()) for c in cases])
    scenarios["omit_subdomains"] = _evasion_block([(_scope(c, {c.profile.apex}), frozenset()) for c in cases])
    scenarios["banner_suppression"] = _evasion_block(
        [(_without_checks(c, _VERSION_CHECKS | _MARKER_CHECKS), version_unread(c)) for c in cases]
    )
    scenarios["string_spoofing"] = _evasion_block(
        [(_without_checks(c, _SPOOFABLE_CHECKS), frozenset()) for c in cases]
    )

    engine = MappingEngine()
    r_old = r_new = r_total = 0
    for case in cases:
        mappings = engine.map_findings(case.findings())
        over = set(_overstated_on_surface(case))
        kept = tuple(a for a in case.attestations if a.control_id not in over)
        records = [
            ControlAssessment(
                control_id=cid,
                tier=EvidenceTier.TIER_2,
                status=ComplianceStatus.COMPLIANT,
                evidence_ids=[f"relabelled:{cid}"],
                source="questionnaire",
            )
            for cid in sorted(over)
        ]
        old_flags = {x.control_id for x in detect_contradictions(kept, mappings, now=EVAL_EPOCH)}
        new_flags = {
            x.control_id
            for x in detect_contradictions(kept, mappings, now=EVAL_EPOCH, tier2=records)
            if x.tier == EvidenceTier.TIER_2
        }
        r_total += len(over)
        r_old += len(over & old_flags)
        r_new += len(over & new_flags)
    scenarios["relabel_tier2"] = {
        "n_overstated": r_total,
        "contradiction_recall_old_check": round(r_old / r_total, 6) if r_total else 0.0,
        "contradiction_recall": round(r_new / r_total, 6) if r_total else 0.0,
    }

    key = expert_key()
    by_control: dict[str, list[Any]] = {}
    for check, gold in key.items():
        for cid in gold:
            by_control.setdefault(cid, []).append(check)

    def p_any(case: EvalCase, cid: str) -> float:
        present = {(i.asset, i.check) for i in case.true_injected}
        miss = 1.0
        for host in case.scan_conditions:
            for check in by_control.get(cid, []):
                miss *= 1.0 - _p_finding(check, host, case, (host, check) in present)
        return 1.0 - miss

    def white_box(case: EvalCase, _mappings: Any) -> list[str]:
        violated = sorted(case.ground_truth.control_ids & TIER1_CHECKABLE)
        return sorted(violated, key=lambda c: (p_any(case, c), c))[: len(_overstated_on_surface(case))]

    missed_total = violated_total = 0

    def oracle(case: EvalCase, mappings: Any) -> list[str]:
        nonlocal missed_total, violated_total
        violated = sorted(case.ground_truth.control_ids & TIER1_CHECKABLE)
        found = {m.control_id for m in mappings}
        missed = [c for c in violated if c not in found]
        missed_total += len(missed)
        violated_total += len(violated)
        rest = sorted((c for c in violated if c in found), key=lambda c: (p_any(case, c), c))
        return (missed + rest)[: len(_overstated_on_surface(case))]

    scenarios["adaptive_declarer"] = _declarer_recall(cases, white_box)
    scenarios["oracle_declarer"] = _declarer_recall(cases, oracle)
    scenarios["oracle_declarer"]["violations_missed"] = missed_total
    scenarios["oracle_declarer"]["violations_total"] = violated_total
    return {
        "n_profiles": n,
        "seed": resolved,
        "scenarios": scenarios,
        "note": "evasions 2 to 5 run against the same cohort, true issues and declarations held fixed. "
        "assessed_absent_is_pass is the assessed score under the replaced rule (an absent finding counted "
        "as a pass); assessed uses observation states (not observed never passes). Deliberate blocking "
        "removes every host-read finding on the blocked hosts; throttling thins reachable hosts' findings "
        "to the throttled rate but leaves them read; scope omission removes hosts from the scan but not "
        "from the truth; suppression makes the version reads fail and the dev-server marker read clean; "
        "spoofing makes the version, marker and WAF strings read clean; relabelling files each "
        "overstatement as a Tier-2 record (identical recall by construction); the white-box declarer "
        "overstates its least detectable violated controls and the oracle the ones the scan will miss, "
        "both at the drawn count per firm. The oracle can always escape at most violations_missed.",
    }


def _recovery_and_contradiction(cases: list[EvalCase], *, seed: int) -> dict[str, Any]:
    preds = _predict(cases)
    recovery = _end_to_end_metrics(preds, seed=seed)["exact_micro"]
    engine = MappingEngine()
    c_tp = c_fp = c_fn = 0
    gt_total = flagged = n_att = 0
    for case in cases:
        mappings = engine.map_findings(case.findings())
        gt, detected = _claim_flags(case, mappings, case.ground_truth.control_ids)
        c_tp += len(gt & detected)
        c_fp += len(detected - gt)
        c_fn += len(gt - detected)
        gt_total += len(gt)
        flagged += len(detected)
        n_att += len(case.attestations)
    con = M.prf_from_counts(c_tp, c_fp, c_fn)
    return {
        "n_profiles": len(cases),
        "n_findings": sum(len(c.injected) for c in cases),
        "n_true_findings": sum(len(c.true_injected) for c in cases),
        "recovery": {"precision": recovery["precision"], "recall": recovery["recall"], "f1": recovery["f1"]},
        "predict_all": _trivial_floor(preds)["corpus"],
        "contradiction": {
            "precision": con.precision,
            "recall": con.recall,
            "f1": con.f1,
            "true_contradictions": gt_total,
            "flagged": flagged,
            "tp": c_tp,
            "fp": c_fp,
            "fn": c_fn,
            "n_attestations": n_att,
        },
    }


def cross_generator_report(n: int = 100, *, seed: int | None = None) -> dict[str, Any]:
    resolved = get_settings().global_seed if seed is None else seed
    cases_a = generate_cases(n, seed=resolved)
    cases_b = generate_cases_b(n, seed=resolved)
    cohort_a = _recovery_and_contradiction(cases_a, seed=resolved)
    cohort_b = _recovery_and_contradiction(cases_b, seed=resolved)
    for block, cases in ((cohort_a, cases_a), (cohort_b, cases_b)):
        block["forced_true_fallback"] = sum(c.forced_true_fallback for c in cases)
    return {
        "seed": resolved,
        "cohort_a": cohort_a,
        "cohort_b": cohort_b,
        "note": (
            "cross-generator transfer. Cohort B is a structurally independent, never-tuned second "
            "population run through the identical pipeline and detection model. Recovery and "
            "contradiction transferring shows the headline is not an artifact of the generator's "
            "structure; recovery is governed by the shared detection model, the integrity-check reading. "
            "This tests robustness to population structure, not to the detection assumptions."
        ),
    }


_WEB_ALMANAC_2024_ADOPTION: dict[str, float] = {
    "missing_hsts": 0.34,
    "missing_csp": 0.19,
    "missing_x_frame_options": 0.37,
    "missing_x_content_type_options": 0.48,
    "missing_referrer_policy": 0.17,
    "missing_permissions_policy": 0.0282,
}
_WEB_ALMANAC_2024_TLS13_USED: float = 0.73
_HTTP_ARCHIVE_2024_SA_CSP_ABSENT: float = 0.76
_SAUDINIC_2026_DNSSEC_UNSIGNED: float = 0.9766


def exposure_anchor_report(n: int = 100, *, seed: int | None = None) -> dict[str, Any]:
    from p2c.scanning.catalog import CheckId

    resolved = get_settings().global_seed if seed is None else seed
    cases = generate_cases(n, seed=resolved)
    n_hosts = sum(len(c.profile.assets) for c in cases)

    def per_host(check: CheckId) -> float:
        return round(sum(1 for c in cases for i in c.true_injected if i.check == check) / n_hosts, 6)

    def per_firm(check: CheckId) -> float:
        return round(sum(1 for c in cases if any(i.check == check for i in c.true_injected)) / len(cases), 6)

    headers = {
        "missing_hsts": CheckId.MISSING_HSTS,
        "missing_csp": CheckId.MISSING_CSP,
        "missing_x_frame_options": CheckId.MISSING_X_FRAME_OPTIONS,
        "missing_x_content_type_options": CheckId.MISSING_X_CONTENT_TYPE_OPTIONS,
        "missing_referrer_policy": CheckId.MISSING_REFERRER_POLICY,
        "missing_permissions_policy": CheckId.MISSING_PERMISSIONS_POLICY,
    }
    transport = {
        "legacy_tls_version": CheckId.LEGACY_TLS_VERSION,
        "weak_tls_cipher": CheckId.WEAK_TLS_CIPHER,
        "no_https_redirect": CheckId.NO_HTTPS_REDIRECT,
    }
    email = {
        "spf_missing": CheckId.SPF_MISSING,
        "dmarc_missing_or_none": CheckId.DMARC_MISSING_OR_NONE,
        "dkim_missing": CheckId.DKIM_MISSING,
    }
    header_rates = {k: per_host(v) for k, v in headers.items()}
    published = {k: round(1.0 - a, 6) for k, a in _WEB_ALMANAC_2024_ADOPTION.items()}
    return {
        "seed": resolved,
        "n_firms": len(cases),
        "n_hosts": n_hosts,
        "realized_exposure": {
            "web_headers_per_host": header_rates,
            "web_headers_per_host_min": min(header_rates.values()),
            "web_headers_per_host_max": max(header_rates.values()),
            "transport_per_host": {k: per_host(v) for k, v in transport.items()},
            "email_auth_per_firm": {k: per_firm(v) for k, v in email.items()},
            "dnssec_missing_per_firm": per_firm(CheckId.DNSSEC_MISSING),
        },
        "published_non_adoption": {
            "source": (
                "Web Almanac 2024 (HTTP Archive), desktop home pages, complement of measured adoption; "
                "TLS is the complement of measured TLS 1.3 usage"
            ),
            "web_headers": published,
            "web_headers_min": min(published.values()),
            "web_headers_max": max(published.values()),
            "tls13_not_used": round(1.0 - _WEB_ALMANAC_2024_TLS13_USED, 6),
        },
        "published_non_adoption_saudi": {
            "source": (
                "Saudi slices of published measurement (findings.md B1-R2): HTTP Archive crawl "
                "2024-06-01 desktop, CrUX country assignment, published SQL "
                "sql/2024/security/feature_adoption_by_country.sql (the Saudi-audience web, not the "
                ".sa zone); SaudiNIC registry statistics for the unsigned-domain share, retrieved "
                "2026-08-16"
            ),
            "missing_csp": _HTTP_ARCHIVE_2024_SA_CSP_ABSENT,
            "dnssec_unsigned": _SAUDINIC_2026_DNSSEC_UNSIGNED,
        },
        "note": (
            "R1 anchor. Realized rates are read back from the deterministic cohort (not re-baselined); "
            "published rates are sourced external measurement. Every realized rate sits below the "
            "published non-adoption of the same signal, so the declared construction is conservative."
        ),
    }


def measure_wall_clock(n: int = 100, *, seed: int | None = None) -> float:
    resolved = get_settings().global_seed if seed is None else seed
    cases = generate_cases(n, seed=resolved)
    start = time.perf_counter()
    _predict(cases)
    return time.perf_counter() - start


def write_outputs(report: EvaluationReport, out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    tables = {
        "summary": {
            "seed": report.seed,
            "n_profiles": report.n_profiles,
            "n_findings": report.n_findings,
            "n_true_findings": report.n_true_findings,
            "sector_counts": report.sector_counts,
            "size_band_counts": report.size_band_counts,
        },
        "mapping_metrics": report.mapping,
        "end_to_end": report.end_to_end,
        "end_to_end_corroborated": report.end_to_end_corroborated,
        "per_sector": report.per_sector,
        "per_posture": report.per_posture,
        "per_size": report.per_size,
        "trivial_floor": report.trivial_floor,
        "detection_ceiling": report.detection_ceiling,
        "implemented_only": report.implemented_only,
        "rate_class_slice": report.rate_class_slice,
        "per_control": report.per_control,
        "effect_size": report.effect_size,
        "ablation": report.ablation,
        "baselines": report.baselines,
        "detection": report.detection,
        "contradictions": report.contradictions,
        "posture": report.posture,
        "latency": report.latency,
        "weighting": report.weighting,
        "realism": report.realism,
        "scan_realism": report.scan_realism,
        "specificity": report.specificity,
        "tier2_integrity": report.tier2_integrity,
        "dual_score_gap": report.dual_score_gap,
        "parent_reading": report.parent_reading,
        "cohort_firms": report.cohort_firms,
    }

    def _dump(obj: object) -> str:
        return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"

    for name, payload in tables.items():
        path = out_dir / f"{name}.json"
        path.write_text(_dump(payload), encoding="utf-8")
        written.append(path)
    sim_dir = out_dir / "simulated"
    sim_dir.mkdir(parents=True, exist_ok=True)
    (sim_dir / "README.txt").write_text(
        "Seeded simulations, NOT measurements, and not reported in the paper.\n\n"
        "agreement.json  a simulated 5-annotator set (see _simulated_annotations)\n"
        "sus.json        a simulated System Usability Scale response set (see _sus)\n\n"
        'Both carry "simulated": true. Do not cite either as a result.\n',
        encoding="utf-8",
    )
    for name, payload in (("agreement", report.agreement), ("sus", report.sus)):
        path = sim_dir / f"{name}.json"
        path.write_text(_dump(payload), encoding="utf-8")
        written.append(path)

    full = out_dir / "report.json"
    body = {k: v for k, v in asdict(report).items() if k not in ("agreement", "sus")}
    full.write_text(_dump(body), encoding="utf-8")
    written.append(full)
    return written


def reproduce(out_dir: Path, *, n: int = 100, seed: int | None = None) -> EvaluationReport:
    report = run_evaluation(n, seed=seed)
    write_outputs(report, out_dir)
    cross = cross_generator_report(n, seed=seed)
    (out_dir / "cross_generator.json").write_text(
        json.dumps(cross, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    anchors = exposure_anchor_report(n, seed=seed)
    (out_dir / "exposure_anchors.json").write_text(
        json.dumps(anchors, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    evasions = evasion_report(n, seed=seed)
    (out_dir / "evasions.json").write_text(
        json.dumps(evasions, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    for name, payload in (
        ("exposure_sweep", exposure_toward_anchors(n, seed=seed)),
        ("mapper_disagreements", mapper_disagreement_audit()),
    ):
        (out_dir / f"{name}.json").write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    return report
