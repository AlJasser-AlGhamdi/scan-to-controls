from __future__ import annotations

import json
import random
import statistics
import time
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
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
from p2c.mapping.models import ControlMapping
from p2c.scanning.catalog import LIVE_CHECKS
from p2c.mapping.rules import MappingEngine, check_id_from_finding
from p2c.scoring.assemble import (
    TIER1_CHECKABLE,
    attestation_assessments,
    merge_assessments,
    tier1_assessments,
)
from p2c.scoring.contradictions import control_related, detect_contradictions
from p2c.scoring.dual_score import apply_weights, compute_dual_score
from p2c.schemas.enums import EvidenceTier
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


def _implemented_only(preds: list[CasePrediction]) -> dict[str, Any]:
    from p2c.evaluation.synthetic import expert_key

    live = {c for check, gold in expert_key().items() if check.value in LIVE_INSPECTOR_CHECKS for c in gold}
    pairs = [(set(p.predicted) & live, set(p.true_gold) & live) for p in preds]
    micro = M.micro_prf(pairs)
    true_cells = sum(len(g) for _, g in pairs)
    base = true_cells / (len(pairs) * len(live)) if pairs and live else 0.0
    return {
        "n_controls": len(live),
        "controls": sorted(live),
        "precision": round(micro.precision, 4),
        "recall": round(micro.recall, 4),
        "f1": round(micro.f1, 4),
        "true_assignments": true_cells,
        "trivial_floor_f1": round(2 * base / (base + 1), 4) if base else 0.0,
        "note": "recovery over the controls reachable by an implemented inspector. Detection is modelled "
        "here exactly as in the full result, so this is a dependence check on the implementation gap, "
        "not a field measurement.",
    }


def _detection_ceiling(cases: list[EvalCase]) -> dict[str, Any]:
    from p2c.evaluation import synthetic as S

    key = S.expert_key()
    universe = sorted({c for case in cases for c in case.ground_truth.control_ids})
    by_control: dict[str, list[Any]] = {c: [] for c in universe}
    for check, gold in key.items():
        for cid in gold:
            if cid in by_control:
                by_control[cid].append(check)

    def p_observed(check: Any, host: str, case: EvalCase, present: bool) -> float:
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

    e_tp = e_fp = e_fn = 0.0
    for case in cases:
        present = {(i.asset, i.check) for i in case.true_injected}
        for cid in universe:
            miss = 1.0
            for host in case.scan_conditions:
                for check in by_control[cid]:
                    miss *= 1.0 - p_observed(check, host, case, (host, check) in present)
            assert_p = 1.0 - miss
            if cid in case.ground_truth.control_ids:
                e_tp += assert_p
                e_fn += 1.0 - assert_p
            else:
                e_fp += assert_p
    precision = e_tp / (e_tp + e_fp) if e_tp + e_fp else 0.0
    recall = e_tp / (e_tp + e_fn) if e_tp + e_fn else 0.0
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0.0,
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
            "base_rate": round(base, 4),
            "f1": round(2 * base / (base + 1), 4) if base else 0.0,
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


def _all_tier_assessments(case: EvalCase, mappings: Sequence[ControlMapping]) -> list[ControlAssessment]:
    return merge_assessments(
        tier1_assessments(mappings),
        _internal_assessments(case),
        attestation_assessments(case.attestations, now=EVAL_EPOCH),
    )


def _governance(cases: list[EvalCase], *, seed: int) -> dict[str, Any]:
    engine = MappingEngine()
    n_check = len(TIER1_CHECKABLE)
    c_tp = c_fp = c_fn = 0
    gt_total = flagged = n_att = 0
    n_lapsed = 0
    n_unrefutable = n_unrefutable_live = 0
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
        gt = {c for c in attested if any(control_related(c, t) for t in true)}
        detected = {x.control_id for x in detect_contradictions(case.attestations, mappings, now=EVAL_EPOCH)}
        tp_i, fp_i, fn_i = len(gt & detected), len(detected - gt), len(gt - detected)
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
        lapsed_wrongly_flagged += len(detected & (lapsed_ids - attested))
        score = compute_dual_score(_all_tier_assessments(case, mappings))
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
            "lapsed_wrongly_flagged": lapsed_wrongly_flagged,
            "note": "overstatement detection: a Tier-3 attestation refuted by a Tier-1 finding; "
            "recall limited by scanner misses, precision by false alarms. Lapsed (expired or not yet "
            "effective) attestations are excluded from both the ground truth and the detector. "
            "Declarations on off-surface controls, which no Tier-1 finding can reach, are counted "
            "separately: the detector sees them and correctly leaves them alone, so they enter "
            "neither the ground truth nor the flagged set and move no rate here.",
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
    n_with_tier2 = precedence_total = precedence_correct = 0
    for case in cases:
        mappings = engine.map_findings(case.findings())
        t1 = tier1_assessments(mappings)
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
        for cid in refuted:
            precedence_total += 1
            if status.get(cid) == ComplianceStatus.NON_COMPLIANT:
                precedence_correct += 1
    return {
        "n_orgs_with_tier2": n_with_tier2,
        "precedence_checks": precedence_total,
        "precedence_correct": precedence_correct,
        "precedence_rate": precedence_correct / precedence_total if precedence_total else 1.0,
        "note": "three-tier assembly at scale: a Tier-2 compliant self-report on a control a Tier-1 "
        "finding refutes must not raise the score (lowest-tier-wins). Tier-2 answers are synthesized, "
        "so this is a precedence-integrity check, not accuracy against experts.",
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
        score = compute_dual_score(_all_tier_assessments(case, engine.map_findings(case.findings())))
        true_states = {(i.asset, i.check) for i in case.true_injected}
        live = [a for a in case.attestations if a.valid_from <= EVAL_EPOCH <= a.valid_until]
        truly_violated = case.ground_truth.control_ids
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
                "n_overstated": sum(
                    1 for a in live if any(control_related(a.control_id, t) for t in truly_violated)
                ),
                "assessed_score": round(score.assessed_score, 4),
                "documented_score": round(score.documented_score, 4),
            }
        )
    return {
        "seed": seed,
        "n_profiles": len(firms),
        "firms": sorted(firms, key=lambda f: f["case_id"]),
        "note": (
            "one record per synthetic firm of the reported seed: counts are the per-firm terms of "
            "the cohort totals (hosts, true issues, findings, false positives, declarations, "
            "overstatements) and the two scores are the assessed (Tier-1, 16 externally testable "
            "subcontrols) and documented (every evidenced control) shares the toolkit reports"
        ),
    }


def _dual_score_gap(cases: list[EvalCase], *, seed: int) -> dict[str, Any]:
    engine = MappingEngine()
    assessed: list[float] = []
    documented: list[float] = []
    gaps: list[float] = []
    off_surface_counts: list[int] = []
    tier2_3_only = 0
    must_answer_rows = sum(len(pool) for pool in _syn.off_surface_pools())
    worked: dict[str, Any] = {}
    for case in cases:
        mappings = engine.map_findings(case.findings())
        merged = _all_tier_assessments(case, mappings)
        score = compute_dual_score(merged)
        assessed.append(score.assessed_score)
        documented.append(score.documented_score)
        gaps.append(score.documented_score - score.assessed_score)
        off_surface = sum(1 for a in merged if a.control_id not in TIER1_CHECKABLE)
        off_surface_counts.append(off_surface)
        tier2_3_only += sum(1 for a in merged if a.tier != EvidenceTier.TIER_1)
        if case.case_id == "eval-000":
            worked = {
                "case_id": case.case_id,
                "assessed": round(score.assessed_score, 4),
                "documented": round(score.documented_score, 4),
                "off_surface_controls": off_surface,
                "documented_universe": len(merged),
                "must_answer_remaining": must_answer_rows - off_surface,
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
        "share_firms_differ": round(n_differ / len(gaps), 4) if gaps else 0.0,
        "assessed_mean": round(statistics.fmean(assessed), 4),
        "documented_mean": round(statistics.fmean(documented), 4),
        "off_surface_controls_mean": round(statistics.fmean(off_surface_counts), 2),
        "off_surface_controls_min": min(off_surface_counts),
        "off_surface_controls_max": max(off_surface_counts),
        "must_answer_rows": must_answer_rows,
        "surviving_tier2_3_only_assessments": tier2_3_only,
        "worked_firm": worked,
        "note": (
            "documented minus assessed across the cohort, under uniform (unweighted) control "
            "weights, the reported default. The assessed score is over the Tier-1 checkable "
            "subcontrols; the documented score is over those plus the off-surface controls the "
            "firm evidences at Tier 2 or Tier 3, so the gap is entirely the firm's off-surface "
            "evidence. A declaration on a Tier-1 checkable control contributes nothing, because "
            "lowest-tier-wins collapses it onto that control's Tier-1 assessment."
        ),
    }


def _coarsen_2_15_3_3(check_value: str, control_id: str) -> str:
    if check_value in PARENT_READING_CHECKS and control_id == "2-15-3-3":
        return "2-15-3"
    return control_id


def _parent_reading(cases: list[EvalCase], *, seed: int) -> dict[str, Any]:
    engine = MappingEngine()
    key = expert_key()

    def block(remap: bool) -> dict[str, Any]:
        rec_pairs: list[tuple[set[str], set[str]]] = []
        c_tp = c_fp = c_fn = 0
        for case in cases:
            findings = case.findings()
            fid_check = {f.finding_id: check_id_from_finding(f) for f in findings}
            mappings = engine.map_findings(findings)
            if remap:
                relabeled = []
                for m in mappings:
                    chk = fid_check.get(m.finding_id)
                    cid = _coarsen_2_15_3_3(chk.value if chk is not None else "", m.control_id)
                    relabeled.append(m.model_copy(update={"control_id": cid}))
                mappings = relabeled
                true = {
                    _coarsen_2_15_3_3(inj.check.value, cid)
                    for inj in case.true_injected
                    for cid in key[inj.check]
                }
            else:
                true = set(case.ground_truth.control_ids)
            rec_pairs.append(({m.control_id for m in mappings}, true))
            live = [a for a in case.attestations if a.valid_from <= EVAL_EPOCH <= a.valid_until]
            attested = {a.control_id for a in live}
            gt = {c for c in attested if any(control_related(c, t) for t in true)}
            detected = {x.control_id for x in detect_contradictions(case.attestations, mappings, now=EVAL_EPOCH)}
            c_tp += len(gt & detected)
            c_fp += len(detected - gt)
            c_fn += len(gt - detected)
        rec = M.micro_prf(rec_pairs)
        con = M.prf_from_counts(c_tp, c_fp, c_fn)
        return {
            "recovery": {
                "precision": round(rec.precision, 4),
                "recall": round(rec.recall, 4),
                "f1": round(rec.f1, 4),
            },
            "contradiction": {
                "precision": round(con.precision, 4),
                "recall": round(con.recall, 4),
                "f1": round(con.f1, 4),
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
            "recovery (end-to-end micro P/R/F1) and contradiction P/R/F1 under the fine reading "
            "(2-15-3-3 as a leaf, shipped) and the coarse reading (the seven hardening checks moved "
            "to the parent 2-15-3), with the finding-weighted modal share and the constant-mapper "
            "floor from parent_reading_sensitivity. The relabel is applied consistently to predicted "
            "and gold. The fine reading is the object the expert panel will test and is held fixed; "
            "the coarse reading raises both recovery and contradiction (a parent finding refutes more "
            "sibling declarations) while lowering the concentration, so shipping the fine reading is "
            "the conservative choice."
        ),
    }


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
        end_to_end=_end_to_end_metrics(preds, seed=resolved),
        end_to_end_corroborated=_end_to_end_corroborated_metrics(preds, seed=resolved),
        per_sector=_per_sector(preds, seed=resolved),
        per_posture=_per_posture(preds, seed=resolved),
        per_size=_per_size(preds, seed=resolved),
        trivial_floor=_trivial_floor(preds),
        detection_ceiling=_detection_ceiling(cases),
        implemented_only=_implemented_only(preds),
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
        1337, 7, 42, 2025, 99,
        3, 11, 13, 17, 19, 23, 29, 31, 37, 101,
        202, 303, 404, 505, 606, 707, 808, 909, 1234, 4242,
        5150, 8675, 314159, 271828, 161803,
    ),
) -> dict[str, Any]:
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
        tier1 = tier1_assessments(engine.map_findings(case.findings()))
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
    base_sens = dict(_syn.SENSITIVITY)
    base_fa = dict(_syn.FALSE_ALARM)
    try:
        for cid in LOW_CONFIDENCE_CHECKS:
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
        "note": "all low-confidence checks at their pessimistic end at once (false alarm x2, "
        "sensitivity x0.8): a defended simultaneous worst case for the scanner-dependent numbers.",
    }


def detection_uncertainty_ensemble(n: int = 100, *, draws: int = 500, seed: int = 1337) -> dict[str, Any]:
    rng = random.Random(seed)
    base_sens = dict(_syn.SENSITIVITY)
    base_fa = dict(_syn.FALSE_ALARM)

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
                _syn.SENSITIVITY[cid] = _sample(mean, wide=cid in LOW_CONFIDENCE_CHECKS)
            for cid, mean in base_fa.items():
                drawn = _sample(mean, wide=cid in LOW_CONFIDENCE_CHECKS)
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
        "note": "Monte-Carlo ensemble with per-check Beta priors (wide for low-confidence checks, tight "
        "for deterministic reads); the predictive interval is the honest uncertainty from the modelled "
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


def _recovery_and_contradiction(cases: list[EvalCase], *, seed: int) -> dict[str, Any]:
    preds = _predict(cases)
    recovery = _end_to_end_metrics(preds, seed=seed)["exact_micro"]
    engine = MappingEngine()
    c_tp = c_fp = c_fn = 0
    gt_total = flagged = n_att = 0
    for case in cases:
        mappings = engine.map_findings(case.findings())
        true = case.ground_truth.control_ids
        live = [a for a in case.attestations if a.valid_from <= EVAL_EPOCH <= a.valid_until]
        attested = {a.control_id for a in live}
        gt = {c for c in attested if any(control_related(c, t) for t in true)}
        detected = {x.control_id for x in detect_contradictions(case.attestations, mappings, now=EVAL_EPOCH)}
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
    cohort_b = _recovery_and_contradiction(cases_b, seed=resolved)
    cohort_b["forced_true_fallback"] = sum(c.forced_true_fallback for c in cases_b)
    cohort_b["forced_observe_fallback"] = sum(c.forced_observe_fallback for c in cases_b)
    return {
        "seed": resolved,
        "cohort_a": _recovery_and_contradiction(cases_a, seed=resolved),
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
        return round(sum(1 for c in cases for i in c.true_injected if i.check == check) / n_hosts, 4)

    def per_firm(check: CheckId) -> float:
        return round(sum(1 for c in cases if any(i.check == check for i in c.true_injected)) / len(cases), 4)

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
    published = {k: round(1.0 - a, 4) for k, a in _WEB_ALMANAC_2024_ADOPTION.items()}
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
            "tls13_not_used": round(1.0 - _WEB_ALMANAC_2024_TLS13_USED, 4),
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
        "Both carry \"simulated\": true. Do not cite either as a result.\n",
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
    return report
