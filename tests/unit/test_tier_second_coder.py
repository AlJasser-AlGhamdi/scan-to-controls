from __future__ import annotations

import pytest

from p2c.evaluation import metrics as M
from p2c.evaluation.tier_second_coder import (
    ANSWER,
    SCAN,
    author_binary,
    parse_label,
    score_binary,
    score_recode,
)


def test_author_binary_boundary() -> None:
    assert author_binary(1) == SCAN
    assert author_binary(2) == ANSWER
    assert author_binary(3) == ANSWER


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        ("SCAN", SCAN),
        ("answer", ANSWER),
        ("ANSWER.", ANSWER),
        ("*SCAN*", SCAN),
        ("The control needs internal review, so ANSWER", ANSWER),
        ("scannable, therefore SCAN", SCAN),
        ("maybe", None),
        ("", None),
    ],
)
def test_parse_label(response: str, expected: str | None) -> None:
    assert parse_label(response) == expected


def test_score_binary_agreement_kappa_and_disagreements() -> None:
    rows = [
        ("2-5-3-1", SCAN, SCAN),
        ("2-8-3-3", SCAN, SCAN),
        ("2-2-3-1", SCAN, ANSWER),
        ("1-1-1", ANSWER, ANSWER),
        ("1-1-2", ANSWER, ANSWER),
        ("1-10-3-3", ANSWER, SCAN),
    ]
    result = score_binary(rows)
    assert result.n_rows == 6 and result.n_scored == 6 and result.n_unparseable == 0
    assert result.agreement_rate == pytest.approx(4 / 6)
    assert result.confusion == {"scan_scan": 2, "scan_answer": 1, "answer_scan": 1, "answer_answer": 2}
    assert result.n_scan_author == 3 and result.n_scan_model == 3
    a = [r[1] for r in rows]
    m = [r[2] for r in rows]
    assert result.cohen_kappa == pytest.approx(M.cohens_kappa(a, m))
    ids = {d["id"] for d in result.disagreements}
    assert ids == {"2-2-3-1", "1-10-3-3"}
    assert [d["id"] for d in result.disagreements] == ["1-10-3-3", "2-2-3-1"]


def test_score_binary_excludes_unparseable() -> None:
    rows = [("a-1-1", SCAN, None), ("a-1-2", ANSWER, ANSWER)]
    result = score_binary([(i, a, m) for i, a, m in rows])
    assert result.n_scored == 1 and result.n_unparseable == 1
    assert result.agreement_rate == pytest.approx(1.0)


def test_score_recode_perfect_and_moved() -> None:
    committed = {"1-1-1": 3, "2-5-3-1": 1, "2-8-3-3": 1, "2-9-3": 2}
    recoded = {"1-1-1": 2, "2-5-3-1": 1, "2-8-3-3": 2, "2-9-3": 2}
    result = score_recode(committed, recoded)
    assert result["n_rows"] == 4 and result["n_moved"] == 2
    assert result["threeway"]["agreement_rate"] == pytest.approx(0.5)
    assert result["binary"]["agreement_rate"] == pytest.approx(0.75)
    moved_ids = {m["id"] for m in result["moved"]}
    assert moved_ids == {"1-1-1", "2-8-3-3"}


def test_score_recode_requires_overlap() -> None:
    with pytest.raises(ValueError, match="no control ids in common"):
        score_recode({"1-1-1": 1}, {"2-2-2": 1})
