from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from p2c.schemas import Severity, severity_from_cvss


@given(st.floats(min_value=0.0, max_value=10.0, allow_nan=False, allow_infinity=False))
def test_score_maps_to_correct_band(score: float) -> None:
    band = severity_from_cvss(score)
    if score == 0.0:
        assert band is Severity.NONE
    elif score < 4.0:
        assert band is Severity.LOW
    elif score < 7.0:
        assert band is Severity.MEDIUM
    elif score < 9.0:
        assert band is Severity.HIGH
    else:
        assert band is Severity.CRITICAL


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.0, Severity.NONE),
        (0.1, Severity.LOW),
        (3.9, Severity.LOW),
        (4.0, Severity.MEDIUM),
        (6.9, Severity.MEDIUM),
        (7.0, Severity.HIGH),
        (8.9, Severity.HIGH),
        (9.0, Severity.CRITICAL),
        (10.0, Severity.CRITICAL),
    ],
)
def test_band_boundaries(score: float, expected: Severity) -> None:
    assert severity_from_cvss(score) is expected


@pytest.mark.parametrize("bad", [-0.1, -1.0, 10.1, 100.0])
def test_out_of_range_raises(bad: float) -> None:
    with pytest.raises(ValueError, match="outside"):
        severity_from_cvss(bad)
