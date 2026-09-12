from __future__ import annotations

import httpx
import pytest
import respx

from p2c.discovery.crtsh import CRTSH_HOST, CrtshSource
from p2c.sovereignty.egress_guard import EgressBlocked, EgressPolicy, egress_guard

pytestmark = pytest.mark.sovereignty

CRTSH_JSON = '[{"common_name":"www.example.com","name_value":"www.example.com"}]'


def _chain_contains(exc: BaseException, exc_type: type[BaseException]) -> bool:
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, exc_type):
            return True
        current = current.__cause__ or current.__context__
    return False


def test_crtsh_blocked_when_not_allowlisted() -> None:
    with (
        egress_guard(EgressPolicy(sovereign=True, allowlist=frozenset())),
        pytest.raises(httpx.HTTPError) as excinfo,
    ):
        CrtshSource().discover("example.com", consent_ref="C1")
    assert _chain_contains(excinfo.value, EgressBlocked)


def test_crtsh_host_is_allowlistable() -> None:
    policy = EgressPolicy(sovereign=True, allowlist=frozenset({CRTSH_HOST}))
    assert policy.is_allowed(CRTSH_HOST)
    assert not policy.is_allowed("shodan.io")


@respx.mock
def test_crtsh_allowlisted_source_parses_under_guard() -> None:
    respx.route(host=CRTSH_HOST).mock(return_value=httpx.Response(200, text=CRTSH_JSON))
    with egress_guard(EgressPolicy(sovereign=True, allowlist=frozenset({CRTSH_HOST}))):
        assets = CrtshSource().discover("example.com", consent_ref="C1")
    assert any(a.value == "www.example.com" for a in assets)
