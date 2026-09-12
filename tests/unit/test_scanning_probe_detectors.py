from __future__ import annotations

import json

import pytest

from p2c.scanning.catalog import CheckId
from p2c.scanning.httpx_probe import HttpProbe, checks_for_probe, dev_environment_signature, parse_httpx
from p2c.scanning.services import ServiceProbe, checks_for_service, identify_database


def _probe(**kwargs: object) -> HttpProbe:
    base: dict[str, object] = {"url": "https://h/", "host": "h", "scheme": "https", "status_code": 200}
    base.update(kwargs)
    return HttpProbe(**base)


def test_a_cookie_without_secure_is_reported() -> None:
    probe = _probe(set_cookie=("sid=abc; Path=/; HttpOnly",))
    assert CheckId.INSECURE_COOKIE in checks_for_probe(probe)


def test_a_cookie_with_secure_is_not() -> None:
    probe = _probe(set_cookie=("sid=abc; Path=/; Secure; HttpOnly",))
    assert CheckId.INSECURE_COOKIE not in checks_for_probe(probe)


def test_the_attribute_match_is_case_insensitive_and_not_substring() -> None:
    assert CheckId.INSECURE_COOKIE not in checks_for_probe(_probe(set_cookie=("a=1; secure",)))
    assert CheckId.INSECURE_COOKIE in checks_for_probe(_probe(set_cookie=("a=secure; Path=/",)))
    assert CheckId.INSECURE_COOKIE in checks_for_probe(_probe(set_cookie=("a=1; SameSite=Insecure",)))


def test_one_insecure_cookie_among_several_is_enough() -> None:
    probe = _probe(set_cookie=("a=1; Secure", "b=2; Path=/", "c=3; Secure"))
    assert CheckId.INSECURE_COOKIE in checks_for_probe(probe)


def test_a_response_that_set_no_cookies_raises_nothing() -> None:
    assert CheckId.INSECURE_COOKIE not in checks_for_probe(_probe(set_cookie=()))


def test_an_unreceived_response_raises_nothing_even_with_cookies() -> None:
    probe = _probe(status_code=0, set_cookie=("a=1; Path=/",))
    assert checks_for_probe(probe) == []


def test_multiple_set_cookie_headers_survive_parsing() -> None:
    row = json.dumps(
        {
            "url": "https://h/",
            "host": "h",
            "scheme": "https",
            "status_code": 200,
            "header": {"set-cookie": ["a=1; Secure", "b=2; Path=/"]},
        }
    )
    probe = parse_httpx(row)[0]
    assert probe.set_cookie == ("a=1; Secure", "b=2; Path=/")
    assert CheckId.INSECURE_COOKIE in checks_for_probe(probe)


def test_a_newline_joined_set_cookie_header_also_survives() -> None:
    row = json.dumps(
        {
            "url": "https://h/",
            "host": "h",
            "scheme": "https",
            "status_code": 200,
            "header": {"Set-Cookie": "a=1; Secure\nb=2; Path=/"},
        }
    )
    assert parse_httpx(row)[0].set_cookie == ("a=1; Secure", "b=2; Path=/")


@pytest.mark.parametrize(
    "headers",
    [
        {"Server": "Werkzeug/3.0.1 Python/3.12.1"},
        {"X-Debug-Token": "a1b2c3"},
        {"x-debug-token-link": "/_profiler/a1b2c3"},
        {"Server": "WEBrick/1.8.1"},
    ],
)
def test_a_development_signature_is_reported(headers: dict[str, str]) -> None:
    assert dev_environment_signature(headers) is not None
    assert CheckId.EXPOSED_DEV_ENVIRONMENT in checks_for_probe(_probe(headers=headers))


@pytest.mark.parametrize(
    "headers",
    [{"Server": "nginx/1.30.3"}, {"Server": "gunicorn/21.2"}, {}, {"X-Runtime": "0.03"}],
)
def test_a_production_response_raises_nothing(headers: dict[str, str]) -> None:
    assert dev_environment_signature(headers) is None
    assert CheckId.EXPOSED_DEV_ENVIRONMENT not in checks_for_probe(_probe(headers=headers))


def test_a_hostname_is_not_evidence() -> None:
    probe = _probe(url="https://dev.example.com/", host="dev.example.com", headers={"Server": "nginx"})
    assert CheckId.EXPOSED_DEV_ENVIRONMENT not in checks_for_probe(probe)


def test_an_unreceived_response_cannot_show_a_development_signature() -> None:
    probe = _probe(status_code=0, headers={"Server": "Werkzeug/3.0.1"})
    assert checks_for_probe(probe) == []


def test_a_mysql_greeting_is_identified() -> None:
    greeting = b"\x4a\x00\x00\x00\x0a8.0.36\x00"
    assert identify_database(greeting) == "mysql"


def test_a_mariadb_greeting_is_named_separately() -> None:
    greeting = b"\x4a\x00\x00\x00\x0a5.5.5-10.11.6-MariaDB\x00"
    assert identify_database(greeting) == "mariadb"


@pytest.mark.parametrize("reply", [b"S", b"N"])
def test_a_postgres_ssl_reply_is_identified(reply: bytes) -> None:
    assert identify_database(b"", pg_reply=reply) == "postgresql"


@pytest.mark.parametrize("reply", [b"+PONG\r\n", b"-NOAUTH Authentication required.\r\n"])
def test_a_redis_reply_is_identified_even_when_it_demands_auth(reply: bytes) -> None:
    assert identify_database(b"", redis_reply=reply) == "redis"


def test_an_http_server_on_a_database_port_is_not_a_database() -> None:
    assert identify_database(b"HTTP/1.1 400 Bad Request\r\n") is None
    assert checks_for_service(ServiceProbe("h", 3306, protocol=None)) == []


def test_a_database_on_an_unusual_port_is_still_found() -> None:
    greeting = b"\x4a\x00\x00\x00\x0a8.0.36\x00"
    protocol = identify_database(greeting)
    assert checks_for_service(ServiceProbe("h", 48306, protocol=protocol)) == [CheckId.EXPOSED_DATABASE_PORT]


def test_an_unidentified_service_raises_nothing() -> None:
    assert identify_database(b"\x00\x01\x02") is None
    assert identify_database(b"") is None
    assert checks_for_service(ServiceProbe("h", 5432)) == []


def test_an_unreachable_service_is_distinguishable_from_an_unidentified_one() -> None:
    unreachable = ServiceProbe("h", 5432, read=False)
    answered_but_unknown = ServiceProbe("h", 5432, read=True)
    assert unreachable.read is False
    assert answered_but_unknown.read is True
    assert checks_for_service(unreachable) == []
    assert checks_for_service(answered_but_unknown) == []
