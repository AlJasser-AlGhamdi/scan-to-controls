from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from p2c.scanning.catalog import CheckId
from p2c.scanning.web_paths import PathState, WebPathInspector
from p2c.sovereignty.egress_guard import EgressBlocked

BASE = "https://x.example"
SOFT_404 = b"<html><head><title>Not Found</title></head><body>Sorry</body></html>"


def _resp(status: int, content: bytes = b"", headers: dict[str, str] | None = None) -> httpx.Response:
    return httpx.Response(status, headers=headers, stream=httpx.ByteStream(content))


def _inspector(routes: dict[str, httpx.Response], default: Callable[[], httpx.Response] | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path in routes:
            return routes[request.url.path]
        return default() if default else _resp(404, b"no")

    return WebPathInspector(httpx.Client(transport=httpx.MockTransport(handler)))


def test_autoindex_page_is_a_directory_listing() -> None:
    page = b"<html><head><title>Index of /files/</title></head><body><a href='a.zip'>a.zip</a></body></html>"
    result = _inspector({"/files/": _resp(200, page)}).directory_listing(BASE)
    assert result.state is PathState.FOUND and result.checks == (CheckId.DIRECTORY_LISTING_ENABLED,)


def test_soft_404_on_every_path_raises_nothing() -> None:
    inspector = _inspector({}, default=lambda: _resp(200, SOFT_404))
    for result in (inspector.directory_listing(BASE), inspector.sensitive_files(BASE)):
        assert result.state is PathState.CLEAN and result.checks == ()
    login = inspector.login_panel(BASE)
    assert login.state is PathState.UNREAD and login.checks == ()
    assert _inspector({}, default=lambda: _resp(404, SOFT_404)).login_panel(BASE).state is PathState.CLEAN


def test_a_page_that_mentions_an_index_is_not_a_listing() -> None:
    page = b"<html><head><title>Shop</title></head><body><h1>Index of products</h1></body></html>"
    assert _inspector({"/": _resp(200, page)}).directory_listing(BASE).checks == ()


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/.git/HEAD", b"ref: refs/heads/main\n"),
        ("/.env", b"APP_KEY=base64:abc\nDB_PASSWORD=secret\nDEBUG=true\n"),
        ("/.DS_Store", b"\x00\x00\x00\x01Bud1\x00\x00"),
        ("/backup.sql", b"-- MySQL dump 10.13  Distrib 8.0.36\nCREATE TABLE users (id int);\n"),
        ("/server-status", b"<h1>Apache Server Status for x.example</h1>"),
        ("/phpinfo.php", b"<html><head><title>phpinfo()</title></head></html>"),
    ],
)
def test_each_sensitive_file_is_found_by_its_own_format(path: str, body: bytes) -> None:
    result = _inspector({path: _resp(200, body)}).sensitive_files(BASE)
    assert result.checks == (CheckId.EXPOSED_SENSITIVE_FILE,)
    assert result.evidence[1] == f"{path} format"


def test_an_html_page_at_a_sensitive_path_is_not_the_file() -> None:
    assert _inspector({"/.env": _resp(200, SOFT_404)}).sensitive_files(BASE).checks == ()


def test_password_form_is_a_login_panel() -> None:
    page = b"<form method=post><input name=user><input type='password' name=pw></form>"
    result = _inspector({"/admin/": _resp(200, page)}).login_panel(BASE)
    assert result.checks == (CheckId.EXPOSED_LOGIN_PANEL,)


def test_authentication_challenge_is_a_login_surface() -> None:
    challenge = _resp(401, headers={"WWW-Authenticate": 'Basic realm="Tomcat Manager"'})
    result = _inspector({"/manager/html": challenge}).login_panel(BASE)
    assert result.checks == (CheckId.EXPOSED_LOGIN_PANEL,)
    assert result.evidence[1] == "401 challenge: Basic"


def test_a_form_without_a_password_is_not_a_login_panel() -> None:
    page = b"<form action=/search><input name=q type=text></form>"
    assert _inspector({"/login": _resp(200, page)}).login_panel(BASE).checks == ()


def test_a_failed_fetch_leaves_the_detector_unread() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/uploads/":
            raise httpx.ConnectTimeout("timed out", request=request)
        return _resp(404)

    inspector = WebPathInspector(httpx.Client(transport=httpx.MockTransport(handler)))
    result = inspector.directory_listing(BASE)
    assert result.state is PathState.UNREAD and result.checks == ()


def test_a_finding_still_counts_when_another_path_failed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            raise httpx.ConnectTimeout("timed out", request=request)
        if request.url.path == "/.git/HEAD":
            return _resp(200, b"ref: refs/heads/main\n")
        return _resp(404)

    inspector = WebPathInspector(httpx.Client(transport=httpx.MockTransport(handler)))
    assert inspector.sensitive_files(BASE).checks == (CheckId.EXPOSED_SENSITIVE_FILE,)


def test_an_egress_block_is_never_swallowed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise EgressBlocked("x.example")

    inspector = WebPathInspector(httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(EgressBlocked):
        inspector.login_panel(BASE)


def test_inspect_combines_the_three_detectors() -> None:
    routes = {
        "/": _resp(200, b"<title>Index of /</title>"),
        "/.env": _resp(200, b"A=1\nB=2\n"),
        "/admin/": _resp(200, b"<form><input type=password></form>"),
    }
    assert set(_inspector(routes).inspect(BASE)) == {
        CheckId.DIRECTORY_LISTING_ENABLED,
        CheckId.EXPOSED_SENSITIVE_FILE,
        CheckId.EXPOSED_LOGIN_PANEL,
    }




def test_a_redirect_to_another_host_is_not_followed() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if request.url.host == "x.example":
            return _resp(302, headers={"Location": "http://10.0.0.5/admin/"})
        return _resp(200, b"<form><input type=password></form>")

    inspector = WebPathInspector(httpx.Client(transport=httpx.MockTransport(handler)))
    assert inspector.login_panel(BASE).checks == ()
    assert all("10.0.0.5" not in url for url in seen)


def test_a_same_origin_redirect_is_followed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/admin/":
            return _resp(302, headers={"Location": "/admin/login.php"})
        if request.url.path == "/admin/login.php":
            return _resp(200, b"<form><input type='password'></form>")
        return _resp(404)

    inspector = WebPathInspector(httpx.Client(transport=httpx.MockTransport(handler)))
    assert inspector.login_panel(BASE).checks == (CheckId.EXPOSED_LOGIN_PANEL,)


def test_a_redirect_loop_leaves_the_read_open() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _resp(302, headers={"Location": request.url.path})

    inspector = WebPathInspector(httpx.Client(transport=httpx.MockTransport(handler)))
    assert inspector.login_panel(BASE).state is PathState.UNREAD


def test_the_body_read_is_bounded() -> None:
    huge = b"A=1\nB=2\n" + b"x" * 5_000_000

    def handler(request: httpx.Request) -> httpx.Response:
        return _resp(200, huge)

    inspector = WebPathInspector(httpx.Client(transport=httpx.MockTransport(handler)))
    fetched = inspector._fetch(f"{BASE}/.env")
    assert fetched is not None and len(fetched.body) <= 65_536


def test_identity_encoding_is_requested_and_a_compressed_body_is_left_unread() -> None:
    import gzip

    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("accept-encoding", ""))
        return _resp(200, gzip.compress(b"A=1\nB=2\n"), headers={"Content-Encoding": "gzip"})

    inspector = WebPathInspector(httpx.Client(transport=httpx.MockTransport(handler)))
    assert inspector._fetch(f"{BASE}/.env") is None
    assert seen and all(value == "identity" for value in seen)




@pytest.mark.parametrize("status", [429, 500, 503])
def test_a_non_answer_status_leaves_the_detectors_unread(status: int) -> None:
    inspector = _inspector({}, default=lambda: _resp(status, b"busy"))
    reads = (inspector.directory_listing(BASE), inspector.sensitive_files(BASE), inspector.login_panel(BASE))
    for result in reads:
        assert result.state is PathState.UNREAD and result.checks == ()


def test_a_login_form_served_on_every_path_is_neither_a_panel_nor_clean() -> None:
    page = b"<html><body><form><input name=u><input type=password name=p></form></body></html>"
    inspector = _inspector({}, default=lambda: _resp(200, page))
    assert inspector.login_panel(BASE).state is PathState.UNREAD


def test_site_wide_basic_auth_leaves_the_login_panel_unread() -> None:
    inspector = _inspector({}, default=lambda: _resp(401, headers={"WWW-Authenticate": 'Basic realm="x"'}))
    assert inspector.login_panel(BASE).state is PathState.UNREAD


def test_a_listing_served_on_every_path_is_neither_a_listing_nor_clean() -> None:
    inspector = _inspector({}, default=lambda: _resp(200, b"<title>Index of /</title>"))
    assert inspector.directory_listing(BASE).state is PathState.UNREAD


def test_an_injected_redirecting_client_cannot_leave_the_origin() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.host)
        if request.url.host == "x.example":
            return _resp(302, headers={"Location": "https://idp.other.example/login"})
        return _resp(200, b"<form><input type=password></form>")

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)
    assert WebPathInspector(client).login_panel(BASE).checks == ()
    assert set(seen) == {"x.example"}


def test_a_site_that_blocks_every_path_leaves_the_reads_open() -> None:
    inspector = _inspector({}, default=lambda: _resp(403, b"Access denied"))
    assert inspector.sensitive_files(BASE).state is PathState.UNREAD
    assert inspector.login_panel(BASE).state is PathState.UNREAD


def test_a_bot_challenge_is_not_an_answer_but_a_403_on_one_protected_path_is() -> None:
    page = b"<html>checking</html>"
    challenge = _inspector({}, default=lambda: _resp(200, page, {"cf-mitigated": "challenge"}))
    assert challenge.directory_listing(BASE).state is PathState.UNREAD
    protected = _inspector({"/.git/HEAD": _resp(403)}, default=lambda: _resp(404))
    assert protected.sensitive_files(BASE).state is PathState.CLEAN


def test_without_a_clean_baseline_nothing_the_paths_show_is_trusted() -> None:
    widget = b"<form><input type='password' name='p'></form>"
    routes = {"/p2c-nonexistent-7f3a9c1e/": _resp(503)}
    inspector = _inspector(routes, default=lambda: _resp(200, widget))
    assert inspector.login_panel(BASE).state is PathState.UNREAD


def test_a_block_that_starts_mid_group_is_not_read_as_clean() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return _resp(404) if len(seen) == 1 else _resp(403)

    inspector = WebPathInspector(httpx.Client(transport=httpx.MockTransport(handler)))
    assert inspector.sensitive_files(BASE).state is PathState.UNREAD
    assert seen[-1] == "/p2c-nonexistent-7f3a9c1e/"


def test_a_site_wide_authentication_wall_leaves_every_path_read_open() -> None:
    wall = lambda: _resp(401, headers={"WWW-Authenticate": 'Basic realm="intranet"'})
    inspector = _inspector({}, default=wall)
    reads = (inspector.directory_listing(BASE), inspector.sensitive_files(BASE), inspector.login_panel(BASE))
    assert all(result.state is PathState.UNREAD for result in reads)


def test_a_redirect_to_another_site_leaves_the_path_read_open() -> None:
    off = lambda: _resp(302, headers={"Location": "https://sso.other.example/login"})
    inspector = _inspector({"/": _resp(200, b"home")}, default=off)
    assert inspector.login_panel(BASE).state is PathState.UNREAD
