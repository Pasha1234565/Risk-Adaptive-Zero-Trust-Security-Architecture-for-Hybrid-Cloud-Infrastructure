"""API documentation route and its Content-Security-Policy (Phase 2, bugs 4 and 5).

Before the fix, the README and the Architecture page linked to ``/api/docs``,
which returned 404, while FastAPI served ``/docs`` with a CDN script, a CDN
stylesheet and an inline script, all blocked by the app's own CSP.
"""

from __future__ import annotations

import re

import pytest

from app import config, main

EXPECTED_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'"
)


def test_api_docs_page_is_served_at_the_documented_url(make_client):
    response = make_client().get("/api/docs")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert 'id="swagger-ui"' in response.text
    assert 'data-openapi-url="/api/openapi.json"' in response.text


def test_openapi_schema_is_served_under_api_prefix(make_client):
    response = make_client().get("/api/openapi.json")

    assert response.status_code == 200
    schema = response.json()
    assert schema["info"]["title"] == main.API_TITLE
    assert "/api/health" in schema["paths"]
    assert "/api/auth/login" in schema["paths"]
    assert "/api/docs" not in schema["paths"]


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"])
def test_no_duplicate_documentation_routes(make_client, path):
    assert make_client().get(path).status_code == 404


def test_docs_page_loads_only_same_origin_assets_and_no_inline_script(make_client):
    html = make_client().get("/api/docs").text

    scripts = re.findall(r"<script\b([^>]*)>(.*?)</script>", html, flags=re.S)
    assert scripts, "expected script tags"
    for attributes, body in scripts:
        source = re.search(r'src="([^"]+)"', attributes)
        assert source and source.group(1).startswith("/static/"), attributes
        assert not body.strip(), "inline script would be blocked by script-src 'self'"
    for href in re.findall(r'<link\b[^>]*href="([^"]+)"', html):
        assert href.startswith("/static/"), href
    assert "cdn.jsdelivr.net" not in html
    assert "fastapi.tiangolo.com" not in html


@pytest.mark.parametrize(
    "path, content_type",
    [
        ("/static/vendor/swagger-ui/swagger-ui-bundle.js", "javascript"),
        ("/static/vendor/swagger-ui/swagger-ui.css", "text/css"),
        ("/static/js/api-docs.js", "javascript"),
    ],
)
def test_docs_assets_are_served_locally_with_script_safe_types(make_client, path, content_type):
    response = make_client().get(path)

    assert response.status_code == 200
    # X-Content-Type-Options: nosniff makes browsers refuse scripts served as text/plain.
    assert content_type in response.headers["content-type"]
    assert len(response.content) > 500


def test_vendored_swagger_matches_the_pinned_release():
    import hashlib

    vendor = config.STATIC_DIR / "vendor" / "swagger-ui"
    expected = {
        "swagger-ui-bundle.js": "36eeb4d5640b9c036b1d0f854499af1cceebbdb260b790a03a18be5e8488fbf5",
        "swagger-ui.css": "c3cfe8248c4b0b89673600fb829924eafbac6de4bc4b2b06f5f5243483074d0a",
    }
    for name, digest in expected.items():
        assert hashlib.sha256((vendor / name).read_bytes()).hexdigest() == digest, name
    assert (vendor / "LICENSE").is_file()


def test_docs_page_keeps_the_default_csp_and_security_headers(make_client):
    headers = make_client().get("/api/docs").headers

    assert main.CONTENT_SECURITY_POLICY == EXPECTED_CSP
    assert headers["content-security-policy"] == EXPECTED_CSP
    assert "unsafe-eval" not in headers["content-security-policy"]
    assert "*" not in headers["content-security-policy"]
    assert headers["x-frame-options"] == "DENY"
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["permissions-policy"] == "geolocation=(), microphone=(), camera=()"
    assert headers["cache-control"] == "no-store"


def test_application_pages_keep_the_same_csp(make_client):
    from conftest import ANALYST, login

    browser = make_client()
    login(browser, *ANALYST)
    for path in ("/login", "/", "/access", "/architecture"):
        response = browser.get(path, follow_redirects=True)
        assert response.status_code == 200, path
        assert response.headers["content-security-policy"] == EXPECTED_CSP, path


def test_architecture_page_links_to_working_docs_url(make_client):
    from conftest import ANALYST, login

    browser = make_client()
    login(browser, *ANALYST)
    page = browser.get("/architecture").text
    links = re.findall(r'href="(/api/docs[^"]*)"', page)

    assert links == ["/api/docs"]
    assert browser.get(links[0]).status_code == 200
