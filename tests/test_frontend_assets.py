"""Page script wiring (Phase 2, defect found during browser verification).

Before the fix, ``login.html`` loaded ``login.js`` without ``core.js``. The
sign-in handler called ``window.ZT.setLoading`` and threw a TypeError after
``preventDefault()``, so browser login silently did nothing. These tests check
every page: each script it loads exists, is served as JavaScript, and any
script that uses ``window.ZT`` is loaded after ``core.js``.
"""

from __future__ import annotations

import re

import pytest

from app import config
from conftest import ADMIN, login

PUBLIC_PAGES = ["/login", "/api/docs"]
SIGNED_IN_PAGES = ["/", "/access", "/monitoring", "/simulation", "/evaluation", "/architecture", "/admin"]


def _script_sources(html: str) -> list[str]:
    return re.findall(r'<script\b[^>]*\bsrc="([^"]+)"', html)


def _static_file(src: str):
    assert src.startswith("/static/"), src
    return config.STATIC_DIR / src[len("/static/"):]


def _check_page(client, path: str) -> None:
    response = client.get(path)
    assert response.status_code == 200, path
    sources = _script_sources(response.text)
    assert sources, f"{path} loads no scripts"
    for index, src in enumerate(sources):
        asset = client.get(src)
        assert asset.status_code == 200, f"{path}: {src}"
        assert "javascript" in asset.headers["content-type"], f"{path}: {src}"
        if src.endswith("/core.js"):
            continue
        if "window.ZT" in _static_file(src).read_text(encoding="utf-8"):
            assert "/static/js/core.js" in sources[:index], f"{path}: {src} needs core.js first"


@pytest.mark.parametrize("path", PUBLIC_PAGES)
def test_public_pages_load_their_script_dependencies(make_client, path):
    _check_page(make_client(), path)


def test_login_page_loads_core_before_login_script(make_client):
    sources = _script_sources(make_client().get("/login").text)
    assert sources.index("/static/js/core.js") < sources.index("/static/js/login.js")


@pytest.mark.parametrize("path", SIGNED_IN_PAGES)
def test_signed_in_pages_load_their_script_dependencies(make_client, path):
    browser = make_client()
    assert login(browser, *ADMIN).status_code == 200
    _check_page(browser, path)
