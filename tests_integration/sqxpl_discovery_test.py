"""GitHub PoC discovery: a supported-language PoC below top-ranked
unsupported-language repos must still be surfaced (e.g. CVE-2025-32463,
whose C PoC ranks below several Shell ones). Network calls are stubbed."""

import httpx
import pytest

from sqxpl import GitHubExploitSearcher


def _repo(full_name: str, language: str | None, stars: int) -> dict:
    owner, name = full_name.split("/")
    return {
        "full_name": full_name,
        "html_url": f"https://github.com/{full_name}",
        "language": language,
        "description": f"PoC for {full_name}",
        "stargazers_count": stars,
        "owner": {"login": owner},
        "name": name,
    }


SHELL_FIRST_ITEMS = [
    _repo("pr0v3rbs/CVE-2025-32463_chwoot", "Shell", 525),
    _repo("kh4sh3i/CVE-2025-32463", "Shell", 472),
    _repo("MohamedKarrab/CVE-2025-32463", "Shell", 48),
    _repo("1xPwn/CVE-2025-32463", "Go", 26),
    _repo("mirchr/CVE-2025-32463-sudo-chwoot", "C", 25),
    _repo("zinzloun/CVE-2025-32463", "Shell", 14),
]


@pytest.mark.integration
def test_search_repositories_finds_c_poc_below_shell_ranked_top(monkeypatch):
    """Top results by stars are unsupported languages; a C PoC further down
    the list must still be surfaced (CVE-2025-32463)."""

    def fake_get(url, headers=None, params=None, timeout=None):
        if url == GitHubExploitSearcher.SEARCH_REPOS:
            return httpx.Response(
                200, json={"total_count": 78, "items": SHELL_FIRST_ITEMS}
            )
        return httpx.Response(404)

    monkeypatch.setattr(httpx, "get", fake_get)
    monkeypatch.setattr("sqxpl._throttle_search", lambda: None)

    searcher = GitHubExploitSearcher()
    repos = searcher.search_repositories("CVE-2025-32463", max_results=3)

    assert [r["url"] for r in repos] == [
        "https://github.com/mirchr/CVE-2025-32463-sudo-chwoot"
    ]
    assert repos[0]["language"] == "C"


@pytest.mark.integration
def test_search_repositories_retries_on_rate_limit(monkeypatch):
    """A 429 must not silently yield zero results."""

    calls = []

    def fake_get(url, headers=None, params=None, timeout=None):
        calls.append(url)
        if len(calls) == 1:
            return httpx.Response(429, headers={"Retry-After": "1"})
        return httpx.Response(
            200, json={"total_count": 1, "items": [SHELL_FIRST_ITEMS[4]]}
        )

    monkeypatch.setattr(httpx, "get", fake_get)
    monkeypatch.setattr("sqxpl._throttle_search", lambda: None)
    monkeypatch.setattr("sqxpl.time.sleep", lambda _: None)

    searcher = GitHubExploitSearcher()
    repos = searcher.search_repositories("CVE-2025-32463", max_results=3)

    search_calls = [u for u in calls if u == GitHubExploitSearcher.SEARCH_REPOS]
    assert len(search_calls) == 2
    assert repos and repos[0]["url"].endswith(
        "mirchr/CVE-2025-32463-sudo-chwoot"
    )