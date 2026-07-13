"""SSRF-safe page fetching and HTML text extraction.

Because this tool fetches operator-supplied URLs, the fetcher must not become
an SSRF pivot into the local network. Before every request (and after every
redirect) the resolved IP is checked against private/loopback/link-local
ranges and rejected. Responses are size- and time-limited, and JavaScript is
never executed — only the raw HTML is parsed.
"""

import ipaddress
import socket
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import requests

from autosoc.logging_setup import get_logger
from autosoc.phishing.url_features import normalize_url

log = get_logger("phishing.fetcher")

USER_AGENT = "Mozilla/5.0 (compatible; AutoSOC-PhishingScanner/1.0)"
MAX_BYTES = 2_000_000
MAX_REDIRECTS = 5
CONNECT_TIMEOUT = 6
READ_TIMEOUT = 12


@dataclass
class FetchResult:
    ok: bool
    url: str
    final_url: str = ""
    status_code: int = 0
    html: str = ""
    text: str = ""
    title: str = ""
    forms: list = field(default_factory=list)
    links: list = field(default_factory=list)
    scripts_inline: int = 0
    iframes: int = 0
    hidden_inputs: int = 0
    password_inputs: int = 0
    redirect_chain: list = field(default_factory=list)
    server_header: str = ""
    error: str = ""


class _PageParser(HTMLParser):
    """Extracts visible text, forms, links, and risky element counts."""

    _SKIP_TEXT_TAGS = {"script", "style", "noscript", "template", "svg", "head"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text_parts = []
        self.title = ""
        self.forms = []
        self.links = []
        self.inline_scripts = 0
        self.iframes = 0
        self.hidden_inputs = 0
        self.password_inputs = 0
        self._skip_depth = 0
        self._in_title = False
        self._current_form = None

    def handle_starttag(self, tag, attrs):
        attr = dict(attrs)
        if tag in self._SKIP_TEXT_TAGS:
            self._skip_depth += 1
        if tag == "title":
            self._in_title = True
        if tag == "script" and not attr.get("src"):
            self.inline_scripts += 1
        if tag == "iframe":
            self.iframes += 1
        if tag == "a" and attr.get("href"):
            self.links.append(attr["href"])
        if tag == "form":
            self._current_form = {"action": attr.get("action", ""), "method": attr.get("method", "get"),
                                  "inputs": []}
        if tag == "input":
            input_type = (attr.get("type") or "text").lower()
            if input_type == "hidden":
                self.hidden_inputs += 1
            if input_type == "password":
                self.password_inputs += 1
            if self._current_form is not None:
                self._current_form["inputs"].append(input_type)

    def handle_endtag(self, tag):
        if tag in self._SKIP_TEXT_TAGS and self._skip_depth > 0:
            self._skip_depth -= 1
        if tag == "title":
            self._in_title = False
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        if self._skip_depth == 0:
            stripped = data.strip()
            if stripped:
                self.text_parts.append(stripped)

    @property
    def text(self):
        return " ".join(self.text_parts)


def _is_public_ip(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, OSError):
        return False
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return False
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return False
    return True


def fetch_page(raw_url: str) -> FetchResult:
    url = normalize_url(raw_url)
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return FetchResult(False, url, error=f"Unsupported scheme: {parsed.scheme}")
    host = parsed.hostname or ""
    if not host:
        return FetchResult(False, url, error="URL has no host")

    if not _is_public_ip(host):
        return FetchResult(
            False, url,
            error="Refusing to fetch: host resolves to a private/loopback address (SSRF guard).",
        )

    session = requests.Session()
    session.max_redirects = MAX_REDIRECTS
    redirect_chain = []
    try:
        with session.get(
            url,
            headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"},
            timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            allow_redirects=True,
            stream=True,
        ) as response:
            for redirect in response.history:
                redirect_chain.append(redirect.url)
                hop_host = urlparse(redirect.headers.get("Location", "")).hostname
                if hop_host and not _is_public_ip(hop_host):
                    return FetchResult(
                        False, url, error="Redirect pointed to a private address (SSRF guard).",
                        redirect_chain=redirect_chain,
                    )

            content_type = response.headers.get("Content-Type", "")
            raw = b""
            for chunk in response.iter_content(chunk_size=16_384):
                raw += chunk
                if len(raw) >= MAX_BYTES:
                    break

            encoding = response.encoding or "utf-8"
            try:
                html = raw.decode(encoding, errors="replace")
            except (LookupError, TypeError):
                html = raw.decode("utf-8", errors="replace")

            parser = _PageParser()
            if "html" in content_type.lower() or "<html" in html.lower():
                parser.feed(html)

            return FetchResult(
                ok=True,
                url=url,
                final_url=response.url,
                status_code=response.status_code,
                html=html,
                text=parser.text,
                title=parser.title.strip(),
                forms=parser.forms,
                links=[urljoin(response.url, href) for href in parser.links],
                scripts_inline=parser.inline_scripts,
                iframes=parser.iframes,
                hidden_inputs=parser.hidden_inputs,
                password_inputs=parser.password_inputs,
                redirect_chain=redirect_chain,
                server_header=response.headers.get("Server", ""),
            )
    except requests.exceptions.SSLError as exc:
        return FetchResult(False, url, error=f"TLS error: {exc}", redirect_chain=redirect_chain)
    except requests.exceptions.RequestException as exc:
        return FetchResult(False, url, error=f"Request failed: {exc}", redirect_chain=redirect_chain)
    except Exception as exc:  # HTMLParser and decoding edge cases
        log.debug("Unexpected fetch error for %s: %s", url, exc)
        return FetchResult(False, url, error=f"Unexpected error: {exc}", redirect_chain=redirect_chain)
