import logging
import re
from dataclasses import dataclass, field
import os

from mitmproxy import http
from mitmproxy.net.http.url import default_port, parse_authority

# Headers stripped from every request regardless of policy.
# Covers the most common vectors for leaking credentials or session state.
ALWAYS_STRIP: frozenset[str] = frozenset({
    "authorization",
    "cookie",
    "proxy-authorization",
    "x-auth-token",
    "x-api-key",
    "x-access-token",
    "x-secret",
    "x-forwarded-for",  # avoid leaking internal topology
})

# Minimal set of headers kept when a policy uses a strict allowlist.
BASE_HEADERS: frozenset[str] = frozenset({
    "host",
    "user-agent",
    "accept",
    "accept-encoding",
    "accept-language",
    "content-type",
    "content-length",
    "connection",
    "cache-control",
    "pragma",
    "if-modified-since",
    "if-none-match",
    "range",
    "transfer-encoding",
})


@dataclass(frozen=True)
class Policy:
    host: str
    methods: frozenset[str] | None = None           # None = any method
    schemes: frozenset[str] | None = None           # None = http and https
    path_re: re.Pattern | None = None               # None = any path
    allow_query: bool = False                       # query strings forbidden by default
    header_allowlist: frozenset[str] | None = None  # None = apply ALWAYS_STRIP only
    # Fake-to-real key substitution for x-api-key and Authorization: Bearer.
    # When set, requests whose presented key/token is not in the map are blocked.
    # A None value means the key is recognised and forwarded as-is (no substitution).
    # Use field() to exclude the dict from __hash__ (frozen=True generates __hash__
    # but dict is unhashable).
    key_map: dict[str, str | None] | None = field(default=None, hash=False, compare=False)


POLICIES: list[Policy] = [
    Policy(
        host="archive.ubuntu.com",
        methods=frozenset({"GET", "HEAD"}),
        schemes=frozenset({"http", "https"}),
        header_allowlist=BASE_HEADERS,
    ),
    Policy(
        host="security.ubuntu.com",
        methods=frozenset({"GET", "HEAD"}),
        schemes=frozenset({"http", "https"}),
        header_allowlist=BASE_HEADERS,
    ),
    Policy(
        host="deb.nodesource.com",
        methods=frozenset({"GET", "HEAD"}),
        schemes=frozenset({"http", "https"}),
        header_allowlist=BASE_HEADERS,
    ),
    Policy(
        host="static.rust-lang.org",
        methods=frozenset({"GET", "HEAD"}),
        schemes=frozenset({"http", "https"}),
        header_allowlist=BASE_HEADERS,
    ),
    # Git clone via Smart HTTP (GET for ref discovery, POST for pack negotiation)
    Policy(
        host="github.com",
        methods=frozenset({"GET", "POST"}),
        schemes=frozenset({"http", "https"}),
        path_re=re.compile(r"^/[^/]+/[^/]+\.git/(info/refs(\?.*)?|git-upload-pack)$"),
        allow_query=True,  # info/refs uses ?service=git-upload-pack
        header_allowlist=BASE_HEADERS | frozenset({"git-protocol"}),
    ),
    # Read-only website browsing
    Policy(
        host="github.com",
        methods=frozenset({"GET", "HEAD"}),
        schemes=frozenset({"http", "https"}),
        allow_query=True,
        header_allowlist=BASE_HEADERS,
    ),
    Policy(
        host="raw.githubusercontent.com",
        methods=frozenset({"GET", "HEAD"}),
        schemes=frozenset({"http", "https"}),
        header_allowlist=BASE_HEADERS,
    ),
    Policy(
        host="release-assets.githubusercontent.com",
        methods=frozenset({"GET", "HEAD"}),
        schemes=frozenset({"http", "https"}),
        header_allowlist=BASE_HEADERS,
    ),
    # Full access, but auth/session headers are still stripped
    # Policy(
    #     host="httpbin.org",
    #     allow_query=True,
    # ),

    # --- Python ---
    Policy(
        host="pypi.org",
        methods=frozenset({"GET", "HEAD"}),
        schemes=frozenset({"http", "https"}),
        allow_query=True,  # simple index and JSON API use query params
        header_allowlist=BASE_HEADERS,
    ),
    Policy(
        host="files.pythonhosted.org",
        methods=frozenset({"GET", "HEAD"}),
        schemes=frozenset({"http", "https"}),
        header_allowlist=BASE_HEADERS,
    ),

    # --- Node / npm ---
    Policy(
        host="registry.npmjs.org",
        methods=frozenset({"GET", "HEAD"}),
        schemes=frozenset({"http", "https"}),
        allow_query=True,  # search endpoint uses ?text=
        header_allowlist=BASE_HEADERS,
    ),

    # --- Rust / Cargo ---
    Policy(
        host="crates.io",
        methods=frozenset({"GET", "HEAD"}),
        schemes=frozenset({"http", "https"}),
        allow_query=True,  # crate search API
        header_allowlist=BASE_HEADERS,
    ),
    Policy(
        host="static.crates.io",
        methods=frozenset({"GET", "HEAD"}),
        schemes=frozenset({"http", "https"}),
        header_allowlist=BASE_HEADERS,
    ),

    # --- Go modules ---
    Policy(
        host="proxy.golang.org",
        methods=frozenset({"GET", "HEAD"}),
        schemes=frozenset({"http", "https"}),
        header_allowlist=BASE_HEADERS,
    ),
    Policy(
        host="sum.golang.org",
        methods=frozenset({"GET", "HEAD"}),
        schemes=frozenset({"http", "https"}),
        header_allowlist=BASE_HEADERS,
    ),

    # --- GitHub extras ---
    # Read-only REST API access (no writes, no token uploads since auth headers are stripped)
    Policy(
        host="api.github.com",
        methods=frozenset({"GET", "HEAD"}),
        schemes=frozenset({"https"}),
        allow_query=True,
        header_allowlist=BASE_HEADERS,
    ),
    # Source archive downloads (zip/tar.gz of repos)
    Policy(
        host="codeload.github.com",
        methods=frozenset({"GET", "HEAD"}),
        schemes=frozenset({"https"}),
        header_allowlist=BASE_HEADERS,
    ),

    # --- Reference / docs ---
    Policy(
        host="stackoverflow.com",
        methods=frozenset({"GET", "HEAD"}),
        schemes=frozenset({"http", "https"}),
        allow_query=True,  # search and pagination
        header_allowlist=BASE_HEADERS,
    ),
    Policy(
        host="developer.mozilla.org",
        methods=frozenset({"GET", "HEAD"}),
        schemes=frozenset({"http", "https"}),
        allow_query=True,
        header_allowlist=BASE_HEADERS,
    ),

    # --- Anthropic ---
    # Full API access over HTTPS only. Auth headers are kept in the allowlist so
    # they reach the server (after substitution — see key_map below).
    # Populate key_map to swap fake aliases for real credentials:
    #   x-api-key:            key_map={"dev-alias": "sk-ant-api03-..."}
    #   Authorization: Bearer key_map={"dev-token": "<real bearer token>"}
    # Requests carrying an unrecognised key/token are blocked rather than forwarded.
    # A None value in key_map forwards the presented credential unchanged.
    Policy(
        host="api.anthropic.com",
        schemes=frozenset({"https"}),
        allow_query=True,
        header_allowlist=BASE_HEADERS | frozenset({
            "x-api-key",
            "authorization",
            "anthropic-version",
            "anthropic-beta",
        }),
        key_map={
            "YOUR_API_KEY_HERE": os.getenv("ACTUAL_ANTHROPIC_API_KEY"),
            "YOUR_AUTH_TOKEN_HERE": os.getenv("ACTUAL_ANTHROPIC_AUTH_TOKEN"),
        },
    ),
    Policy(
        host="platform.claude.com",
        schemes=frozenset({"https"}),
        methods=frozenset({"GET", "HEAD"}),
        allow_query=True,
        header_allowlist=BASE_HEADERS,
    ),
]


def _find_matching_policy(flow: http.HTTPFlow) -> Policy | None:
    """Return the first policy that matches the request, or None."""
    for policy in POLICIES:
        if policy.host != flow.request.pretty_host:
            continue
        if policy.schemes is not None and flow.request.scheme not in policy.schemes:
            continue
        if policy.methods is not None and flow.request.method not in policy.methods:
            continue
        if not policy.allow_query and flow.request.query:
            continue
        if policy.path_re is not None and not policy.path_re.match(flow.request.path):
            continue
        return policy
    return None


def _substitute_api_key(flow: http.HTTPFlow, policy: Policy) -> tuple[bool, str]:
    """Replace x-api-key and Authorization: Bearer values using the policy's key_map.

    Returns (False, reason) if the presented key/token is not in the map — it is
    never forwarded in that case.  A None map value means the key is recognised
    and forwarded as-is.  Skipped entirely when key_map is None.
    """
    if policy.key_map is None:
        return True, "ok"

    key = flow.request.headers.get("x-api-key")
    if key is not None:
        if key not in policy.key_map:
            return False, f"unrecognised x-api-key for '{flow.request.pretty_host}'"
        real_key = policy.key_map[key]
        if real_key is not None:
            flow.request.headers["x-api-key"] = real_key
            logging.debug("Substituted x-api-key on request to %s", flow.request.pretty_host)

    auth_hdr = flow.request.headers.get("authorization")
    if auth_hdr is not None:
        _BEARER = "Bearer "
        if auth_hdr.startswith(_BEARER):
            token = auth_hdr[len(_BEARER):]
            if token not in policy.key_map:
                return False, f"unrecognised Bearer token for '{flow.request.pretty_host}'"
            real_token = policy.key_map[token]
            if real_token is not None:
                flow.request.headers["authorization"] = _BEARER + real_token
                logging.debug("Substituted Authorization Bearer token on request to %s", flow.request.pretty_host)

    return True, "ok"


def _filter_headers(flow: http.HTTPFlow, policy: Policy) -> None:
    """Strip sensitive or out-of-policy headers from the request in-place."""
    allowlist = policy.header_allowlist
    to_remove = [
        name for name in flow.request.headers
        if (allowlist is not None and name.lower() not in allowlist)
        or (allowlist is None and name.lower() in ALWAYS_STRIP)
    ]
    for name in to_remove:
        del flow.request.headers[name]
        logging.debug("Stripped header '%s' on request to %s", name, flow.request.pretty_host)


class TrafficFilter:
    def __init__(self):
        self.num_seen = 0
        self.num_blocked = 0

    def _block(self, flow: http.HTTPFlow, reason: str) -> None:
        self.num_blocked += 1
        logging.warning(
            "BLOCKED [%d/%d] %s %s://%s%s — %s",
            self.num_blocked,
            self.num_seen,
            flow.request.method,
            flow.request.scheme,
            flow.request.pretty_host,
            flow.request.path,
            reason,
        )
        flow.response = http.Response.make(
            403,
            f"Blocked by traffic policy: {reason}",
            {"Content-Type": "text/plain"},
        )

    def http_connect(self, flow: http.HTTPFlow) -> None:
        # Use flow.request.host (the actual CONNECT target), not pretty_host,
        # which would look at the Host header and allow spoofing the allowlist.
        host = flow.request.host
        host_hdr = flow.request.headers.get("host")
        if host_hdr is not None:
            try:
                parsed_host, _ = parse_authority(host_hdr, check=True)
            except ValueError:
                parsed_host = None
            if parsed_host != host:
                logging.warning(
                    "BLOCKED CONNECT to '%s' — Host header '%s' does not match CONNECT target",
                    host, host_hdr,
                )
                flow.response = http.Response.make(
                    403,
                    f"Blocked by traffic policy: Host header '{host_hdr}' does not match CONNECT target '{host}'",
                    {"Content-Type": "text/plain"},
                )
                return
        if not any(p.host == host for p in POLICIES):
            logging.warning("BLOCKED CONNECT to '%s' — host not in policy", host)
            flow.response = http.Response.make(
                403,
                f"Blocked by traffic policy: host '{host}' not in policy",
                {"Content-Type": "text/plain"},
            )

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        self.num_seen += 1

        host_hdr = flow.request.headers.get("host", "")
        if not host_hdr:
            self._block(flow, "missing or empty Host header")
            return
        try:
            parsed_host, port = parse_authority(host_hdr, check=True)
        except ValueError:
            self._block(flow, f"malformed Host header: {host_hdr!r}")
            return
        if parsed_host != flow.request.host:
            self._block(flow, f"Host header '{parsed_host}' does not match connection target '{flow.request.host}'")
            return
        if port is not None and port != default_port(flow.request.scheme):
            self._block(flow, f"Host header port {port} not allowed for scheme '{flow.request.scheme}'")
            return

        policy = _find_matching_policy(flow)
        if policy is None:
            host = flow.request.pretty_host
            known = any(p.host == host for p in POLICIES)
            reason = (
                f"no matching policy for {flow.request.method} "
                f"{flow.request.scheme}://{host}{flow.request.path}"
                if known else
                f"host '{host}' not in policy"
            )
            self._block(flow, reason)
            return

        allowed, reason = _substitute_api_key(flow, policy)
        if not allowed:
            self._block(flow, reason)
            return

        _filter_headers(flow, policy)
        logging.info(
            "ALLOWED [%d seen] %s %s://%s%s",
            self.num_seen,
            flow.request.method,
            flow.request.scheme,
            flow.request.pretty_host,
            flow.request.path,
        )


addons = [TrafficFilter()]
