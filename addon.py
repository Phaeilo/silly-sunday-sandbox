import functools
import logging
import os
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Self

from mitmproxy import http
from mitmproxy.net.http.url import default_port, parse_authority

# Headers stripped from every request regardless of policy.
# Covers the most common vectors for leaking credentials or session state.
ALWAYS_STRIP = (
    "authorization",
    "cookie",
    "proxy-authorization",
    "x-auth-token",
    "x-api-key",
    "x-access-token",
    "x-secret",
    "x-forwarded-for",
)
ALWAYS_STRIP_SET = frozenset(ALWAYS_STRIP)

# Minimal set of headers kept when a policy uses a strict allowlist.
BASE_HEADERS = (
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
)


class BlockRequest(Exception):
    """Raised inside mitmproxy hooks to block the current flow with a 403."""


@dataclass(frozen=True)
class Policy:
    """Describes what requests are permitted for a given host."""
    host: str
    methods: tuple[str, ...] | None = None
    http: bool = True
    https: bool = True
    path_re: re.Pattern | None = None
    allow_query: bool = False
    header_allowlist: tuple[str, ...] | None = None
    header_callback: Callable[[str, str], str | None] | None = field(default=None, hash=False, compare=False)

    def allows_request(self, flow: http.HTTPFlow) -> bool:
        if self.host != flow.request.host:
            return False
        if flow.request.scheme == "http" and not self.http:
            return False
        if flow.request.scheme == "https" and not self.https:
            return False
        if self.methods is not None and flow.request.method not in self.methods:
            return False
        if not self.allow_query and "?" in flow.request.path:
            return False
        if self.path_re is not None and not self.path_re.match(flow.request.path):
            return False
        return True

    def allows_connect(self, host: str, port: int) -> bool:
        return (self.host == host) and ((port == 443 and self.https) or (port == 80 and self.http))

    def apply_header_callback(self, flow: http.HTTPFlow):
        if self.header_callback is None:
            return

        new_fields = []
        for name_b, value_b in flow.request.headers.fields:
            name = name_b.decode("utf-8", "surrogateescape")
            value = value_b.decode("utf-8", "surrogateescape")
            result = self.header_callback(name.lower(), value)
            if result is None:
                logging.debug(f"dropped header {name!r} on request to {flow.request.host!r}")
            else:
                if result != value:
                    logging.debug(f"substituted header {name!r} on request to {flow.request.host!r}")
                new_fields.append((name_b, result.encode("utf-8", "surrogateescape")))
        flow.request.headers.fields = tuple(new_fields)

    def filter_headers(self, flow: http.HTTPFlow):
        allowlist = self.header_allowlist
        for name in dict.fromkeys(flow.request.headers):
            lower = name.lower()

            if allowlist is not None and lower in allowlist:
                continue
            if allowlist is None and lower not in ALWAYS_STRIP_SET:
                continue

            del flow.request.headers[name]
            logging.debug(f"stripped header {name!r} on request to {flow.request.host!r}")

    @classmethod
    def readonly(
        cls,
        host: str,
        *,
        allow_query: bool = False,
        https_only: bool = False,
        extra_headers: tuple[str, ...] = (),
    ) -> Self:
        return cls(
            host=host,
            methods=("GET", "HEAD"),
            http=not https_only,
            allow_query=allow_query,
            header_allowlist=BASE_HEADERS + extra_headers,
        )


def _anthropic_header_callback(name: str, value: str) -> str | None:
    """
    Substitute placeholder API credentials with real ones from the environment.
    Only inspects x-api-key and Authorization: Bearer; passes all other headers through.
    """
    if name == "x-api-key":
        if value == "PLACEHOLDER_API_KEY":
            return os.getenv("ACTUAL_ANTHROPIC_API_KEY") or value
        return None  # drop

    if name == "authorization":
        if value.startswith("Bearer "):
            token = value.partition(" ")[-1]
            if token == "PLACEHOLDER_AUTH_TOKEN":
                real = os.getenv("ACTUAL_ANTHROPIC_AUTH_TOKEN")
                return f"Bearer {real}" if real else value
        return None  # drop ALL authorization values that aren't the expected Bearer placeholder

    return value


# NOTE: maybe load this form file
POLICIES = [
    # Ubuntu package repos
    Policy.readonly("archive.ubuntu.com"),
    Policy.readonly("security.ubuntu.com"),
    Policy.readonly("deb.nodesource.com"),

    # Software libraries
    Policy.readonly("pypi.org", allow_query=True),
    Policy.readonly("files.pythonhosted.org"),
    Policy.readonly("registry.npmjs.org", allow_query=True),
    Policy.readonly("static.rust-lang.org"),
    Policy.readonly("crates.io", allow_query=True),
    Policy.readonly("static.crates.io"),
    Policy.readonly("proxy.golang.org"),
    Policy.readonly("sum.golang.org"),

    # Documentation
    Policy.readonly("stackoverflow.com", allow_query=True),
    Policy.readonly("developer.mozilla.org", allow_query=True),

    # GitHub
    # clone via smart HTTP
    Policy(
        host="github.com",
        methods=("GET", "POST"),
        path_re=re.compile(r"^/[^/]+/[^/]+\.git/(info/refs(\?.*)?|git-upload-pack)$"),
        allow_query=True,
        header_allowlist=BASE_HEADERS + ("git-protocol",),
    ),
    # source code downloads
    Policy.readonly("raw.githubusercontent.com"),
    Policy.readonly("release-assets.githubusercontent.com"),
    Policy.readonly("codeload.github.com", https_only=True),
    # website browsing
    Policy.readonly("github.com", allow_query=True),
    # read-only API access, auth headers stripped
    Policy.readonly("api.github.com", allow_query=True, https_only=True),

    # Anthropic
    # Full API access
    Policy(
        host="api.anthropic.com",
        http=False,
        allow_query=True,
        header_allowlist=BASE_HEADERS + (
            "x-api-key",
            "authorization",
            "anthropic-version",
            "anthropic-beta",
        ),
        header_callback=_anthropic_header_callback,
    ),
    # contacted during Claude startup
    Policy.readonly("platform.claude.com", allow_query=True, https_only=True),
]


class TrafficFilter:
    """mitmproxy addon that enforces per-host traffic policies."""

    def __init__(self, policies=POLICIES):
        self.policies = policies
        self.num_seen = 0
        self.num_blocked = 0

    @staticmethod
    def _flow_url(flow: http.HTTPFlow) -> str:
        return f"{flow.request.method} {flow.request.scheme}://{flow.request.host}{flow.request.path}"

    @staticmethod
    def _handle_block(method):
        @functools.wraps(method)
        def wrapper(self, flow: http.HTTPFlow):
            try:
                method(self, flow)
            except BlockRequest as e:
                self.num_blocked += 1
                logging.warning(f"BLOCKED [{self.num_blocked}/{self.num_seen}] {self._flow_url(flow)} — {e}")
                flow.response = http.Response.make(
                    403,
                    f"Blocked by traffic policy: {e}",
                    {"Content-Type": "text/plain"},
                )
        return wrapper

    @_handle_block
    def http_connect(self, flow: http.HTTPFlow):
        self.num_seen += 1

        # CONNECT target from the request line
        connect_to = flow.request.host

        # If a Host header is present, it must match the CONNECT target exactly
        host_hdr = flow.request.headers.get("host")
        if host_hdr is not None:
            try:
                parsed_host, port = parse_authority(host_hdr, check=True)
            except ValueError:
                parsed_host, port = None, None

            if parsed_host != connect_to:
                raise BlockRequest(f"Host header {host_hdr!r} does not match CONNECT target {connect_to!r}")
            if port is not None and port != flow.request.port:
                raise BlockRequest(f"Host header port {port} does not match CONNECT target port {flow.request.port}")

        if not any(p.allows_connect(connect_to, flow.request.port) for p in self.policies):
            raise BlockRequest(f"no policy allows CONNECT to {connect_to!r}:{flow.request.port}")

    @_handle_block
    def requestheaders(self, flow: http.HTTPFlow):
        # Ensure Host header is well-formed
        host_hdr = flow.request.headers.get("host")
        if not host_hdr:
            raise BlockRequest("missing or empty Host header")

        try:
            parsed_host, port = parse_authority(host_hdr, check=True)
        except ValueError:
            raise BlockRequest(f"malformed Host header: {host_hdr!r}")

        # Host header must match the TCP/TLS connection target
        if parsed_host != flow.request.host:
            raise BlockRequest(f"Host header {parsed_host!r} does not match connection target {flow.request.host!r}")

        # Reject non-standard ports
        if port is not None and port != default_port(flow.request.scheme):
            raise BlockRequest(f"Host header port {port} not allowed for scheme {flow.request.scheme!r}")

        # Find the first policy whose constraints match
        policy = next((p for p in self.policies if p.allows_request(flow)), None)
        if policy is None:
            raise BlockRequest(f"no matching policy for {self._flow_url(flow)}")

        # Modify headers: substitute/drop via callback, then strip by allowlist
        policy.apply_header_callback(flow)
        policy.filter_headers(flow)
        logging.info(f"ALLOWED [{self.num_seen} seen] {self._flow_url(flow)}")


addons = [TrafficFilter()]
