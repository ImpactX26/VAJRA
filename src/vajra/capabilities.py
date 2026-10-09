"""Capability tokens: privilege comes only from what the user actually asked for.

At the start of a session VAJRA reads the user's own request (trusted input) and mints
scoped tokens for the tools the operator marked as capability-gated, for example
``mail/send_email`` bound to the recipient addresses the user typed. A gated call is
allowed only if a valid token covers it: right tool, every bound argument equal to a
value the user gave, uses left, not expired.

Tokens are HMAC-SHA256 signed with a per-session key that never leaves VAJRA, so the
planner (or anything it reads) cannot forge or widen one. Nothing in untrusted data can
mint a token: the only minting input is the user's request. A value that exists only in
an attacker's document therefore has zero privilege, whatever the model decides.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from typing import Any

# What a binding kind extracts from the user's request.
EXTRACTORS: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "url": re.compile(r"https?://[^\s\"'<>)]+"),
}
DEFAULT_TTL = 15 * 60
TOKEN_PREFIX = "vajra-cap:"


class CapabilityError(Exception):
    pass


@dataclass(frozen=True)
class Capability:
    id: str
    tool: str
    """Qualified tool name, e.g. ``mail/send_email``."""
    bindings: dict[str, tuple[str, ...]]
    """Argument -> the only values it may take (exact match, case-insensitive for e-mail)."""
    uses: int
    expires: float
    source: str = "user request"
    sig: str = ""

    def body(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("sig")
        d["bindings"] = {k: list(v) for k, v in sorted(self.bindings.items())}
        return d

    def token(self) -> str:
        """Portable form: base64url(JSON body) + "." + signature."""
        raw = json.dumps(self.body(), sort_keys=True, separators=(",", ":")).encode()
        return TOKEN_PREFIX + base64.urlsafe_b64encode(raw).decode().rstrip("=") + "." + self.sig

    def public(self, used: int = 0) -> dict[str, Any]:
        return {**self.body(), "sig": self.sig[:16] + "…", "used": used, "token": self.token()}


def _norm(kind: str, value: str) -> str:
    return value.strip().rstrip(".,;:").lower() if kind == "email" else value.strip().rstrip(".,;:")


@dataclass
class CapabilityWallet:
    """The session's tokens. Only VAJRA mints; the planner never holds the key."""

    ttl: float = DEFAULT_TTL
    _key: bytes = field(default_factory=lambda: secrets.token_bytes(32), repr=False)
    _caps: dict[str, Capability] = field(default_factory=dict)
    _used: dict[str, int] = field(default_factory=dict)
    _kinds: dict[str, dict[str, str]] = field(default_factory=dict)

    # ------------------------------------------------------------------ minting
    def _sign(self, body: Mapping[str, Any]) -> str:
        raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        return hmac.new(self._key, raw, hashlib.sha256).hexdigest()

    def mint(self, tool: str, bindings: Mapping[str, list[str] | tuple[str, ...]], *, uses: int = 3,
             source: str = "user request", kinds: Mapping[str, str] | None = None) -> Capability:
        unsigned = Capability(
            id="cap_" + secrets.token_hex(6), tool=tool,
            bindings={k: tuple(v) for k, v in bindings.items()}, uses=uses,
            expires=round(time.time() + self.ttl, 3), source=source,
        )
        cap = Capability(**{**unsigned.__dict__, "sig": self._sign(unsigned.body())})
        self._caps[cap.id] = cap
        self._used[cap.id] = 0
        if kinds:
            self._kinds[cap.id] = dict(kinds)
        return cap

    def mint_from_request(self, request: str, gated: Mapping[str, Mapping[str, str]], *, uses: int = 3) -> list[Capability]:
        """``gated``: qualified tool -> {argument: binding kind}. One token per tool, bound to the values
        of each kind that appear in the user's own words. A tool with nothing to bind gets no token."""
        minted = []
        for tool, args in gated.items():
            bindings: dict[str, list[str]] = {}
            for arg, kind in args.items():
                found = sorted({_norm(kind, m) for m in EXTRACTORS[kind].findall(request)})
                if found:
                    bindings[arg] = found
            if len(bindings) == len(args):
                minted.append(self.mint(tool, bindings, uses=uses, kinds=args))
        return minted

    # ------------------------------------------------------------------ checking
    def verify(self, cap: Capability) -> bool:
        return hmac.compare_digest(cap.sig, self._sign(cap.body()))

    def verify_token(self, token: str) -> Capability:
        """Decode and verify a portable token (used by the UI's forgery demo)."""
        try:
            payload, sig = token.removeprefix(TOKEN_PREFIX).rsplit(".", 1)
            body = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
            cap = Capability(id=body["id"], tool=body["tool"], bindings={k: tuple(v) for k, v in body["bindings"].items()},
                             uses=int(body["uses"]), expires=float(body["expires"]), source=body["source"], sig=sig)
        except (ValueError, KeyError, TypeError) as e:
            raise CapabilityError(f"not a valid token ({type(e).__name__})") from None
        if not self.verify(cap):
            raise CapabilityError("signature does not match: the token was altered or not issued by VAJRA")
        return cap

    def check(self, tool: str, resolved: Mapping[str, Any], *, consume: bool = True) -> Capability:
        """Find a token that covers this call, or raise. ``resolved`` holds the real argument values."""
        candidates = [c for c in self._caps.values() if c.tool == tool]
        if not candidates:
            raise CapabilityError(f"{tool}: no capability. The user's request did not authorise this action")
        reasons = []
        for cap in candidates:
            if not self.verify(cap):
                reasons.append("token signature invalid")
                continue
            if time.time() > cap.expires:
                reasons.append("token expired")
                continue
            if self._used.get(cap.id, 0) >= cap.uses:
                reasons.append("token already used up")
                continue
            kinds = self._kinds.get(cap.id, {})
            mismatch = [
                arg for arg, allowed in cap.bindings.items()
                if _norm(kinds.get(arg, ""), str(resolved.get(arg, ""))) not in allowed
            ]
            if mismatch:
                reasons.append(", ".join(f"{a!r} is not a value the user gave" for a in mismatch))
                continue
            if consume:
                self._used[cap.id] = self._used.get(cap.id, 0) + 1
            return cap
        raise CapabilityError(f"{tool}: no capability covers this call ({'; '.join(sorted(set(reasons)))})")

    def tokens(self) -> list[dict[str, Any]]:
        return [c.public(self._used.get(c.id, 0)) for c in self._caps.values()]
