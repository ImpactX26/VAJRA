"""Information-flow labels.

Integrity forms a two-point lattice: TRUSTED ⊑ UNTRUSTED. Combining data
(``join``) always yields the *least* trusted of its inputs, so taint can only
ever spread, never be laundered away. Provenance is carried alongside so
policy decisions and audit logs can name where data came from.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import IntEnum
from functools import reduce


class Integrity(IntEnum):
    TRUSTED = 0
    UNTRUSTED = 1

    @classmethod
    def parse(cls, value: str) -> Integrity:
        try:
            return cls[value.upper()]
        except KeyError:
            raise ValueError(f"unknown integrity level {value!r} (expected 'trusted' or 'untrusted')") from None


@dataclass(frozen=True, slots=True)
class Source:
    """Where a piece of data entered the system."""

    upstream: str
    kind: str  # "tool" | "resource" | "client"
    name: str
    call_id: str | None = None

    def __str__(self) -> str:
        suffix = f"#{self.call_id}" if self.call_id else ""
        return f"{self.upstream}/{self.kind}:{self.name}{suffix}"


@dataclass(frozen=True, slots=True)
class Label:
    integrity: Integrity
    sources: frozenset[Source] = frozenset()

    @property
    def trusted(self) -> bool:
        return self.integrity is Integrity.TRUSTED

    def join(self, other: Label) -> Label:
        return Label(max(self.integrity, other.integrity), self.sources | other.sources)

    def __or__(self, other: Label) -> Label:
        return self.join(other)

    def describe(self) -> str:
        srcs = ", ".join(sorted(str(s) for s in self.sources)) or "-"
        return f"{self.integrity.name.lower()} [{srcs}]"


TRUSTED = Label(Integrity.TRUSTED)
"""Bottom of the lattice: data written directly by the privileged planner."""


def join_all(labels: Iterable[Label]) -> Label:
    return reduce(Label.join, labels, TRUSTED)
