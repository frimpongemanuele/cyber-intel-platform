"""Source registry: load and validate ``config/sources.toml``.

The registry is the single place outbound destinations are declared. The SSRF allowlist
is *derived* from it, so adding a source and allowing its host are one reviewed change.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from cyberintel.security.url_guard import HostAllowlist

Kind = Literal["kev", "epss", "nvd", "cve5", "attack", "feed"]


class Source(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,62}$")
    kind: Kind
    url: str
    trust_tier: Literal["primary", "secondary", "community"]
    poll_minutes: int = Field(default=180, ge=5, le=60 * 24 * 30)
    min_interval_seconds: float = Field(default=2.0, ge=0.1, le=3600)
    enabled: bool = True
    extra_hosts: tuple[str, ...] = ()  # known redirect targets, reviewed explicitly

    @field_validator("url")
    @classmethod
    def _https_only(cls, v: str) -> str:
        parts = urlsplit(v)
        if parts.scheme != "https" or not parts.hostname or parts.username or parts.port:
            raise ValueError("source URLs must be plain https://host/... URLs")
        return v

    @property
    def host(self) -> str:
        host = urlsplit(self.url).hostname
        assert host is not None  # guaranteed by the validator
        return host


class Registry(BaseModel):
    model_config = ConfigDict(frozen=True)

    sources: tuple[Source, ...]

    @model_validator(mode="after")
    def _unique_names(self) -> Registry:
        names = [s.name for s in self.sources]
        dupes = {n for n in names if names.count(n) > 1}
        if dupes:
            raise ValueError(f"duplicate source names: {sorted(dupes)}")
        return self

    def enabled(self, kind: Kind | None = None) -> tuple[Source, ...]:
        return tuple(s for s in self.sources if s.enabled and (kind is None or s.kind == kind))

    def get(self, name: str) -> Source:
        for s in self.sources:
            if s.name == name:
                return s
        raise KeyError(name)

    def allowlist(self) -> HostAllowlist:
        hosts = {h for s in self.enabled() for h in (s.host, *s.extra_hosts)}
        return HostAllowlist(sorted(hosts))


def load_registry(path: Path) -> Registry:
    with path.open("rb") as fh:
        raw = tomllib.load(fh)
    return Registry(sources=tuple(Source(**row) for row in raw.get("source", [])))
