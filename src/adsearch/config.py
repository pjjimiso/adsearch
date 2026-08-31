from __future__ import annotations

import os
import warnings

from dataclasses import dataclass, field
from collections.abc import Mapping

from adsearch.errors import LDAPConfigError



@dataclass(frozen=True, slots=True)
class LDAPConfig:
    server: str
    base_dn: str
    group_base_dn: str | None = None
    bind_user: str | None = None
    bind_password: str | None = field(default=None, repr=False)
    ca_certs_file: str | None = None
    use_ssl: bool = True
    validate_cert: bool = True
    connect_timeout: int = 10
    receive_timeout: int = 60
    time_limit: int = 120
    page_size: int = 1000


    def __post_init__(self) -> None:
        if not self.server or not self.base_dn:
            raise LDAPConfigError("server and base_dn are required")
        if self.bind_password is not None and self.use_ssl is False:
            raise LDAPConfigError("SIMPLE bind requires use_ssl=True")
        if not self.validate_cert:
            warnings.warn("Disabling certificate validation is not recommended for production use", UserWarning)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> LDAPConfig:
        env = os.environ if env is None else env
        if env.get("ADSEARCH_SERVER") is None or env.get("ADSEARCH_BASE_DN") is None:
            raise LDAPConfigError("ADSEARCH_SERVER and ADSEARCH_BASE_DN environment variables are required")
        return cls(
            server=env.get("ADSEARCH_SERVER"),
            base_dn=env.get("ADSEARCH_BASE_DN"),
            group_base_dn=env.get("ADSEARCH_GROUP_BASE_DN"),
            bind_user=env.get("ADSEARCH_BIND_USER"),
            bind_password=env.get("ADSEARCH_BIND_PASSWORD"),
            ca_certs_file=env.get("ADSEARCH_CA_CERTS"),
        )

