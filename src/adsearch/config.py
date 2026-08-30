from __future__ import annotations

import os
from dataclasses import dataclass

from adsearch.errors import LDAPConfigError




@dataclass(frozen=True, slots=True)
class LDAPConfig:
    server: str
    base_dn: str
    group_base_dn: str
    bind_user: str
    bind_password: str
    ca_certs_file: str
    use_ssl: bool = True
    validate_cert: bool = True
    connect_timeout: int = 10
    receive_timeout: int = 60
    time_limit: int = 120
    page_size: int = 1000


    def __post_init__(self) -> None:
        if not self.server or not self.base_dn:
            raise LDAPConfigError("server and base_dn are required")
        if not self.use_ssl:
            raise LDAPConfigError("SIMPLE bind requires use_ssl=True")

    def from_env(self) -> LDAPConfig:
        return LDAPConfig(
            server=os.environ.get("ADSEARCH_SERVER", self.server),
            base_dn=os.environ.get("ADSEARCH_BASE_DN", self.base_dn),
            group_base_dn=os.environ.get("ADSEARCH_GROUP_BASE_DN", self.group_base_dn),
            bind_user=os.environ.get("ADSEARCH_BIND_USER", self.bind_user),
            bind_password=os.environ.get("ADSEARCH_BIND_PASSWORD", self.bind_password),
        )

