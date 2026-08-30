import asyncio
import json
import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(
    0, os.path.abspath("../../..")
)  # Adds the parent directory to the system path

from litellm.proxy.auth.litellm_license import LicenseCheck


def test_read_public_key_loads_successfully():
    """Ensure public_key.pem is valid PEM with no leading whitespace."""
    license_check = LicenseCheck()
    assert (
        license_check.public_key is not None
    ), "public_key.pem could not be loaded — check for leading whitespace or malformed PEM header"


def test_is_over_limit():
    license_check = LicenseCheck()
    license_check.airgapped_license_data = {"max_users": 100}
    assert license_check.is_over_limit(101) is True
    assert license_check.is_over_limit(100) is False
    assert license_check.is_over_limit(99) is False

    license_check.airgapped_license_data = {}
    assert license_check.is_over_limit(101) is False
    assert license_check.is_over_limit(100) is False
    assert license_check.is_over_limit(99) is False

    license_check.airgapped_license_data = None
    assert license_check.is_over_limit(101) is False
    assert license_check.is_over_limit(100) is False
    assert license_check.is_over_limit(99) is False


# Committed airgapped license from scripts/CRACK_ENTERPRISE.md, signed with the
# private key matching litellm/proxy/auth/public_key.pem (regenerate both with
# scripts/crack_enterprise_license.py).
COMMITTED_LITELLM_LICENSE = (
    "eyJleHBpcmF0aW9uX2RhdGUiOiIyMDk5LTEyLTMxIiwidXNlcl9pZCI6ImxvY2FsLWNyYWNrIiwibWF4X3VzZXJzIjoxMDAwMDAw"
    "LCJtYXhfdGVhbXMiOjEwMDAwMDB9LoBBGgGEkYRWOp4I3AbIYQ+mQNcEUZjjU42nkQJNVWIG1x01Oi+GZolybSAkE7TwJYZmj2rX"
    "hqbfOdzpTLREiDYq/vrmWUkhfOYdgHaTpXM1stG6p5LNZ/mPAEw+JHUI4PPzd16iFVET7NZUgKAN4JkSiHB0o+39N5kroE/D07aq"
    "fvmeUBfr1wW0bN+6zxRfF1hYx8C3oLDKVwmX+hT2N+NwJIB9ER3MU6AfohjSC+HVkdNBtVGIBxYJa6bdthS9MkbabhnWdoKHwHnw"
    "PQ6NqvHKwLOzgc0/MFp5myUVAqKXU/4np/QHWiIVotyUgPo7dHUfFMy9J+HKi7sIpAfSXxw="
)


def test_is_premium_with_committed_airgapped_license(monkeypatch):
    """The committed license must verify via the local (airgapped) path and parse its data."""
    monkeypatch.setenv("LITELLM_LICENSE", COMMITTED_LITELLM_LICENSE)
    license_check = LicenseCheck()
    # Disable the network fallback so the local verification path is what is under test.
    with patch.object(license_check, "_verify", return_value=False):
        assert license_check.is_premium() is True
    assert license_check.airgapped_license_data is not None
    assert license_check.airgapped_license_data.get("expiration_date") == "2099-12-31"
    assert license_check.airgapped_license_data.get("user_id") == "local-crack"
    assert license_check.airgapped_license_data.get("max_users") == 1000000
    assert license_check.airgapped_license_data.get("max_teams") == 1000000
    assert license_check.is_over_limit(1000000) is False
    assert license_check.is_over_limit(1000001) is True
