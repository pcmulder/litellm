import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey


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


def test_auto_router_capability_limit() -> None:
    """The signed license's auto_router feature or its "*" wildcard lifts the one-router limit; an
    API-verified license (no airgapped data) and an airgapped license without either keep it."""
    license_check = LicenseCheck()
    license_check.airgapped_license_data = {"expiration_date": "2999-01-01", "allowed_features": ["auto_router"]}
    assert license_check.auto_router_capability_limit() is None

    license_check.airgapped_license_data = {
        "expiration_date": "2999-01-01",
        "allowed_features": ["sso", "auto_router", "audit_logs"],
    }
    assert license_check.auto_router_capability_limit() is None

    license_check.airgapped_license_data = {"expiration_date": "2999-01-01", "allowed_features": ["*"]}
    assert license_check.auto_router_capability_limit() is None

    license_check.airgapped_license_data = {"expiration_date": "2999-01-01", "allowed_features": ["sso", "*"]}
    assert license_check.auto_router_capability_limit() is None

    license_check.airgapped_license_data = {"expiration_date": "2999-01-01", "allowed_features": ["sso"]}
    assert license_check.auto_router_capability_limit() == 1

    license_check.airgapped_license_data = {"expiration_date": "2999-01-01", "allowed_features": "*"}
    assert license_check.auto_router_capability_limit() is None

    license_check.airgapped_license_data = {"expiration_date": "2999-01-01"}
    assert license_check.auto_router_capability_limit() == 1

    license_check.airgapped_license_data = None
    assert license_check.auto_router_capability_limit() == 1


def _signed_license(
    expiration_date: str, allowed_features: tuple[str, ...] = ("auto_router",)
) -> tuple[RSAPublicKey, str]:
    import base64

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    message = json.dumps(
        {"expiration_date": expiration_date, "user_id": "u", "allowed_features": list(allowed_features)}
    ).encode()
    signature = private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return private_key.public_key(), base64.b64encode(message + b"." + signature).decode()


def test_expired_or_unreadable_license_grants_no_features() -> None:
    """The verifier stores the signed payload only after the expiry check passes and clears it when a
    later verify rejects the license, so a stale payload cannot keep lifting the heuristic_v2 limit."""
    license_check = LicenseCheck()
    public_key, valid_key = _signed_license("2999-01-01")
    assert license_check.verify_license_without_api_request(public_key=public_key, license_key=valid_key) is True
    assert license_check.auto_router_capability_limit() is None

    _, expired_key = _signed_license("2000-01-01")
    assert license_check.verify_license_without_api_request(public_key=public_key, license_key=expired_key) is not True
    assert license_check.airgapped_license_data is None
    assert license_check.auto_router_capability_limit() == 1

    assert license_check.verify_license_without_api_request(public_key=public_key, license_key=valid_key) is True
    assert license_check.verify_license_without_api_request(public_key=public_key, license_key="not-a-license") is not True
    assert license_check.airgapped_license_data is None


def test_valid_signed_license_with_auto_router_lifts_the_limit() -> None:
    license_check = LicenseCheck()
    public_key, license_key = _signed_license("2999-01-01")

    assert license_check.verify_license_without_api_request(public_key=public_key, license_key=license_key) is True
    assert license_check.auto_router_capability_limit() is None


def test_valid_signed_wildcard_license_lifts_the_limit() -> None:
    """The license generator defaults allowed_features to ["*"], meaning every feature, so a wildcard
    license grants auto_router the same way a license that names it does."""
    license_check = LicenseCheck()
    public_key, license_key = _signed_license("2999-01-01", allowed_features=("*",))

    assert license_check.verify_license_without_api_request(public_key=public_key, license_key=license_key) is True
    assert license_check.grants_feature("auto_router") is True
    assert license_check.auto_router_capability_limit() is None

    named_public_key, named_key = _signed_license("2999-01-01", allowed_features=("sso", "audit_logs"))
    assert license_check.verify_license_without_api_request(public_key=named_public_key, license_key=named_key) is True
    assert license_check.grants_feature("auto_router") is False
    assert license_check.auto_router_capability_limit() == 1
