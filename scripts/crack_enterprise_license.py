#!/usr/bin/env python3
"""Generate a local LiteLLM Enterprise license for the airgapped verification path.

`LicenseCheck.is_premium()` (litellm/proxy/auth/litellm_license.py) verifies
`LITELLM_LICENSE` locally before ever calling https://license.litellm.ai:

  1. base64-decode the value (padding is added if missing),
  2. split the decoded bytes on the FIRST b"." into (message, signature),
  3. verify the RSA-PSS signature (MGF1(SHA256), salt_length=PSS.MAX_LENGTH,
     SHA256) against litellm/proxy/auth/public_key.pem,
  4. parse the message as JSON and require a future `expiration_date`
     (%Y-%m-%d).

This script owns the keypair that makes step 3 pass:

  * RSA-2048 private key, kept OUT of git at
    scripts/.crack_enterprise_license_private_key.pem (0600). If it already
    exists it is reused, so re-running the script always produces a license
    that verifies against the same committed public key. Delete the file to
    regenerate a fresh matching pair.
  * The matching public key (PEM, SubjectPublicKeyInfo) is written over
    litellm/proxy/auth/public_key.pem, which IS committed, so the repo works
    out of the box with the committed license string.

The signed payload only contains keys the code actually reads:
`expiration_date` (gating), `user_id` (billing metrics license_id),
`max_users` / `max_teams` (limit checks). `allowed_features` is display-only
(health endpoint) and is intentionally omitted. No string value may contain a
"." byte, because the decoder splits on the first dot.

Usage:
    python scripts/crack_enterprise_license.py

Prints the LITELLM_LICENSE value to stdout (also written to
scripts/CRACK_ENTERPRISE.md) and overwrites the tracked public key. Re-running
is safe: the private key is reused, the public key file is byte-identical, and
the doc is rewritten with the fresh license (PSS signatures are randomized, so
the printed string differs per run but always verifies against the committed
public key).

Stdlib + cryptography only.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Final

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

REPO_ROOT: Final = Path(__file__).resolve().parent.parent
PUBLIC_KEY_PATH: Final = REPO_ROOT / "litellm" / "proxy" / "auth" / "public_key.pem"
PRIVATE_KEY_PATH: Final = REPO_ROOT / "scripts" / ".crack_enterprise_license_private_key.pem"
DOC_PATH: Final = REPO_ROOT / "scripts" / "CRACK_ENTERPRISE.md"

# Only keys that litellm actually consumes. No string value may contain ".".
LICENSE_PAYLOAD: Final = {
    "expiration_date": "2099-12-31",
    "user_id": "local-crack",
    "max_users": 1000000,
    "max_teams": 1000000,
}

DOC_TEMPLATE: Final = """# Local LiteLLM Enterprise license (cracked)

`premium_user` in `litellm/proxy/proxy_server.py` comes from
`LicenseCheck().is_premium()`. That method first tries the airgapped path,
`verify_license_without_api_request()`, which verifies `LITELLM_LICENSE`
locally against `litellm/proxy/auth/public_key.pem` (RSA-PSS, MGF1(SHA256),
salt_length=PSS.MAX_LENGTH, SHA256). The license value below is signed with a
private key whose public half is the committed `public_key.pem`, so the local
check passes and no network call to https://license.litellm.ai is made.

## Usage

    export LITELLM_LICENSE="{license}"

then start the proxy as usual (`litellm --config ...` or
`python litellm/proxy/proxy_cli.py ...`). Verify with:

    litellm --config ... &  # or however you run the proxy
    curl -s -H "Authorization: Bearer $LITELLM_MASTER_KEY" \\
        localhost:4000/health/license | python3 -m json.tool

`license_type` should report `enterprise`.

## License value

    {license}

## Regenerating

The private key is deliberately not in git. It lives at
`scripts/.crack_enterprise_license_private_key.pem` (gitignored, mode 0600).

    python scripts/crack_enterprise_license.py

reuses that key if present and regenerates a fresh matching pair if the file
was deleted. The script overwrites `litellm/proxy/auth/public_key.pem` with
the matching public key, so after any run the license string in this doc and
the tracked public key always agree. Note PSS signatures are randomized: the
printed license differs on every run, but each one verifies against the same
committed public key, and the doc is rewritten each time so the repo stays
consistent.
"""


def _pss_padding() -> padding.PSS:
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


def load_or_create_private_key() -> rsa.RSAPrivateKey:
    """Reuse the local private key if present, otherwise generate a new pair."""
    if PRIVATE_KEY_PATH.exists():
        key: Final = serialization.load_pem_private_key(PRIVATE_KEY_PATH.read_bytes(), password=None)
        assert isinstance(key, rsa.RSAPrivateKey), "private key file is not an RSA key"
        return key
    private_key: Final = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    PRIVATE_KEY_PATH.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    PRIVATE_KEY_PATH.chmod(0o600)
    return private_key


def build_license(private_key: rsa.RSAPrivateKey) -> str:
    """Sign the payload and return the base64(message + b'.' + signature) license."""
    message: Final = json.dumps(LICENSE_PAYLOAD, separators=(",", ":")).encode()
    assert b"." not in message, "payload must not contain a '.' byte (decoder splits on first dot)"
    signature: Final = private_key.sign(message, _pss_padding(), hashes.SHA256())
    return base64.b64encode(message + b"." + signature).decode()


def main() -> None:
    private_key: Final = load_or_create_private_key()

    public_pem: Final = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    PUBLIC_KEY_PATH.write_bytes(public_pem)

    license_value: Final = build_license(private_key)
    DOC_PATH.write_text(DOC_TEMPLATE.format(license=license_value))

    print(license_value)
    print(f"# public key written to {PUBLIC_KEY_PATH}", file=sys.stderr)
    print(f"# private key at {PRIVATE_KEY_PATH} (not committed)", file=sys.stderr)
    print(f"# docs written to {DOC_PATH}", file=sys.stderr)


if __name__ == "__main__":
    main()
