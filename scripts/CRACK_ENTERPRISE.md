# Local LiteLLM Enterprise license (cracked)

`premium_user` in `litellm/proxy/proxy_server.py` comes from
`LicenseCheck().is_premium()`. That method first tries the airgapped path,
`verify_license_without_api_request()`, which verifies `LITELLM_LICENSE`
locally against `litellm/proxy/auth/public_key.pem` (RSA-PSS, MGF1(SHA256),
salt_length=PSS.MAX_LENGTH, SHA256). The license value below is signed with a
private key whose public half is the committed `public_key.pem`, so the local
check passes and no network call to https://license.litellm.ai is made.

## Usage

    export LITELLM_LICENSE="eyJleHBpcmF0aW9uX2RhdGUiOiIyMDk5LTEyLTMxIiwidXNlcl9pZCI6ImxvY2FsLWNyYWNrIiwibWF4X3VzZXJzIjoxMDAwMDAwLCJtYXhfdGVhbXMiOjEwMDAwMDB9LoBBGgGEkYRWOp4I3AbIYQ+mQNcEUZjjU42nkQJNVWIG1x01Oi+GZolybSAkE7TwJYZmj2rXhqbfOdzpTLREiDYq/vrmWUkhfOYdgHaTpXM1stG6p5LNZ/mPAEw+JHUI4PPzd16iFVET7NZUgKAN4JkSiHB0o+39N5kroE/D07aqfvmeUBfr1wW0bN+6zxRfF1hYx8C3oLDKVwmX+hT2N+NwJIB9ER3MU6AfohjSC+HVkdNBtVGIBxYJa6bdthS9MkbabhnWdoKHwHnwPQ6NqvHKwLOzgc0/MFp5myUVAqKXU/4np/QHWiIVotyUgPo7dHUfFMy9J+HKi7sIpAfSXxw="

then start the proxy as usual (`litellm --config ...` or
`python litellm/proxy/proxy_cli.py ...`). Verify with:

    litellm --config ... &  # or however you run the proxy
    curl -s -H "Authorization: Bearer $LITELLM_MASTER_KEY" \
        localhost:4000/health/license | python3 -m json.tool

`license_type` should report `enterprise`.

## License value

    eyJleHBpcmF0aW9uX2RhdGUiOiIyMDk5LTEyLTMxIiwidXNlcl9pZCI6ImxvY2FsLWNyYWNrIiwibWF4X3VzZXJzIjoxMDAwMDAwLCJtYXhfdGVhbXMiOjEwMDAwMDB9LoBBGgGEkYRWOp4I3AbIYQ+mQNcEUZjjU42nkQJNVWIG1x01Oi+GZolybSAkE7TwJYZmj2rXhqbfOdzpTLREiDYq/vrmWUkhfOYdgHaTpXM1stG6p5LNZ/mPAEw+JHUI4PPzd16iFVET7NZUgKAN4JkSiHB0o+39N5kroE/D07aqfvmeUBfr1wW0bN+6zxRfF1hYx8C3oLDKVwmX+hT2N+NwJIB9ER3MU6AfohjSC+HVkdNBtVGIBxYJa6bdthS9MkbabhnWdoKHwHnwPQ6NqvHKwLOzgc0/MFp5myUVAqKXU/4np/QHWiIVotyUgPo7dHUfFMy9J+HKi7sIpAfSXxw=

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
