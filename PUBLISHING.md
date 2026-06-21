# Publishing the TWZRD receipt verifier

The verifier is ready to publish to **PyPI** (Python) and **npm** (Node). The
package metadata is committed; this is the operator's release runbook. The only
steps that need credentials are the final `upload` / `publish`.

> Goal: a stranger can `pip install twzrd-receipt-verifier` or
> `npx twzrd-receipt-verifier receipt.json` and verify a TWZRD receipt offline
> with only the published public key.

## 0. One-time prerequisites
- **PyPI**: an account + an API token (https://pypi.org/manage/account/token/).
- **npm**: an account + `npm login` (or an automation token in `NPM_TOKEN`).
- **Name check**: confirm `twzrd-receipt-verifier` is free on both
  (https://pypi.org/project/twzrd-receipt-verifier/ , `npm view twzrd-receipt-verifier`).
  If taken, scope it — npm `@twzrd/receipt-verifier` (set `"publishConfig": {"access": "public"}`),
  PyPI `twzrd-receipt-verifier` is unscoped only, so pick an alternate name in `pyproject.toml`.

## 1. Python -> PyPI
```bash
cd packages/twzrd-agent-intel/verifier
python -m pip install --upgrade build twine
python -m build                        # -> dist/twzrd_receipt_verifier-1.0.4{.tar.gz,-py3-none-any.whl}
python -m twine check dist/*           # metadata sanity
# upload (token auth):
TWINE_USERNAME=__token__ TWINE_PASSWORD=pypi-XXXX python -m twine upload dist/*
```
Smoke-test the published package in a clean env:
```bash
python -m venv /tmp/vt && /tmp/vt/bin/pip install twzrd-receipt-verifier
/tmp/vt/bin/twzrd-verify-receipt receipt.json --pubkey 9V6Pn19kiUA5Rn6JpQfNduanvGt2aXGwsarosNfa2Ldf --self-test
```

## 2. Node -> npm
```bash
cd packages/twzrd-agent-intel/verifier
npm pack --dry-run                     # preview tarball: should contain only
                                       # verify_twzrd_receipt.js, README.md, LICENSE, package.json
npm publish --access public            # needs npm login / NPM_TOKEN
```
Smoke-test:
```bash
npx twzrd-receipt-verifier@latest receipt.json --pubkey 9V6Pn19kiUA5Rn6JpQfNduanvGt2aXGwsarosNfa2Ldf --self-test
```

## 3. After publishing
- Add the install lines to the public docs / `/llms.txt` so agents discover it:
  `pip install twzrd-receipt-verifier` and `npx twzrd-receipt-verifier`.
- Tag the release (e.g. `verifier-v1.0.4` for PyPI, `verifier-v1.0.5` for npm).
- Bump `version` in BOTH `pyproject.toml` and `package.json` for the next release.

## Notes
- Crypto is in audited libs (PyNaCl/libsodium, pycryptodome; tweetnacl, js-sha3).
  Only base58 + the documented keccak-leaf layout are embedded. See `README.md`.
- The published public key (`9V6Pn19kiUA5Rn6JpQfNduanvGt2aXGwsarosNfa2Ldf`,
  key_id `twzrd-receipt-ed25519-v1`) is also at
  `https://intel.twzrd.xyz/.well-known/x402` for fetch-mode verification.
