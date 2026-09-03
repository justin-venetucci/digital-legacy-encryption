"""Digital Legacy Encryption Suite.

Encrypt a document once so that it can only be decrypted later when *N of M*
keyholders bring their key files together, using `age` and the `age-plugin-sss`
Shamir Secret Sharing plugin.

The package is deliberately standard-library only.  A beneficiary opening this
folder in 2045 should need nothing but a Python interpreter and the three
vendored binaries -- no network, no `pip install`, no lockfile to resolve.
"""

__version__ = "2.0.0"

# The on-disk formats this build reads and writes.  Bump only for a breaking
# change; `vault.json` records the value it was written with so a future
# version can migrate an old vault instead of guessing.
MANIFEST_VERSION = 1

__all__ = ["__version__", "MANIFEST_VERSION"]
