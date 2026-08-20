"""
_compat.py
==========
Compatibility shims that must run BEFORE passlib imports bcrypt.

passlib 1.7.x detects the bcrypt version via `bcrypt.__about__.__version__`,
an attribute removed in bcrypt >= 4.1. Without this shim, using bcrypt raises:

    AttributeError: module 'bcrypt' has no attribute '__about__'

We recreate the missing attribute from `bcrypt.__version__` so passlib keeps
working with any modern bcrypt release.
"""

from __future__ import annotations


def patch_bcrypt() -> None:
    try:
        import bcrypt
    except Exception:
        return
    if not hasattr(bcrypt, "__about__"):
        version = getattr(bcrypt, "__version__", "4.0.0")

        class _About:  # minimal stand-in passlib is happy with
            __version__ = version

        bcrypt.__about__ = _About  # type: ignore[attr-defined]


# Apply on import.
patch_bcrypt()
