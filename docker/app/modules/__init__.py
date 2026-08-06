"""Importing this package registers every module."""
from .base import REGISTRY, Module, modules_for, register  # noqa: F401
from . import email_mods, google_mods, phone_mods, username_mods  # noqa: F401,E402

__all__ = ["REGISTRY", "Module", "modules_for", "register"]
