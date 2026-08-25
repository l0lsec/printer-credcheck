#!/usr/bin/env python3
"""Vendor module registry.

Adding support for another printer vendor means dropping a module in here that
subclasses PrinterModule and registering it below.
"""
from typing import Dict, List

from .base import Account, LoginResult, PrinterModule, ScanContext, Target
from .ricoh import RicohModule
from .sharp import SharpModule

MODULES: List[PrinterModule] = [
    RicohModule(),
    SharpModule(),
]

BY_NAME: Dict[str, PrinterModule] = {m.name: m for m in MODULES}


def get(name: str) -> PrinterModule:
    try:
        return BY_NAME[name.lower()]
    except KeyError:
        raise KeyError(f"unknown vendor '{name}' (known: {', '.join(sorted(BY_NAME))})")


def names() -> List[str]:
    return [m.name for m in MODULES]


__all__ = [
    "Account", "LoginResult", "PrinterModule", "ScanContext", "Target",
    "MODULES", "BY_NAME", "get", "names",
]
