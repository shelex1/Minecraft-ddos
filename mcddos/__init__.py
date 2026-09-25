"""MCDDOS — Minecraft Java DDoS toolkit (1.16 -> 26.3).

Features:
  * Bypass Velocity / BungeeCord + common anti-bot
  * Real-IP discovery behind proxies
  * Auto proxy pool (fetch -> verify -> reuse)
  * Bot & no-bot load (ping / tcp / login / bot / mixed)
  * Bots chat & keepalive
"""
__version__ = "1.0.0"

from . import versions  # noqa: F401
from . import protocol  # noqa: F401
