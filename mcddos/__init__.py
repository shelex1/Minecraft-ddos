"""
MCDDOS — набор инструментов для DDoS/нагрузки Minecraft Java (1.16 -> 26.3).

Возможности:
  * обход Velocity / BungeeCord и частых анти-ботов
  * поиск реального IP за прокси
  * авто-пул прокси (fetch -> verify -> reuse)
  * нагрузка с ботами и без (ping / tcp / login / bot / mixed)
  * боты пишут в чат и держат keepalive
"""
__version__ = "1.0.0"

from . import versions  # noqa: F401
from . import protocol  # noqa: F401
