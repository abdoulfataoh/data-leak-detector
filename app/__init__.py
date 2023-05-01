# coding: utf-8

from app import settings
from app.hotspot import AcessPoint

access_point = AcessPoint(
    config_file=settings.HOTSPOT_CONF
)

__all__ = [
    'access_point',
]
