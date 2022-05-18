from __future__ import annotations

from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .connector import Connector


class BotoscError(Exception):
    pass


class BaseObject:
    _connection = None

    @property
    def connection(self) -> Connector:
        if self._connection is None:
            raise BotoscError("Connection has not been initialized")
        return self._connection
