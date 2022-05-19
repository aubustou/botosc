from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional, Protocol

if TYPE_CHECKING:
    from . import Connector
    from .model import Image


@dataclass
class ResponseParameter:
    _all_optional: bool = field(default=True, init=False)


class VmProtocol(Protocol):
    image_id: str

    @property
    def connection(self) -> Connector:
        ...


@dataclass
class VmMixin:
    toto: str = field(default="toto", init=False)

    @property
    def tutu(self):
        return self.toto

    def ssh(self):
        print("ssh")

    def get_image_details(self: VmProtocol) -> Optional[Image]:
        from .model import FiltersImage

        images = self.connection.read_images(
            filters=FiltersImage(image_ids=[self.image_id])
        )
        return images[0] if images else None
